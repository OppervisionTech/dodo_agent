//! Host-side workflow commands for VMs (no Kubernetes).
//!
//! They ride on the existing `apply_manifest` command: a JSON manifest with
//! `apiVersion: dodo.io/v1` is handled here and never reaches kubectl.
//!
//! - `HostScript` runs a bash/python/node script the platform hashed when the
//!   workflow was saved. Needs `DODO_ALLOW_SCRIPTS=true` and a matching
//!   SHA-256. Runs in a private temp dir with a clean environment, rlimits, a
//!   hard timeout that kills the whole process group and, when the agent is
//!   root, as `DODO_SCRIPT_USER` (default `nobody`).
//! - `HttpRequest` calls an API from the agent's network (internal APIs the
//!   platform cannot reach). Needs `DODO_ALLOW_HTTP=true` and the host listed
//!   in `DODO_HTTP_ALLOW`; everything else is refused.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use crate::CommandError;

pub(crate) const API_VERSION: &str = "dodo.io/v1";
const MAX_OUTPUT: usize = 64 * 1024;
const MAX_SCRIPT_TIMEOUT: u64 = 3600;
const MAX_HTTP_TIMEOUT: u64 = 60;
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Some(doc) when the manifest is a dodo.io/v1 host command.
pub(crate) fn parse(manifest: &[u8]) -> Option<Value> {
    let doc: Value = serde_json::from_slice(manifest).ok()?;
    (doc.get("apiVersion").and_then(Value::as_str) == Some(API_VERSION)).then_some(doc)
}

pub(crate) async fn run(doc: &Value) -> Result<String, CommandError> {
    let spec = doc.get("spec").cloned().unwrap_or(Value::Null);
    match doc.get("kind").and_then(Value::as_str) {
        Some("HostScript") => {
            let user = script_user();
            run_script(&spec, env_flag("DODO_ALLOW_SCRIPTS"), Some(&user)).await
        }
        Some("HttpRequest") => {
            let allow = std::env::var("DODO_HTTP_ALLOW").unwrap_or_default();
            http_request(&spec, env_flag("DODO_ALLOW_HTTP"), &allow).await
        }
        other => Err(CommandError::Execution(format!(
            "unsupported dodo.io/v1 kind {}",
            other.unwrap_or("<none>")
        ))),
    }
}

fn exec_err(msg: impl Into<String>) -> CommandError {
    CommandError::Execution(msg.into())
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_OUTPUT {
        let mut end = MAX_OUTPUT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("\n…[truncated]");
    }
    s
}

fn script_user() -> String {
    std::env::var("DODO_SCRIPT_USER").unwrap_or_else(|_| "dodo-script".into())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn valid_env_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && !matches!(k, "PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH" | "HOME")
}

/// (uid, gid) scripts run as. Never the agent's own uid (that would expose
/// /proc/<agent>/environ (the API key) and the agent's files) and never root.
#[cfg(unix)]
fn target_ids(user: &str) -> Result<(u32, u32), CommandError> {
    let name = std::ffi::CString::new(user).map_err(|_| exec_err("invalid DODO_SCRIPT_USER"))?;
    // SAFETY: getpwnam returns a pointer to a static passwd buffer or null;
    // the ids are copied out immediately.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(exec_err(format!(
            "script user {user:?} not found on this host (install with --allow-scripts)"
        )));
    }
    // SAFETY: pw is non-null and points to a valid passwd struct.
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if uid == 0 || uid == me {
        return Err(exec_err(
            "workflow scripts must run as a separate unprivileged user (DODO_SCRIPT_USER)",
        ));
    }
    Ok((uid, gid))
}

/// In the forked child, before exec: no privilege gain via exec, and no
/// capability inherited from the agent (it holds CAP_DAC_READ_SEARCH etc.).
/// Only async-signal-safe syscalls.
#[cfg(target_os = "linux")]
fn drop_privileges_in_child() -> std::io::Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // SAFETY: plain prctl/capset syscalls on the current (child) process with
    // valid, stack-owned arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        let mut hdr = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_privileges_in_child() -> std::io::Result<()> {
    Ok(())
}

/// `user`: the account scripts run as; `None` only in tests (runs as self).
pub(crate) async fn run_script(
    spec: &Value,
    allowed: bool,
    user: Option<&str>,
) -> Result<String, CommandError> {
    if !allowed {
        return Err(exec_err(
            "workflow scripts are disabled on this agent (set DODO_ALLOW_SCRIPTS=true)",
        ));
    }
    let language = spec.get("language").and_then(Value::as_str).unwrap_or("");
    let interpreter = match language {
        "bash" => "bash",
        "python" => "python3",
        "node" => "node",
        other => return Err(exec_err(format!("language {other:?} not supported"))),
    };
    let script = spec.get("script").and_then(Value::as_str).unwrap_or("");
    let expected = spec.get("sha256").and_then(Value::as_str).unwrap_or("");
    if script.is_empty() || !sha256_hex(script.as_bytes()).eq_ignore_ascii_case(expected) {
        return Err(exec_err("script sha256 mismatch — refused"));
    }
    let timeout_s = spec
        .get("timeout_s")
        .and_then(Value::as_u64)
        .unwrap_or(300)
        .clamp(1, MAX_SCRIPT_TIMEOUT);
    let mut env = BTreeMap::new();
    if let Some(map) = spec.get("env").and_then(Value::as_object) {
        for (k, v) in map {
            if !valid_env_key(k) {
                return Err(exec_err(format!("invalid env name {k:?}")));
            }
            env.insert(
                k.clone(),
                v.as_str().map_or_else(|| v.to_string(), str::to_string),
            );
        }
    }

    let dir = std::env::temp_dir().join(format!("dodo-script-{}", uuid::Uuid::new_v4()));
    let _guard = DirGuard(dir.clone());
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| exec_err(format!("create work dir: {e}")))?;
    }
    let ids = user.map(target_ids).transpose()?;
    let path = dir.join("script");
    std::fs::write(&path, script).map_err(|e| exec_err(format!("write script: {e}")))?;
    // Work dir the script may write to. The agent can't chown (no
    // CAP_CHOWN), so when switching users the script stays read-only
    // (0644, agent-owned) and work/ is world-writable inside this private
    // 0711 directory under the agent's PrivateTmp.
    let work = dir.join("work");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(&work).map_err(|e| exec_err(format!("create work dir: {e}")))?;
        if ids.is_some() {
            let set = |p: &std::path::Path, m: u32| {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(m))
                    .map_err(|e| exec_err(format!("chmod: {e}")))
            };
            set(&dir, 0o711)?;
            set(&path, 0o644)?;
            set(&work, 0o777)?;
        }
    }

    let mut cmd = tokio::process::Command::new(interpreter);
    cmd.arg(&path)
        .current_dir(&work)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("HOME", &work)
        .env("LANG", "C.UTF-8")
        .envs(&env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if let Some((uid, gid)) = ids {
        cmd.uid(uid).gid(gid);
    }
    let cpu = timeout_s + 5;
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let lim = |res, v: u64| {
                let r = libc::rlimit {
                    rlim_cur: v as _,
                    rlim_max: v as _,
                };
                libc::setrlimit(res, &r);
            };
            lim(libc::RLIMIT_CPU, cpu);
            lim(libc::RLIMIT_AS, 512 * 1024 * 1024);
            lim(libc::RLIMIT_NPROC, 64);
            lim(libc::RLIMIT_FSIZE, 50 * 1024 * 1024);
            lim(libc::RLIMIT_CORE, 0);
            drop_privileges_in_child()
        });
    }
    let child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied && ids.is_some() {
            exec_err(format!(
                "agent cannot switch to the script user: {e} (install with --allow-scripts)"
            ))
        } else {
            exec_err(format!("{interpreter} not available on this host: {e}"))
        }
    })?;
    let pid = child.id();
    let out = match tokio::time::timeout(Duration::from_secs(timeout_s), child.wait_with_output())
        .await
    {
        Ok(res) => res.map_err(|e| exec_err(format!("wait: {e}")))?,
        Err(_) => {
            if let Some(pid) = pid {
                // SAFETY: kill on our own process group.
                unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            }
            return Err(exec_err(format!("script timed out after {timeout_s}s")));
        }
    };
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str("\n[stderr]\n");
        text.push_str(&err);
    }
    let code = out.status.code().unwrap_or(-1);
    let text = clip(format!("exit={code}\n{text}"));
    if out.status.success() {
        Ok(text)
    } else {
        Err(exec_err(text))
    }
}

struct DirGuard(std::path::PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Is `host:port` allowed by a comma list of `host`, `host:port` or `*.suffix`?
pub(crate) fn host_allowed(allow: &str, host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    allow
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|entry| {
            let (pat, want_port) = match entry.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                    (h.to_string(), p.parse::<u16>().ok())
                }
                _ => (entry.clone(), None),
            };
            if want_port.is_some_and(|p| p != port) {
                return false;
            }
            match pat.strip_prefix("*.") {
                Some(suffix) => host.ends_with(&format!(".{suffix}")),
                None => host == pat,
            }
        })
}

/// Caller-set headers may not steer routing or framing (Host, hop-by-hop,
/// proxy and forwarding headers).
pub(crate) fn header_allowed(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !n.is_empty()
        && n.len() <= 64
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !matches!(
            n.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "content-length"
                | "forwarded"
                | "via"
        )
        && !n.starts_with("proxy-")
        && !n.starts_with("x-forwarded-")
}

pub(crate) async fn http_request(
    spec: &Value,
    allowed: bool,
    allow_list: &str,
) -> Result<String, CommandError> {
    if !allowed {
        return Err(exec_err(
            "HTTP calls are disabled on this agent (set DODO_ALLOW_HTTP=true)",
        ));
    }
    let url_s = spec.get("url").and_then(Value::as_str).unwrap_or("");
    let url = reqwest::Url::parse(url_s).map_err(|_| exec_err("invalid url"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(exec_err("url must be http or https"));
    }
    let host = url.host_str().unwrap_or("");
    let port = url.port_or_known_default().unwrap_or(0);
    if !host_allowed(allow_list, host, port) {
        return Err(exec_err(format!(
            "{host}:{port} is not in DODO_HTTP_ALLOW on this agent"
        )));
    }
    let method = spec
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| exec_err("invalid method"))?;
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
    ) {
        return Err(exec_err("invalid method"));
    }
    let timeout_s = spec
        .get("timeout_s")
        .and_then(Value::as_u64)
        .unwrap_or(15)
        .clamp(1, MAX_HTTP_TIMEOUT);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_s))
        .build()
        .map_err(|e| exec_err(format!("http client: {e}")))?;
    let mut req = client.request(method, url);
    if let Some(h) = spec.get("headers").and_then(Value::as_object) {
        for (k, v) in h {
            if !header_allowed(k) {
                return Err(exec_err(format!("header {k:?} not allowed")));
            }
            req = req.header(k.as_str(), v.as_str().unwrap_or_default());
        }
    }
    match spec.get("body") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => req = req.body(s.clone()),
        Some(other) => req = req.json(other),
    }
    let resp = req
        .send()
        .await
        .map_err(|e| exec_err(format!("request failed: {e}")))?;
    let status = resp.status().as_u16();
    let mut body = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| exec_err(format!("read body: {e}")))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_OUTPUT {
            break;
        }
    }
    Ok(clip(format!(
        "status={status}\n{}",
        String::from_utf8_lossy(&body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(script: &str) -> Value {
        json!({"language": "bash", "script": script, "sha256": sha256_hex(script.as_bytes()), "timeout_s": 5,
               "env": {"DODO_SERVICE": "checkout"}})
    }

    #[test]
    fn parse_only_takes_dodo_manifests() {
        assert!(parse(br#"{"apiVersion":"dodo.io/v1","kind":"HostScript"}"#).is_some());
        assert!(parse(br#"{"apiVersion":"v1","kind":"List"}"#).is_none());
        assert!(parse(b"kind: Pod").is_none());
    }

    #[tokio::test]
    async fn script_disabled_or_tampered_is_refused() {
        let s = spec("echo hi");
        assert!(run_script(&s, false, None).await.is_err());
        let mut bad = s.clone();
        bad["script"] = json!("echo pwned");
        let err = run_script(&bad, true, None).await.unwrap_err().to_string();
        assert!(err.contains("sha256"), "{err}");
    }

    #[tokio::test]
    async fn script_runs_with_clean_env_and_reports_exit() {
        std::env::set_var("DODO_LEAK_TEST", "secret");
        let ok = run_script(&spec("echo \"svc=$DODO_SERVICE leak=${DODO_LEAK_TEST:-none}\"\necho '{\"healthy\":true}'"), true, None)
            .await
            .unwrap();
        assert!(ok.starts_with("exit=0"), "{ok}");
        assert!(ok.contains("svc=checkout leak=none"), "{ok}");
        let err = run_script(&spec("echo boom >&2; exit 3"), true, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("exit=3") && err.contains("boom"), "{err}");
    }

    #[tokio::test]
    async fn script_timeout_kills() {
        let mut s = spec("sleep 30");
        s["timeout_s"] = json!(1);
        let err = run_script(&s, true, None).await.unwrap_err().to_string();
        assert!(err.contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn bad_env_and_language_refused() {
        let mut s = spec("true");
        s["env"] = json!({"LD_PRELOAD": "/x.so"});
        assert!(run_script(&s, true, None).await.is_err());
        let mut s = spec("true");
        s["language"] = json!("ruby");
        assert!(run_script(&s, true, None).await.is_err());
    }

    #[test]
    fn script_user_must_differ_from_agent_and_root() {
        assert!(target_ids("root").is_err());
        assert!(target_ids("no-such-user-dodo").is_err());
        // SAFETY: getpwuid(geteuid()) returns the current user's entry.
        let me = unsafe { std::ffi::CStr::from_ptr((*libc::getpwuid(libc::geteuid())).pw_name) }
            .to_string_lossy()
            .into_owned();
        assert!(target_ids(&me).is_err());
    }

    #[test]
    fn routing_headers_refused() {
        for h in [
            "Host",
            "Connection",
            "Transfer-Encoding",
            "Proxy-Authorization",
            "X-Forwarded-For",
            "bad header",
        ] {
            assert!(!header_allowed(h), "{h}");
        }
        assert!(header_allowed("Authorization"));
        assert!(header_allowed("X-Api-Key"));
    }

    #[test]
    fn allow_list_matching() {
        let allow = "api.internal, *.corp.local, billing:8080";
        assert!(host_allowed(allow, "api.internal", 443));
        assert!(host_allowed(allow, "x.corp.local", 80));
        assert!(!host_allowed(allow, "corp.local", 80));
        assert!(host_allowed(allow, "billing", 8080));
        assert!(!host_allowed(allow, "billing", 80));
        assert!(!host_allowed(allow, "evil.com", 443));
        assert!(!host_allowed("", "api.internal", 443));
    }

    #[tokio::test]
    async fn http_refused_unless_enabled_and_listed() {
        let s = json!({"url": "http://169.254.169.254/latest/meta-data", "method": "GET"});
        assert!(http_request(&s, false, "*").await.is_err());
        let err = http_request(&s, true, "api.internal")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not in DODO_HTTP_ALLOW"), "{err}");
        let s = json!({"url": "file:///etc/passwd"});
        assert!(http_request(&s, true, "*").await.is_err());
    }
}
