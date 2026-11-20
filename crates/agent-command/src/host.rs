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
            run_script(&spec, env_flag("DODO_ALLOW_SCRIPTS"), &script_user()).await
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
    std::env::var("DODO_SCRIPT_USER").unwrap_or_else(|_| "nobody".into())
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

/// (uid, gid) of `user` when this process is root; None otherwise.
#[cfg(unix)]
fn target_ids(user: &str) -> Result<Option<(u32, u32)>, CommandError> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let name = std::ffi::CString::new(user).map_err(|_| exec_err("invalid DODO_SCRIPT_USER"))?;
    // SAFETY: getpwnam reads a static buffer; we copy the ids immediately and
    // this runs on the executor's single command path.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(exec_err(format!(
            "script user {user:?} not found on this host"
        )));
    }
    // SAFETY: pw is non-null and points to a valid passwd struct.
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    if uid == 0 {
        return Err(exec_err("refusing to run workflow scripts as root"));
    }
    Ok(Some((uid, gid)))
}

pub(crate) async fn run_script(
    spec: &Value,
    allowed: bool,
    user: &str,
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
    let path = dir.join("script");
    std::fs::write(&path, script).map_err(|e| exec_err(format!("write script: {e}")))?;
    let ids = target_ids(user)?;
    if let Some((uid, gid)) = ids {
        use std::os::unix::fs::chown;
        chown(&dir, Some(uid), Some(gid)).map_err(|e| exec_err(format!("chown: {e}")))?;
        chown(&path, Some(uid), Some(gid)).map_err(|e| exec_err(format!("chown: {e}")))?;
    }

    let mut cmd = tokio::process::Command::new(interpreter);
    cmd.arg(&path)
        .current_dir(&dir)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("HOME", &dir)
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
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| exec_err(format!("{interpreter} not available on this host: {e}")))?;
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
        assert!(run_script(&s, false, "nobody").await.is_err());
        let mut bad = s.clone();
        bad["script"] = json!("echo pwned");
        let err = run_script(&bad, true, "nobody")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("sha256"), "{err}");
    }

    #[tokio::test]
    async fn script_runs_with_clean_env_and_reports_exit() {
        std::env::set_var("DODO_LEAK_TEST", "secret");
        let ok = run_script(&spec("echo \"svc=$DODO_SERVICE leak=${DODO_LEAK_TEST:-none}\"\necho '{\"healthy\":true}'"), true, "nobody")
            .await
            .unwrap();
        assert!(ok.starts_with("exit=0"), "{ok}");
        assert!(ok.contains("svc=checkout leak=none"), "{ok}");
        let err = run_script(&spec("echo boom >&2; exit 3"), true, "nobody")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("exit=3") && err.contains("boom"), "{err}");
    }

    #[tokio::test]
    async fn script_timeout_kills() {
        let mut s = spec("sleep 30");
        s["timeout_s"] = json!(1);
        let err = run_script(&s, true, "nobody")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn bad_env_and_language_refused() {
        let mut s = spec("true");
        s["env"] = json!({"LD_PRELOAD": "/x.so"});
        assert!(run_script(&s, true, "nobody").await.is_err());
        let mut s = spec("true");
        s["language"] = json!("ruby");
        assert!(run_script(&s, true, "nobody").await.is_err());
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
