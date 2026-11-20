//! Self-update for agents installed as a binary (systemd / Windows service).
//!
//! Kubernetes installs are updated by the platform patching the DaemonSet
//! image (org update policy), never by the binary replacing itself inside a
//! container. Here the agent:
//!   1. every `DODO_UPDATE_INTERVAL_HOURS` (default 6) asks
//!      `$DODO_UPDATE_URL?channel=<stable|beta>` for the latest release;
//!   2. if newer and `DODO_AUTO_UPDATE=auto`, downloads the artifact for its
//!      target over HTTPS, verifies the SHA-256 published with the release,
//!      swaps the executable atomically (keeping `<exe>.previous`) and exits
//!      so the service manager restarts it on the new version;
//!   3. with `DODO_AUTO_UPDATE=notify` (default) it only logs that an update
//!      is available — the dashboard shows it from the heartbeat version.
//!
//! Nothing runs unless `DODO_UPDATE_URL` is set. Auto-install additionally
//! needs an Ed25519 release public key compiled in (`DODO_RELEASE_PUBKEY`,
//! hex, set by the release CI): every artifact must carry a signature by the
//! matching private key, so a compromised release server or metadata
//! endpoint cannot push a binary. Without the key the agent only notifies.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Off,
    Notify,
    Auto,
}

#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    pub url: String,
    pub channel: String,
    pub mode: Mode,
    pub interval: Duration,
}

impl UpdaterConfig {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("DODO_UPDATE_URL").ok()?.trim().to_string();
        if !url.starts_with("https://") {
            if !url.is_empty() {
                warn!(url = %url, "DODO_UPDATE_URL must be https — self-update disabled");
            }
            return None;
        }
        let mode = match std::env::var("DODO_AUTO_UPDATE")
            .unwrap_or_else(|_| "notify".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "auto" => Mode::Auto,
            "off" | "manual" => Mode::Off,
            _ => Mode::Notify,
        };
        if mode == Mode::Off {
            return None;
        }
        let hours: u64 = std::env::var("DODO_UPDATE_INTERVAL_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|h| *h >= 1)
            .unwrap_or(6);
        Some(Self {
            url,
            channel: std::env::var("DODO_UPDATE_CHANNEL").unwrap_or_else(|_| "stable".into()),
            mode,
            interval: Duration::from_secs(hours * 3600),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
}

/// Ed25519 public key (hex) of the release signer, baked in at build time.
const RELEASE_PUBKEY: Option<&str> = option_env!("DODO_RELEASE_PUBKEY");
/// Artifacts are only fetched from the release host.
const ALLOWED_URL_PREFIXES: &[&str] = &["https://github.com/OppervisionTech/dodo-agent-releases/"];
const MAX_ARTIFACT_BYTES: usize = 150 * 1024 * 1024;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Checks `signature` (hex Ed25519) over `bytes` with the public key `pubkey_hex`.
pub fn verify_signature(bytes: &[u8], signature: &str, pubkey_hex: &str) -> bool {
    let (Some(sig), Some(key)) = (hex_decode(signature), hex_decode(pubkey_hex)) else {
        return false;
    };
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(bytes, &sig)
        .is_ok()
}

pub fn url_allowed(url: &str) -> bool {
    ALLOWED_URL_PREFIXES.iter().any(|p| url.starts_with(p))
}

/// Picks the artifact for `target` out of the release JSON
/// `{"version": "...", "artifacts": {"<target>": {"url", "sha256"}}}`.
pub fn parse_release(body: &serde_json::Value, target: &str) -> Option<Release> {
    let version = body.get("version")?.as_str()?.to_string();
    let art = body.get("artifacts")?.get(target)?;
    let url = art.get("url")?.as_str()?.to_string();
    let sha256 = art.get("sha256")?.as_str()?.to_ascii_lowercase();
    let signature = art
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !url.starts_with("https://") || sha256.len() != 64 {
        return None;
    }
    Some(Release {
        version,
        url,
        sha256,
        signature,
    })
}

/// "1.2.10" > "1.10.0" is false; leading "v" and "-suffix" ignored.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        let v = v.trim().trim_start_matches('v');
        let v = v.split(['-', '+']).next().unwrap_or("");
        v.split('.').map_while(|p| p.parse().ok()).collect()
    }
    let (a, b) = (parts(candidate), parts(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    false
}

pub fn target_triple() -> String {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "windows" => format!("{arch}-pc-windows-msvc"),
        "macos" => format!("{arch}-apple-darwin"),
        _ => format!("{arch}-unknown-linux-musl"),
    }
}

pub fn verify_sha256(bytes: &[u8], expected: &str) -> bool {
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    actual.eq_ignore_ascii_case(expected)
}

/// Writes `bytes` next to `exe`, then renames: exe -> exe.previous, new -> exe.
pub fn swap_executable(exe: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let new_path = exe.with_extension("new");
    std::fs::write(&new_path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o755))?;
    }
    let previous = exe.with_extension("previous");
    let _ = std::fs::remove_file(&previous);
    std::fs::rename(exe, &previous)?;
    if let Err(e) = std::fs::rename(&new_path, exe) {
        let _ = std::fs::rename(&previous, exe); // roll back
        return Err(e);
    }
    Ok(previous)
}

fn in_kubernetes() -> bool {
    std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

pub async fn run(cfg: UpdaterConfig, current: &'static str, cancel: CancellationToken) {
    if in_kubernetes() {
        info!("running in Kubernetes — agent updates come from the platform (image)");
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "updater disabled: http client");
            return;
        }
    };
    let target = target_triple();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(300)) => {}
        }
        match check_once(&client, &cfg, &target, current).await {
            Ok(true) => {
                info!("agent updated — exiting so the service manager restarts it");
                cancel.cancel();
                std::process::exit(0);
            }
            Ok(false) => {}
            Err(e) => warn!(error = %e, "update check failed"),
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(cfg.interval) => {}
        }
    }
}

async fn check_once(
    client: &reqwest::Client,
    cfg: &UpdaterConfig,
    target: &str,
    current: &str,
) -> anyhow::Result<bool> {
    let body: serde_json::Value = client
        .get(&cfg.url)
        .query(&[("channel", cfg.channel.as_str())])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let Some(release) = parse_release(&body, target) else {
        return Ok(false);
    };
    if !is_newer(&release.version, current) {
        return Ok(false);
    }
    let pubkey = RELEASE_PUBKEY.filter(|k| k.len() == 64);
    if cfg.mode == Mode::Notify || pubkey.is_none() {
        if cfg.mode == Mode::Auto {
            warn!("auto-update needs a build with DODO_RELEASE_PUBKEY — notifying only");
        }
        info!(current, available = %release.version, "agent update available");
        return Ok(false);
    }
    if !url_allowed(&release.url) {
        anyhow::bail!("artifact URL outside the release host — refused");
    }
    info!(current, version = %release.version, "downloading agent update");
    let mut resp = client.get(&release.url).send().await?.error_for_status()?;
    if resp.content_length().unwrap_or(0) as usize > MAX_ARTIFACT_BYTES {
        anyhow::bail!("artifact too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > MAX_ARTIFACT_BYTES {
            anyhow::bail!("artifact too large");
        }
    }
    if !verify_sha256(&bytes, &release.sha256) {
        anyhow::bail!("downloaded agent does not match published sha256 — refused");
    }
    if !verify_signature(&bytes, &release.signature, pubkey.unwrap_or_default()) {
        anyhow::bail!("artifact signature invalid — refused");
    }
    let exe = std::env::current_exe()?;
    swap_executable(&exe, &bytes)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_versions() {
        assert!(is_newer("1.10.0", "1.2.10"));
        assert!(is_newer("v0.5.1", "0.5.0"));
        assert!(!is_newer("0.5.0", "0.5.0"));
        assert!(!is_newer("0.4.9", "0.5.0"));
    }

    #[test]
    fn release_parsing() {
        let sha = "a".repeat(64);
        let body = serde_json::json!({"version": "1.2.0", "artifacts": {
            "x86_64-unknown-linux-musl": {"url": "https://x/agent", "sha256": sha}}});
        let r = parse_release(&body, "x86_64-unknown-linux-musl").unwrap();
        assert_eq!(r.version, "1.2.0");
        assert!(parse_release(&body, "aarch64-unknown-linux-musl").is_none());
        let http = serde_json::json!({"version": "1", "artifacts": {
            "t": {"url": "http://x", "sha256": "a".repeat(64)}}});
        assert!(parse_release(&http, "t").is_none());
    }

    #[test]
    fn signatures() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let pk = hex(kp.public_key().as_ref());
        let sig = hex(kp.sign(b"binary").as_ref());
        assert!(verify_signature(b"binary", &sig, &pk));
        assert!(!verify_signature(b"evil", &sig, &pk));
        assert!(!verify_signature(b"binary", "zz", &pk));
        assert!(url_allowed(
            "https://github.com/OppervisionTech/dodo-agent-releases/releases/download/v1/a"
        ));
        assert!(!url_allowed("https://evil.example/agent"));
    }

    #[test]
    fn sha_and_swap() {
        let dir = std::env::temp_dir().join(format!("dodo-upd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("aegis-agent");
        std::fs::write(&exe, b"old").unwrap();
        let new = b"new-binary";
        let sum: String = Sha256::digest(new)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(verify_sha256(new, &sum));
        assert!(!verify_sha256(b"evil", &sum));
        let prev = swap_executable(&exe, new).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), new);
        assert_eq!(std::fs::read(prev).unwrap(), b"old");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
