use anyhow::{bail, Context, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, PKCS_ECDSA_P256_SHA256};
use std::io::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;
use x509_parser::prelude::FromDer as _;

const RENEWAL_THRESHOLD_SECS: i64 = 7 * 86_400;

/// Returns true if the PEM cert at `path` exists and does not expire within 7 days.
pub fn cert_needs_renewal(path: &str) -> bool {
    let Ok(pem_bytes) = std::fs::read(path) else {
        return true;
    };
    let mut cursor = std::io::Cursor::new(&pem_bytes[..]);
    let cert_der = rustls_pemfile::certs(&mut cursor)
        .find_map(|r| r.ok())
        .map(|c| c.to_vec());

    let Some(der) = cert_der else { return true };

    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&der) else {
        return true;
    };

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    cert.validity().not_after.timestamp() - now_ts < RENEWAL_THRESHOLD_SECS
}

#[derive(serde::Serialize)]
struct EnrollRequest<'a> {
    agent_id: &'a str,
    host_id: &'a str,
    csr_pem: String,
}

#[derive(serde::Deserialize)]
struct EnrollResponse {
    ca_cert_pem: String,
    agent_cert_pem: String,
    expires_at: String,
    #[serde(default)]
    agent_jwt: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // parsed for completeness; refresh_token() re-derives its own schedule
    agent_jwt_expires_at: Option<String>,
}

#[derive(serde::Deserialize)]
struct RefreshResponse {
    agent_jwt: String,
    #[allow(dead_code)]
    agent_jwt_expires_at: String,
}

/// Generates an ECDSA P-256 key pair and a CSR with CN=agent_id.
/// Returns (key_pem, csr_pem).
fn generate_csr(agent_id: &str) -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, agent_id);
    params.distinguished_name = dn;

    let cert = Certificate::from_params(params).context("generating ECDSA key pair and CSR")?;
    let key_pem = cert.serialize_private_key_pem();
    let csr_pem = cert
        .serialize_request_pem()
        .context("serializing CSR to PEM")?;
    Ok((key_pem, csr_pem))
}

/// Writes CA cert, agent cert, and private key to `certs_dir`.
/// The private key file is created with mode 0600 on Unix.
fn write_certs(ca_pem: &str, cert_pem: &str, key_pem: &str, certs_dir: &str) -> Result<()> {
    std::fs::create_dir_all(certs_dir)
        .with_context(|| format!("creating certs directory {certs_dir}"))?;

    std::fs::write(format!("{certs_dir}/ca.pem"), ca_pem.as_bytes()).context("writing ca.pem")?;
    std::fs::write(format!("{certs_dir}/agent.pem"), cert_pem.as_bytes())
        .context("writing agent.pem")?;

    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(format!("{certs_dir}/agent-key.pem"))
                .context("creating agent-key.pem")?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(format!("{certs_dir}/agent-key.pem"))
            .context("creating agent-key.pem")?;

        f.write_all(key_pem.as_bytes())
            .context("writing agent-key.pem")?;
    }

    Ok(())
}

/// Checks whether certificates need to be obtained and, if so, performs enrollment.
///
/// Called at agent startup (before transport init) and by the config watcher for renewal.
/// No-ops if `enrollment_endpoint` is empty or `api_key` is missing.
///
/// On success, if the response includes a `jwt`, stores it into `token` — see
/// `refresh_token` for why that has to keep happening independently on a much
/// shorter cycle than certificate renewal.
pub async fn enroll_if_needed(
    enrollment_endpoint: &str,
    api_key: &str,
    agent_id: &str,
    host_id: &str,
    client_cert_path: &str,
    certs_dir: &str,
    token: &crate::SharedToken,
) -> Result<()> {
    if enrollment_endpoint.is_empty() || api_key.is_empty() {
        return Ok(());
    }

    if !cert_needs_renewal(client_cert_path) {
        return Ok(());
    }

    info!(
        endpoint = enrollment_endpoint,
        "certificates missing or expiring — starting enrollment"
    );

    let (key_pem, csr_pem) = generate_csr(agent_id).context("generating CSR")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building enrollment HTTP client")?;

    let resp = client
        .post(enrollment_endpoint)
        .bearer_auth(api_key)
        .json(&EnrollRequest {
            agent_id,
            host_id,
            csr_pem,
        })
        .send()
        .await
        .context("sending enrollment request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("enrollment endpoint returned {status}: {body}");
    }

    let enroll: EnrollResponse = resp.json().await.context("decoding enrollment response")?;

    write_certs(
        &enroll.ca_cert_pem,
        &enroll.agent_cert_pem,
        &key_pem,
        certs_dir,
    )
    .context("writing certificates to disk")?;

    info!(expires_at = %enroll.expires_at, "enrollment complete — mTLS certificates installed");

    if let Some(jwt) = enroll.agent_jwt {
        *token.write().unwrap_or_else(|e| e.into_inner()) = Some(jwt);
    } else {
        info!("enrollment response had no agent_jwt — jwt-guarded routes will fail until a refresh succeeds");
    }

    Ok(())
}

/// Derives the `/v1/token/refresh` URL from the `/v1/enroll` URL, since both
/// live on the same no-mTLS enrollment endpoint (see aegis-kong-enrollment).
fn refresh_endpoint(enrollment_endpoint: &str) -> String {
    match enrollment_endpoint.rsplit_once("/v1/enroll") {
        Some((base, _)) => format!("{base}/v1/token/refresh"),
        None => format!(
            "{}/v1/token/refresh",
            enrollment_endpoint.trim_end_matches('/')
        ),
    }
}

/// Server-issued tokens are valid ~55m (see dodo_ingestor's
/// AgentTokenIssuer, under the Kong jwt plugin's 1h maximum_expiration cap).
/// Refreshing at 45m leaves comfortable margin without parsing
/// `agent_jwt_expires_at` (would need pulling in `time`/`chrono` for just
/// this), and errs toward refreshing a bit early rather than risking expiry.
const REFRESH_INTERVAL: Duration = Duration::from_secs(45 * 60);

/// Reissues the short-lived JWT that satisfies Kong's jwt plugin, without
/// touching the mTLS certificate. Must be called well before expiry — call
/// site is `main.rs`'s periodic refresh task.
///
/// Returns how long the caller should wait before refreshing again.
pub async fn refresh_token(
    enrollment_endpoint: &str,
    api_key: &str,
    agent_id: &str,
    token: &crate::SharedToken,
) -> Result<Duration> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building token refresh HTTP client")?;

    #[derive(serde::Serialize)]
    struct RefreshRequest<'a> {
        agent_id: &'a str,
    }

    let resp = client
        .post(refresh_endpoint(enrollment_endpoint))
        .bearer_auth(api_key)
        .json(&RefreshRequest { agent_id })
        .send()
        .await
        .context("sending token refresh request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("token refresh endpoint returned {status}: {body}");
    }

    let refreshed: RefreshResponse = resp.json().await.context("decoding refresh response")?;

    *token.write().unwrap_or_else(|e| e.into_inner()) = Some(refreshed.agent_jwt);

    info!("agent JWT refreshed");

    Ok(REFRESH_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ingestor's enrollment handler reads `host_id` from the request
    /// body to populate agents.host_id (the stable cross-reinstall identity
    /// used for host dedup) — this pins the wire field name so a rename
    /// here doesn't silently stop working server-side.
    #[test]
    fn enroll_request_serializes_host_id() {
        let req = EnrollRequest {
            agent_id: "11111111-1111-4111-8111-111111111111",
            host_id: "22222222-2222-4222-8222-222222222222",
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n...".to_string(),
        };

        let value = serde_json::to_value(&req).expect("EnrollRequest must serialize");
        assert_eq!(value["agent_id"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(value["host_id"], "22222222-2222-4222-8222-222222222222");
        assert!(value["csr_pem"].as_str().unwrap().starts_with("-----BEGIN"));
    }
}
