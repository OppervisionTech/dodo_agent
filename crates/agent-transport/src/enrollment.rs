use anyhow::{bail, Context, Result};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
};
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
fn generate_csr(agent_id: &str, existing_key: Option<&str>) -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    if let Some(key) = existing_key {
        params.key_pair = Some(KeyPair::from_pem(key).context("loading enrolled private key")?);
    }

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
fn write_private_file(path: &str, bytes: &[u8]) -> Result<()> {
    let path = std::path::Path::new(path);
    let parent = path.parent().context("state file requires parent")?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let tmp = parent.join(format!(
        ".state-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_certs(ca_pem: &str, cert_pem: &str, key_pem: &str, certs_dir: &str) -> Result<()> {
    // Key is stable across renewals; readers never observe a truncated file.
    write_private_file(&format!("{certs_dir}/agent-key.pem"), key_pem.as_bytes())?;
    write_private_file(&format!("{certs_dir}/ca.pem"), ca_pem.as_bytes())?;
    write_private_file(&format!("{certs_dir}/agent.pem"), cert_pem.as_bytes())?;
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
        // JWT lives only in memory. Warm restarts must refresh before starting
        // transport even though their long-lived certificate is still valid.
        refresh_token(enrollment_endpoint, api_key, agent_id, certs_dir, token).await?;
        return Ok(());
    }

    info!(
        endpoint = enrollment_endpoint,
        "certificates missing or expiring — starting enrollment"
    );

    let key_path = format!("{certs_dir}/agent-key.pem");
    let existing_key = match std::fs::read_to_string(&key_path) {
        Ok(key) => Some(key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("reading enrolled private key"),
    };
    let (key_pem, csr_pem) =
        generate_csr(agent_id, existing_key.as_deref()).context("generating CSR")?;
    // Persist before the request: retries after a crash must prove the same key.
    if existing_key.is_none() {
        write_private_file(&key_path, key_pem.as_bytes())?;
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
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
        bail!("enrollment endpoint returned {status}");
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
fn refresh_proof(agent_id: &str, certs_dir: &str) -> Result<(String, u64, String)> {
    use base64::Engine as _;
    let key_pem = std::fs::read_to_string(format!("{certs_dir}/agent-key.pem"))
        .context("reading refresh identity key")?;
    let (_, csr_pem) = generate_csr(agent_id, Some(&key_pem))?;
    let mut cursor = std::io::Cursor::new(key_pem.as_bytes());
    let der = rustls_pemfile::private_key(&mut cursor)?.context("missing PKCS8 private key")?;
    let rng = ring::rand::SystemRandom::new();
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        der.secret_der(),
        &rng,
    )
    .map_err(|_| anyhow::anyhow!("invalid P256 identity key"))?;
    let proof_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let message = format!("dodo-token-refresh\n{agent_id}\n{proof_timestamp}");
    let signature = key
        .sign(&rng, message.as_bytes())
        .map_err(|_| anyhow::anyhow!("signing refresh proof failed"))?;
    let proof_signature = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());
    Ok((csr_pem, proof_timestamp, proof_signature))
}

pub async fn refresh_token(
    enrollment_endpoint: &str,
    api_key: &str,
    agent_id: &str,
    certs_dir: &str,
    token: &crate::SharedToken,
) -> Result<Duration> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("building token refresh HTTP client")?;

    #[derive(serde::Serialize)]
    struct RefreshRequest<'a> {
        agent_id: &'a str,
        csr_pem: String,
        proof_timestamp: u64,
        proof_signature: String,
    }
    let (csr_pem, proof_timestamp, proof_signature) = refresh_proof(agent_id, certs_dir)?;

    let resp = client
        .post(refresh_endpoint(enrollment_endpoint))
        .bearer_auth(api_key)
        .json(&RefreshRequest {
            agent_id,
            csr_pem,
            proof_timestamp,
            proof_signature,
        })
        .send()
        .await
        .context("sending token refresh request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        bail!("token refresh endpoint returned {status}");
    }

    let refreshed: RefreshResponse = resp.json().await.context("decoding refresh response")?;

    *token.write().unwrap_or_else(|e| e.into_inner()) = Some(refreshed.agent_jwt);

    info!("agent JWT refreshed");

    Ok(REFRESH_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_renewal_checks_missing_corrupt_expired_and_valid_state() {
        let directory = crate::test_network::Directory::new();
        let path = directory.0.join("agent.pem");
        assert!(cert_needs_renewal(path.to_str().unwrap()));
        for invalid in [
            "not a certificate",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(cert_needs_renewal(path.to_str().unwrap()));
        }
        let mut params = CertificateParams::default();
        params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        let expired = Certificate::from_params(params).unwrap();
        std::fs::write(&path, expired.serialize_pem().unwrap()).unwrap();
        assert!(cert_needs_renewal(path.to_str().unwrap()));
        let valid = Certificate::from_params(CertificateParams::default()).unwrap();
        std::fs::write(&path, valid.serialize_pem().unwrap()).unwrap();
        assert!(!cert_needs_renewal(path.to_str().unwrap()));
        assert_eq!(
            refresh_endpoint("https://example.test/"),
            "https://example.test/v1/token/refresh"
        );
    }

    #[tokio::test]
    async fn real_http_enrollment_then_warm_restart_refresh_preserves_identity() {
        let directory = crate::test_network::Directory::new();
        let cert = Certificate::from_params(CertificateParams::default())
            .unwrap()
            .serialize_pem()
            .unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = requests.clone();
        let response_cert = cert.clone();
        let server = crate::test_network::http(move |request| {
            assert_eq!(request.headers()["authorization"], "Bearer synthetic-key");
            let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
            captured
                .lock()
                .unwrap()
                .push((request.uri().path().to_string(), body));
            let response = if request.uri().path() == "/v1/enroll" {
                serde_json::json!({"ca_cert_pem":response_cert,"agent_cert_pem":response_cert,
                    "expires_at":"future", "agent_jwt":"enrolled-token"})
            } else {
                serde_json::json!({"agent_jwt":"refreshed-token", "agent_jwt_expires_at":"future"})
            };
            (200, serde_json::to_vec(&response).unwrap())
        })
        .await;
        let endpoint = format!("http://{}/v1/enroll", server.address);
        let path = directory.0.join("certs/agent.pem");
        let certs = directory.0.join("certs");
        let token = crate::SharedToken::default();
        enroll_if_needed(
            &endpoint,
            "synthetic-key",
            "agent",
            "host",
            path.to_str().unwrap(),
            certs.to_str().unwrap(),
            &token,
        )
        .await
        .unwrap();
        assert_eq!(token.read().unwrap().as_deref(), Some("enrolled-token"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), cert);
        let original_key = std::fs::read_to_string(certs.join("agent-key.pem")).unwrap();
        *token.write().unwrap() = None;
        enroll_if_needed(
            &endpoint,
            "synthetic-key",
            "agent",
            "host",
            path.to_str().unwrap(),
            certs.to_str().unwrap(),
            &token,
        )
        .await
        .unwrap();
        assert_eq!(token.read().unwrap().as_deref(), Some("refreshed-token"));
        assert_eq!(
            std::fs::read_to_string(certs.join("agent-key.pem")).unwrap(),
            original_key
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].0, "/v1/enroll");
        assert_eq!(requests[0].1["host_id"], "host");
        assert_eq!(requests[1].0, "/v1/token/refresh");
        assert_eq!(requests[1].1["agent_id"], "agent");
        assert!(requests[1].1["proof_timestamp"].as_u64().unwrap() > 0);
        assert!(!requests[1].1["proof_signature"]
            .as_str()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn rejected_or_malformed_responses_never_replace_certificates_or_tokens() {
        for (status, body) in [
            (401, "unauthorized"),
            (302, "redirect"),
            (200, "invalid json"),
        ] {
            let directory = crate::test_network::Directory::new();
            let server =
                crate::test_network::http(move |_| (status, body.as_bytes().to_vec())).await;
            let endpoint = format!("http://{}/v1/enroll", server.address);
            let certs = directory.0.to_str().unwrap();
            let path = directory.0.join("agent.pem");
            let token = crate::SharedToken::default();
            *token.write().unwrap() = Some("original-token".into());
            assert!(enroll_if_needed(
                &endpoint,
                "synthetic-key",
                "agent",
                "host",
                path.to_str().unwrap(),
                certs,
                &token
            )
            .await
            .is_err());
            assert!(!path.exists());
            let key = std::fs::read_to_string(directory.0.join("agent-key.pem")).unwrap();
            assert!(enroll_if_needed(
                &endpoint,
                "synthetic-key",
                "agent",
                "host",
                path.to_str().unwrap(),
                certs,
                &token
            )
            .await
            .is_err());
            assert_eq!(
                std::fs::read_to_string(directory.0.join("agent-key.pem")).unwrap(),
                key
            );
            assert!(
                refresh_token(&endpoint, "synthetic-key", "agent", certs, &token)
                    .await
                    .is_err()
            );
            assert_eq!(token.read().unwrap().as_deref(), Some("original-token"));
        }
        let token = crate::SharedToken::default();
        enroll_if_needed("", "", "agent", "host", "/not-read", "/not-created", &token)
            .await
            .unwrap();
    }

    #[test]
    fn renewal_keeps_private_key_and_refresh_proves_possession() {
        use base64::Engine as _;
        let dir = std::env::temp_dir().join(format!("dodo-proof-{}", uuid::Uuid::new_v4()));
        let (key, _) = generate_csr("test-agent", None).expect("key");
        write_private_file(
            dir.join("agent-key.pem").to_str().expect("path"),
            key.as_bytes(),
        )
        .expect("persist key");
        let (renewed_key, _) = generate_csr("test-agent", Some(&key)).expect("renewal CSR");
        assert_eq!(key, renewed_key);
        let (_, timestamp, signature) =
            refresh_proof("test-agent", dir.to_str().expect("dir")).expect("proof");
        let pair = KeyPair::from_pem(&key).expect("parse key");
        let verifier = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            pair.public_key_raw(),
        );
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .expect("base64");
        let message = format!("dodo-token-refresh\ntest-agent\n{timestamp}");
        verifier
            .verify(message.as_bytes(), &signature)
            .expect("valid proof");
        assert!(verifier
            .verify(b"dodo-token-refresh\nother-agent\n0", &signature)
            .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.join("agent-key.pem"))
                    .expect("key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&dir)
                    .expect("dir metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

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
