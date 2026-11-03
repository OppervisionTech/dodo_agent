use crate::{TransportConfig, TransportError, TransportResult};

/// Load PEM file contents as bytes.
fn load_pem_bytes(path: &str, label: &str) -> TransportResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| TransportError::Tls(format!("cannot read {label} from {path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_or_invalid_tls_material_and_endpoints_fail_closed() {
        let directory = crate::test_network::Directory::new();
        let mut config = TransportConfig {
            endpoint_address: "127.0.0.1:1".into(),
            ca_cert_path: directory.0.join("missing.pem").to_str().unwrap().into(),
            ..Default::default()
        };
        assert!(matches!(
            build_grpc_channel(&config).await,
            Err(TransportError::Tls(_))
        ));
        let cert = rcgen::Certificate::from_params(rcgen::CertificateParams::default()).unwrap();
        let path = directory.0.join("ca.pem");
        std::fs::write(&path, cert.serialize_pem().unwrap()).unwrap();
        config.ca_cert_path = path.to_str().unwrap().into();
        config.client_cert_path = path.to_str().unwrap().into();
        config.client_key_path = directory.0.join("missing-key.pem").to_str().unwrap().into();
        assert!(matches!(
            build_grpc_channel(&config).await,
            Err(TransportError::Tls(_))
        ));
        let key = directory.0.join("key.pem");
        std::fs::write(&key, cert.serialize_private_key_pem()).unwrap();
        config.client_key_path = key.to_str().unwrap().into();
        config.timeout_ms = 0;
        let result = build_grpc_channel(&config).await;
        assert!(
            matches!(result, Err(TransportError::Connection(_))),
            "{result:?}"
        );
        config.endpoint_address = "not a valid authority".into();
        assert!(matches!(
            build_grpc_channel(&config).await,
            Err(TransportError::Connection(_))
        ));
        config.tls_enabled = false;
        assert!(matches!(
            build_grpc_channel(&config).await,
            Err(TransportError::Connection(_))
        ));
        config.endpoint_address = "127.0.0.1:1".into();
        assert!(matches!(
            build_grpc_channel(&config).await,
            Err(TransportError::Connection(_))
        ));
    }
}

/// Build a tonic Channel for connecting to the ingestor.
///
/// When TLS is enabled (production), uses mTLS with PEM certificates.
/// When TLS is disabled (local dev), uses plaintext gRPC.
pub async fn build_grpc_channel(
    config: &TransportConfig,
) -> TransportResult<tonic::transport::Channel> {
    if !config.tls_enabled {
        // Plaintext gRPC for local development
        let mut endpoint =
            tonic::transport::Channel::from_shared(format!("http://{}", config.endpoint_address))
                .map_err(|e| TransportError::Connection(format!("invalid endpoint: {e}")))?
                .keep_alive_timeout(std::time::Duration::from_secs(30))
                .http2_keep_alive_interval(std::time::Duration::from_secs(30));
        if config.timeout_ms > 0 {
            endpoint = endpoint.timeout(std::time::Duration::from_millis(config.timeout_ms as u64));
        }
        // Unconditional: bounds the initial connect even when timeout_ms == 0
        // (the command channel's deliberate "no per-call deadline, stream
        // stays open indefinitely" setting) — otherwise a hung TCP/TLS
        // handshake blocks forever, uninterruptible even by shutdown.
        endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(10));

        let channel = endpoint.connect().await.map_err(|e| {
            TransportError::Connection(format!(
                "failed to connect to {}: {e}",
                config.endpoint_address
            ))
        })?;

        return Ok(channel);
    }

    // mTLS for production (via Kong)
    //
    // Kong's server certificate is a normal publicly-issued one (Let's
    // Encrypt), verified against the OS/Mozilla root store — NOT against
    // `ca_cert_path`, which is the AegisOps internal CA that *issues this
    // agent's own client certificate* (so Kong can verify us), unrelated to
    // verifying Kong's server cert. tonic only trusts what you explicitly
    // add: without `.with_native_roots()`, the connection had exactly one
    // trusted issuer (the internal CA), so Kong's real cert could never
    // validate — every gRPC connect failed here, silently, with no TLS
    // alert (confirmed live: curl using the system trust store connected
    // fine against the same host/cert every time; this channel never did).
    let mut tls = tonic::transport::ClientTlsConfig::new().with_native_roots();

    // Internal AegisOps CA — kept as an additional trusted issuer (harmless,
    // and covers the case Kong ever sits behind a private CA instead), but
    // NOT a substitute for the native roots above.
    if !config.ca_cert_path.is_empty() {
        let ca_pem = load_pem_bytes(&config.ca_cert_path, "CA cert")?;
        let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);
        tls = tls.ca_certificate(ca_cert);
    }

    // Client certificate + key for mTLS
    if !config.client_cert_path.is_empty() && !config.client_key_path.is_empty() {
        let cert_pem = load_pem_bytes(&config.client_cert_path, "client cert")?;
        let key_pem = load_pem_bytes(&config.client_key_path, "client key")?;
        let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
        tls = tls.identity(identity);
    }

    let mut endpoint =
        tonic::transport::Channel::from_shared(format!("https://{}", config.endpoint_address))
            .map_err(|e| TransportError::Connection(format!("invalid endpoint: {e}")))?
            .tls_config(tls)
            .map_err(|e| TransportError::Tls(format!("TLS config error: {e}")))?
            .keep_alive_timeout(std::time::Duration::from_secs(30))
            .http2_keep_alive_interval(std::time::Duration::from_secs(30));
    if config.timeout_ms > 0 {
        endpoint = endpoint.timeout(std::time::Duration::from_millis(config.timeout_ms as u64));
    }
    endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(10));

    let channel = endpoint.connect().await.map_err(|e| {
        TransportError::Connection(format!(
            "failed to connect to {}: {e}",
            config.endpoint_address
        ))
    })?;

    Ok(channel)
}
