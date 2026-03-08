use crate::{TransportConfig, TransportError, TransportResult};

/// Load PEM file contents as bytes.
fn load_pem_bytes(path: &str, label: &str) -> TransportResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| TransportError::Tls(format!("cannot read {label} from {path}: {e}")))
}

/// Build a tonic Channel with mTLS for connecting to Kong.
///
/// Uses tonic's native `ClientTlsConfig` which accepts PEM bytes directly,
/// avoiding the need to construct a `rustls::ClientConfig` manually.
pub async fn build_grpc_channel(
    config: &TransportConfig,
) -> TransportResult<tonic::transport::Channel> {
    let mut tls = tonic::transport::ClientTlsConfig::new();

    // CA certificate for server verification
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

    let endpoint =
        tonic::transport::Channel::from_shared(format!("https://{}", config.endpoint_address))
            .map_err(|e| TransportError::Connection(format!("invalid endpoint: {e}")))?
            .tls_config(tls)
            .map_err(|e| TransportError::Tls(format!("TLS config error: {e}")))?
            .timeout(std::time::Duration::from_millis(config.timeout_ms as u64))
            .keep_alive_timeout(std::time::Duration::from_secs(30))
            .http2_keep_alive_interval(std::time::Duration::from_secs(30));

    let channel = endpoint.connect().await.map_err(|e| {
        TransportError::Connection(format!(
            "failed to connect to {}: {e}",
            config.endpoint_address
        ))
    })?;

    Ok(channel)
}
