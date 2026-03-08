//! Certificate collector — HU025.
//!
//! Scans configured paths for PEM and DER certificate files at hourly
//! intervals. Parses each certificate using x509-parser and produces
//! inventory envelopes with subject, issuer, expiry, fingerprint, and SANs.
//! Also emits a `cert.days_until_expiry` metric per certificate for
//! alerting on expiring certs.

use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::helpers::{inventory_envelope, metric_envelope};

/// Default paths to scan for certificates.
const DEFAULT_CERT_PATHS: &[&str] = &[
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/letsencrypt/live",
];

/// Scans configured paths for TLS certificates and produces inventory
/// and expiry metrics.
pub struct CertsCollector {
    platform: Arc<dyn Platform>,
    cert_paths: Vec<String>,
}

impl CertsCollector {
    /// Create a new certificate collector.
    ///
    /// - `cert_paths`: Paths to scan for certificate files. Pass `None`
    ///   to use built-in defaults.
    pub fn new(platform: Arc<dyn Platform>, cert_paths: Option<Vec<String>>) -> Self {
        let paths = cert_paths
            .unwrap_or_else(|| DEFAULT_CERT_PATHS.iter().map(|s| s.to_string()).collect());
        Self {
            platform,
            cert_paths: paths,
        }
    }

    /// Try to parse a PEM file content and return all certificates found.
    fn parse_pem_certs(data: &[u8]) -> Vec<Vec<u8>> {
        let mut certs = Vec::new();
        for pem in Pem::iter_from_buffer(data).flatten() {
            if pem.label == "CERTIFICATE" {
                certs.push(pem.contents.clone());
            }
        }
        certs
    }

    /// Try to parse raw bytes as a DER certificate.
    fn parse_der_cert(data: &[u8]) -> Option<Vec<u8>> {
        // Quick validation: try to parse it
        if X509Certificate::from_der(data).is_ok() {
            Some(data.to_vec())
        } else {
            None
        }
    }

    /// Compute SHA-256 fingerprint of DER-encoded certificate bytes.
    fn fingerprint(der_bytes: &[u8]) -> String {
        let digest = Sha256::digest(der_bytes);
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Collector for CertsCollector {
    fn name(&self) -> &str {
        "certs"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Inventory
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(3600)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();
            let now = chrono_now_secs();

            for path in &self.cert_paths {
                // Read the file content via platform abstraction.
                // In a real implementation we would recursively list directory
                // entries. For MVP, we attempt to read each path as a file.
                let content = match self.platform.read_file_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::trace!(path = %path, error = %e, "skipping cert path");
                        continue;
                    }
                };

                if content.is_empty() {
                    continue;
                }

                let raw = content.as_bytes();

                // Try PEM first, then DER
                let mut der_certs = Self::parse_pem_certs(raw);
                if der_certs.is_empty() {
                    if let Some(der) = Self::parse_der_cert(raw) {
                        der_certs.push(der);
                    }
                }

                for der_bytes in &der_certs {
                    match X509Certificate::from_der(der_bytes) {
                        Ok((_rem, cert)) => {
                            let subject = cert.subject().to_string();
                            let issuer = cert.issuer().to_string();
                            let not_after_ts = cert.validity().not_after.timestamp();
                            let days_until_expiry = (not_after_ts - now).max(0) / 86400;
                            let fingerprint = Self::fingerprint(der_bytes);

                            // Extract SANs
                            let sans: Vec<String> = cert
                                .subject_alternative_name()
                                .ok()
                                .flatten()
                                .map(|ext| {
                                    ext.value
                                        .general_names
                                        .iter()
                                        .map(|gn| format!("{gn}"))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let not_before = cert
                                .validity()
                                .not_before
                                .to_rfc2822()
                                .ok()
                                .unwrap_or_default();
                            let not_after = cert
                                .validity()
                                .not_after
                                .to_rfc2822()
                                .ok()
                                .unwrap_or_default();

                            // Inventory envelope
                            envelopes.push(inventory_envelope(
                                "certificate",
                                serde_json::json!({
                                    "path": path,
                                    "subject": subject,
                                    "issuer": issuer,
                                    "not_before": not_before,
                                    "not_after": not_after,
                                    "days_until_expiry": days_until_expiry,
                                    "fingerprint_sha256": fingerprint,
                                    "sans": sans,
                                    "serial": cert.raw_serial_as_string(),
                                    "is_ca": cert.is_ca(),
                                }),
                            ));

                            // Expiry metric
                            envelopes.push(metric_envelope(
                                "cert.days_until_expiry",
                                days_until_expiry as f64,
                                &[
                                    ("subject", &subject),
                                    ("path", path),
                                    ("fingerprint", &fingerprint),
                                ],
                                "gauge",
                            ));

                            if days_until_expiry <= 30 {
                                tracing::warn!(
                                    subject = %subject,
                                    days = days_until_expiry,
                                    path = %path,
                                    "certificate expiring soon"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                path = %path,
                                error = %e,
                                "failed to parse certificate"
                            );
                        }
                    }
                }
            }

            Ok(envelopes)
        })
    }
}

/// Get current Unix timestamp in seconds. This avoids pulling in chrono
/// as a dependency — we use std::time directly.
fn chrono_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agent_platform::common::MockPlatform;

    #[tokio::test]
    async fn empty_paths_returns_empty() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = CertsCollector::new(platform, Some(vec![]));

        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[tokio::test]
    async fn default_paths_are_set() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = CertsCollector::new(platform, None);
        assert_eq!(collector.cert_paths.len(), DEFAULT_CERT_PATHS.len());
    }

    #[test]
    fn fingerprint_is_formatted() {
        let data = b"test certificate data";
        let fp = CertsCollector::fingerprint(data);
        // Should be colon-separated hex uppercase
        assert!(fp.contains(':'));
        assert_eq!(fp.len(), 32 * 3 - 1); // 32 hex pairs + 31 colons
    }

    #[test]
    fn chrono_now_is_positive() {
        assert!(chrono_now_secs() > 0);
    }
}
