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
    use crate::helpers::{MetricPayload, MetricType};
    use agent_platform::common::MockPlatform;
    use agent_platform::{
        CgroupCpuInfo, CgroupMemoryInfo, CloudInfo, CpuTimes, DiskIo, DiskSpace, ListeningPort,
        LoadAverage, MemoryInfo, NetworkCounters, NetworkInterface, PackageInfo,
        PlatformCapabilities, PlatformError, PlatformInfo, PlatformResult, ProcessInfo,
        ServiceInfo, TcpConnections, UserInfo,
    };
    use prost::Message;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, SanType,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Only configured synthetic files are readable. Other platform methods
    /// delegate to the existing in-memory mock, never the host platform.
    struct CertificatePlatform {
        files: HashMap<String, String>,
        reads: Mutex<Vec<String>>,
        mock: MockPlatform,
    }

    impl CertificatePlatform {
        fn new(files: &[(&str, String)]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(path, value)| (path.to_string(), value.clone()))
                    .collect(),
                reads: Mutex::new(Vec::new()),
                mock: MockPlatform::new(),
            }
        }
    }

    macro_rules! delegate_mock_data {
        ($($name:ident => $value:ty),+ $(,)?) => {
            $(
                fn $name(&self) -> PlatformResult<$value> {
                    self.mock.$name()
                }
            )+
        };
    }

    impl Platform for CertificatePlatform {
        delegate_mock_data! {
            info => PlatformInfo,
            capabilities => PlatformCapabilities,
            cpu_times => Vec<CpuTimes>,
            load_average => LoadAverage,
            memory_info => MemoryInfo,
            disk_spaces => Vec<DiskSpace>,
            disk_io => Vec<DiskIo>,
            network_counters => Vec<NetworkCounters>,
            tcp_connections => TcpConnections,
            processes => Vec<ProcessInfo>,
            listening_ports => Vec<ListeningPort>,
            network_interfaces => Vec<NetworkInterface>,
            cloud_info => Option<CloudInfo>,
            packages => Vec<PackageInfo>,
            services => Vec<ServiceInfo>,
            users => Vec<UserInfo>,
            cgroup_cpu => Option<CgroupCpuInfo>,
            cgroup_memory => Option<CgroupMemoryInfo>,
        }

        fn file_hash(&self, path: &str) -> PlatformResult<String> {
            self.mock.file_hash(path)
        }

        fn read_file_string(&self, path: &str) -> PlatformResult<String> {
            self.reads.lock().unwrap().push(path.to_string());
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| PlatformError::PermissionDenied("synthetic unreadable file".into()))
        }
    }

    fn certificate(expired: bool, with_sans: bool, is_ca: bool) -> (String, Vec<u8>) {
        let mut params = CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2019, 1, 1);
        params.not_after = rcgen::date_time_ymd(if expired { 2020 } else { 2100 }, 1, 1);
        params.serial_number = Some(42u64.into());
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "synthetic.dodo.test");
        if with_sans {
            params.subject_alt_names = vec![
                SanType::DnsName("synthetic.dodo.test".into()),
                SanType::IpAddress("127.0.0.1".parse().unwrap()),
            ];
        }
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        let certificate = Certificate::from_params(params).unwrap();
        let pem = certificate.serialize_pem().unwrap();
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        (pem, parsed.contents)
    }

    fn assert_certificate_envelopes(
        envelopes: &[Envelope],
        path: &str,
        der: &[u8],
        expected_days: std::ops::RangeInclusive<i64>,
        with_sans: bool,
        is_ca: bool,
    ) {
        assert_eq!(envelopes.len(), 2, "one inventory and one metric per cert");
        assert_eq!(envelopes[0].signal_type, SignalType::Inventory);
        assert_eq!(envelopes[1].signal_type, SignalType::Metric);
        for envelope in envelopes {
            assert!(envelope.timestamp_unix_ns > 0);
            assert!(!envelope.buffered);
            assert_eq!(envelope.retry_count, 0);
        }

        let inventory: serde_json::Value = serde_json::from_slice(&envelopes[0].payload).unwrap();
        assert_eq!(inventory["inventory_type"], "certificate");
        let data = &inventory["data"];
        assert_eq!(data["path"], path);
        assert_eq!(data["subject"], "CN=synthetic.dodo.test");
        assert_eq!(data["issuer"], "CN=synthetic.dodo.test");
        assert_eq!(data["serial"], "2a");
        assert_eq!(data["is_ca"], is_ca);
        assert!(!data["not_before"].as_str().unwrap().is_empty());
        assert!(data["not_after"]
            .as_str()
            .unwrap()
            .contains(if expected_days.contains(&0) {
                "2020"
            } else {
                "2100"
            }));
        let days = data["days_until_expiry"].as_i64().unwrap();
        assert!(expected_days.contains(&days));

        let fingerprint = data["fingerprint_sha256"].as_str().unwrap();
        let fingerprint_bytes: Vec<u8> = fingerprint
            .split(':')
            .map(|pair| u8::from_str_radix(pair, 16).unwrap())
            .collect();
        assert_eq!(fingerprint_bytes, Sha256::digest(der).to_vec());
        let sans = data["sans"].as_array().unwrap();
        if with_sans {
            // Preserve the collector's existing x509-parser display format;
            // IP SANs are encoded as colon-separated bytes rather than dotted IPv4.
            assert_eq!(
                sans,
                serde_json::json!(["DNSName(synthetic.dodo.test)", "IPAddress(7f:00:00:01)"])
                    .as_array()
                    .unwrap()
            );
        } else {
            assert!(sans.is_empty());
        }

        let metric = MetricPayload::decode(envelopes[1].payload.as_slice()).unwrap();
        assert_eq!(metric.name, "cert.days_until_expiry");
        assert_eq!(metric.metric_type, MetricType::Gauge as i32);
        assert_eq!(metric.value, days as f64);
        assert_eq!(metric.labels["subject"], data["subject"]);
        assert_eq!(metric.labels["path"], path);
        assert_eq!(metric.labels["fingerprint"], fingerprint);
        assert!(metric.timestamp_unix_ns > 0);
        assert!(data.get("private_key").is_none());
        assert!(!String::from_utf8_lossy(&envelopes[0].payload).contains("PRIVATE KEY"));
    }

    #[test]
    fn pem_bundles_and_der_preserve_certificate_identity_and_skip_other_labels() {
        let (valid_pem, valid_der) = certificate(false, true, true);
        let (expired_pem, expired_der) = certificate(true, false, false);
        // This block contains only public certificate bytes with a different
        // label; no private key is ever serialized into a fixture.
        let other_label = valid_pem.replace("CERTIFICATE", "PUBLIC KEY");
        let bundle = format!("{other_label}{valid_pem}{expired_pem}");
        let parsed = CertsCollector::parse_pem_certs(bundle.as_bytes());
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], valid_der);
        assert_eq!(parsed[1], expired_der);
        let der = valid_der;
        assert_eq!(CertsCollector::parse_der_cert(&der), Some(der.clone()));
        assert!(CertsCollector::parse_der_cert(&der[..der.len() / 2]).is_none());
        assert!(CertsCollector::parse_der_cert(b"not a certificate").is_none());
        assert!(CertsCollector::parse_pem_certs(other_label.as_bytes()).is_empty());
    }

    #[tokio::test]
    async fn valid_pem_emits_identity_sans_expiry_and_matching_gauge() {
        let (pem, der) = certificate(false, true, true);
        let path = "/fixture/valid.pem";
        let platform = Arc::new(CertificatePlatform::new(&[(path, pem)]));
        let collector = CertsCollector::new(platform.clone(), Some(vec![path.into()]));
        let expires = rcgen::date_time_ymd(2100, 1, 1).unix_timestamp();
        let before = chrono_now_secs();
        let envelopes = collector.collect().await.unwrap();
        let after = chrono_now_secs();
        assert_certificate_envelopes(
            &envelopes,
            path,
            &der,
            (expires - after) / 86400..=(expires - before) / 86400,
            true,
            true,
        );
        assert_eq!(*platform.reads.lock().unwrap(), vec![path]);
    }

    #[tokio::test]
    async fn expired_certificate_without_sans_clamps_inventory_and_gauge_to_zero() {
        let (pem, der) = certificate(true, false, false);
        let path = "/fixture/expired.pem";
        let platform = Arc::new(CertificatePlatform::new(&[(path, pem)]));
        let collector = CertsCollector::new(platform, Some(vec![path.into()]));
        let envelopes = collector.collect().await.unwrap();
        assert_certificate_envelopes(&envelopes, path, &der, 0..=0, false, false);
    }

    #[tokio::test]
    async fn unreadable_empty_and_malformed_sources_do_not_drop_a_later_valid_certificate() {
        let (pem, der) = certificate(false, true, false);
        let platform = Arc::new(CertificatePlatform::new(&[
            ("/fixture/empty.pem", String::new()),
            ("/fixture/plaintext.pem", "not PEM or DER".into()),
            (
                "/fixture/bad-der.pem",
                "-----BEGIN CERTIFICATE-----\nbm90LWEteDUwOS1jZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n".into(),
            ),
            ("/fixture/valid.pem", pem),
        ]));
        let paths = [
            "/fixture/denied.pem",
            "/fixture/empty.pem",
            "/fixture/plaintext.pem",
            "/fixture/bad-der.pem",
            "/fixture/valid.pem",
        ];
        let collector = CertsCollector::new(
            platform.clone(),
            Some(paths.iter().map(|path| path.to_string()).collect()),
        );
        let expires = rcgen::date_time_ymd(2100, 1, 1).unix_timestamp();
        let before = chrono_now_secs();
        let envelopes = collector.collect().await.unwrap();
        let after = chrono_now_secs();
        assert_certificate_envelopes(
            &envelopes,
            "/fixture/valid.pem",
            &der,
            (expires - after) / 86400..=(expires - before) / 86400,
            true,
            false,
        );
        assert_eq!(*platform.reads.lock().unwrap(), paths);
    }

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
        assert_eq!(collector.cert_paths, DEFAULT_CERT_PATHS);
        assert_eq!(collector.name(), "certs");
        assert_eq!(collector.signal_type(), SignalType::Inventory);
        assert_eq!(collector.interval(), Duration::from_secs(3600));
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
