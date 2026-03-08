//! Security collector — HU024.
//!
//! Monitors listening ports and critical file integrity at 15-second
//! intervals. Detects changes between consecutive snapshots and generates
//! SecurityEvent envelopes for: PORT_CHANGE (new/removed ports) and
//! FILE_INTEGRITY (hash changes on monitored files).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::{ListeningPort, Platform};
use tokio::sync::Mutex;

use crate::helpers::security_event_envelope;

/// Default critical files to monitor for integrity changes.
const DEFAULT_MONITORED_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
];

/// Snapshot of a listening port for comparison.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PortKey {
    port: u16,
    protocol: String,
    bind_address: String,
}

impl From<&ListeningPort> for PortKey {
    fn from(lp: &ListeningPort) -> Self {
        Self {
            port: lp.port,
            protocol: lp.protocol.clone(),
            bind_address: lp.bind_address.clone(),
        }
    }
}

/// Previous state for change detection.
struct PreviousState {
    ports: HashMap<PortKey, ListeningPort>,
    file_hashes: HashMap<String, String>,
}

/// Monitors listening ports and critical file integrity for security-relevant changes.
pub struct SecurityCollector {
    platform: Arc<dyn Platform>,
    previous: Mutex<Option<PreviousState>>,
    monitored_files: Vec<String>,
}

impl SecurityCollector {
    /// Create a new security collector.
    ///
    /// - `monitored_files`: Additional files to monitor beyond the defaults.
    ///   Pass `None` to use only the built-in defaults.
    pub fn new(platform: Arc<dyn Platform>, extra_files: Option<Vec<String>>) -> Self {
        let mut monitored_files: Vec<String> = DEFAULT_MONITORED_FILES
            .iter()
            .map(|s| s.to_string())
            .collect();

        if let Some(extras) = extra_files {
            for f in extras {
                if !monitored_files.contains(&f) {
                    monitored_files.push(f);
                }
            }
        }

        Self {
            platform,
            previous: Mutex::new(None),
            monitored_files,
        }
    }
}

impl Collector for SecurityCollector {
    fn name(&self) -> &str {
        "security"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::SecurityEvent
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(15)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();

            // ------------------------------------------------------------------
            // Snapshot current listening ports
            // ------------------------------------------------------------------
            let current_ports = match self.platform.listening_ports() {
                Ok(ports) => ports,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read listening ports");
                    Vec::new()
                }
            };

            let current_port_map: HashMap<PortKey, ListeningPort> = current_ports
                .iter()
                .map(|lp| (PortKey::from(lp), lp.clone()))
                .collect();

            // ------------------------------------------------------------------
            // Snapshot current file hashes
            // ------------------------------------------------------------------
            let mut current_file_hashes: HashMap<String, String> = HashMap::new();
            for path in &self.monitored_files {
                match self.platform.file_hash(path) {
                    Ok(hash) => {
                        current_file_hashes.insert(path.clone(), hash);
                    }
                    Err(e) => {
                        tracing::trace!(
                            path = %path,
                            error = %e,
                            "could not hash monitored file (may not exist)"
                        );
                    }
                }
            }

            // ------------------------------------------------------------------
            // Compare with previous state
            // ------------------------------------------------------------------
            let mut prev_guard = self.previous.lock().await;

            if let Some(prev) = prev_guard.as_ref() {
                // --- Port changes ---
                let prev_keys: HashSet<&PortKey> = prev.ports.keys().collect();
                let curr_keys: HashSet<&PortKey> = current_port_map.keys().collect();

                // New ports (in current but not in previous)
                for key in curr_keys.difference(&prev_keys) {
                    if let Some(lp) = current_port_map.get(key) {
                        tracing::info!(
                            port = lp.port,
                            protocol = %lp.protocol,
                            process = %lp.process_name,
                            "new listening port detected"
                        );
                        envelopes.push(security_event_envelope(
                            "PORT_CHANGE",
                            "medium",
                            &format!(
                                "New listening port detected: {}:{}/{} ({})",
                                lp.bind_address, lp.port, lp.protocol, lp.process_name
                            ),
                            serde_json::json!({
                                "change": "added",
                                "port": lp.port,
                                "protocol": lp.protocol,
                                "bind_address": lp.bind_address,
                                "pid": lp.pid,
                                "process_name": lp.process_name,
                            }),
                        ));
                    }
                }

                // Removed ports (in previous but not in current)
                for key in prev_keys.difference(&curr_keys) {
                    if let Some(lp) = prev.ports.get(key) {
                        tracing::info!(
                            port = lp.port,
                            protocol = %lp.protocol,
                            "listening port removed"
                        );
                        envelopes.push(security_event_envelope(
                            "PORT_CHANGE",
                            "low",
                            &format!(
                                "Listening port removed: {}:{}/{} ({})",
                                lp.bind_address, lp.port, lp.protocol, lp.process_name
                            ),
                            serde_json::json!({
                                "change": "removed",
                                "port": lp.port,
                                "protocol": lp.protocol,
                                "bind_address": lp.bind_address,
                                "pid": lp.pid,
                                "process_name": lp.process_name,
                            }),
                        ));
                    }
                }

                // --- File integrity changes ---
                for (path, current_hash) in &current_file_hashes {
                    if let Some(prev_hash) = prev.file_hashes.get(path) {
                        if current_hash != prev_hash {
                            tracing::warn!(
                                path = %path,
                                "file integrity change detected"
                            );
                            envelopes.push(security_event_envelope(
                                "FILE_INTEGRITY",
                                "high",
                                &format!("File integrity change detected: {path}"),
                                serde_json::json!({
                                    "path": path,
                                    "previous_hash": prev_hash,
                                    "current_hash": current_hash,
                                }),
                            ));
                        }
                    }
                    // A file that did not exist before now has a hash — new file
                    else if !prev.file_hashes.contains_key(path) {
                        // Only report if previous state existed (i.e., this is not
                        // the first scan after agent boot when everything is "new").
                        // We handle this by noting the file appeared after initial scan.
                        tracing::info!(
                            path = %path,
                            "monitored file appeared"
                        );
                        envelopes.push(security_event_envelope(
                            "FILE_INTEGRITY",
                            "medium",
                            &format!("Monitored file appeared: {path}"),
                            serde_json::json!({
                                "path": path,
                                "current_hash": current_hash,
                                "change": "created",
                            }),
                        ));
                    }
                }

                // File removed (was in previous, not in current)
                for (path, prev_hash) in &prev.file_hashes {
                    if !current_file_hashes.contains_key(path) {
                        tracing::warn!(
                            path = %path,
                            "monitored file removed"
                        );
                        envelopes.push(security_event_envelope(
                            "FILE_INTEGRITY",
                            "high",
                            &format!("Monitored file removed: {path}"),
                            serde_json::json!({
                                "path": path,
                                "previous_hash": prev_hash,
                                "change": "removed",
                            }),
                        ));
                    }
                }
            } else {
                tracing::debug!(
                    ports = current_port_map.len(),
                    files = current_file_hashes.len(),
                    "security collector: initial snapshot captured"
                );
            }

            // Store current state as previous
            *prev_guard = Some(PreviousState {
                ports: current_port_map,
                file_hashes: current_file_hashes,
            });

            Ok(envelopes)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agent_platform::common::MockPlatform;

    #[tokio::test]
    async fn first_collection_is_baseline() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = SecurityCollector::new(platform, None);

        // First collection should establish baseline, no events
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[tokio::test]
    async fn stable_state_produces_no_events() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = SecurityCollector::new(platform, None);

        // Baseline
        let _ = collector.collect().await;
        // Second collection with same mock data — no changes
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[tokio::test]
    async fn default_monitored_files_are_set() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = SecurityCollector::new(platform, None);
        assert_eq!(
            collector.monitored_files.len(),
            DEFAULT_MONITORED_FILES.len()
        );
    }

    #[tokio::test]
    async fn extra_files_are_added() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = SecurityCollector::new(platform, Some(vec!["/etc/hosts".to_string()]));
        assert!(collector
            .monitored_files
            .contains(&"/etc/hosts".to_string()));
        assert_eq!(
            collector.monitored_files.len(),
            DEFAULT_MONITORED_FILES.len() + 1
        );
    }
}
