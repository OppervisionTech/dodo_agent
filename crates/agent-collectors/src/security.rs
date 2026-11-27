//! Security collector — HU024.
//!
//! Monitors listening ports and critical file integrity at 15-second
//! intervals. Detects changes between consecutive snapshots and generates
//! SecurityEvent envelopes for: PORT_CHANGE (new/removed ports) and
//! FILE_INTEGRITY (hash changes on monitored files).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PortKey {
    port: u16,
    protocol: String,
    bind_address: String,
}

fn is_loopback(addr: &str) -> bool {
    let a = addr.trim_start_matches('[').trim_end_matches(']');
    a.starts_with("127.") || a == "::1" || a == "localhost"
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

/// Port alert policy: where seen ports persist, how long the learning
/// baseline lasts, and which ports/processes never alert.
#[derive(Debug, Clone, Default)]
pub struct PortPolicy {
    /// File that keeps seen ports across restarts. `None` keeps them in memory.
    pub state_path: Option<PathBuf>,
    /// After the first start, ports are only learned (no alerts) for this long.
    pub learning: Duration,
    /// Ports that never alert (e.g. 22, 80, 443).
    pub allow_ports: HashSet<u16>,
    /// (process name, port) pairs that never alert. A name alone is not
    /// trusted: any binary can be called "nginx".
    pub allow_process_ports: HashSet<(String, u16)>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct PortMemory {
    /// Unix seconds of the first start that created this file.
    learning_started_at: u64,
    ports: HashSet<PortKey>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl PortMemory {
    fn load(path: Option<&PathBuf>) -> Self {
        let loaded = path
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<PortMemory>(&b).ok());
        loaded.unwrap_or_else(|| PortMemory {
            learning_started_at: now_secs(),
            ports: HashSet::new(),
        })
    }

    fn save(&self, path: Option<&PathBuf>) {
        let Some(path) = path else { return };
        let result = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec(self).unwrap_or_default())?;
            std::fs::rename(&tmp, path)
        })();
        if let Err(e) = result {
            tracing::warn!(path = %path.display(), error = %e, "could not persist seen ports");
        }
    }

    fn learning(&self, window: Duration) -> bool {
        now_secs().saturating_sub(self.learning_started_at) < window.as_secs()
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
    /// Ports already reported since the agent started: a dev server or a
    /// short-lived listener that comes and goes is one event, not one per cycle.
    /// Persisted to `policy.state_path` so a restart does not re-alert.
    seen_ports: Mutex<PortMemory>,
    policy: PortPolicy,
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
            seen_ports: Mutex::new(PortMemory::load(None)),
            policy: PortPolicy::default(),
            monitored_files,
        }
    }

    /// Apply a port policy: loads persisted seen ports from `state_path`.
    pub fn with_port_policy(mut self, policy: PortPolicy) -> Self {
        self.seen_ports = Mutex::new(PortMemory::load(policy.state_path.as_ref()));
        self.policy = policy;
        self
    }

    /// True when a port change should alert: not loopback, not allowlisted,
    /// not seen before (recorded either way), and past the learning window.
    fn should_alert(&self, mem: &mut PortMemory, key: &PortKey, process: &str) -> bool {
        if is_loopback(&key.bind_address) {
            return false;
        }
        let first_time = mem.ports.insert(key.clone());
        first_time
            && !mem.learning(self.policy.learning)
            && !self.policy.allow_ports.contains(&key.port)
            && !self
                .policy
                .allow_process_ports
                .contains(&(process.to_string(), key.port))
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

                // New ports (in current but not in previous). Loopback binds are
                // not reachable from outside, and a port seen before is not new.
                let mut seen = self.seen_ports.lock().await;
                let before = seen.ports.len();
                for key in curr_keys.difference(&prev_keys) {
                    let process = current_port_map
                        .get(*key)
                        .map(|lp| lp.process_name.as_str())
                        .unwrap_or("");
                    if !self.should_alert(&mut seen, key, process) {
                        continue;
                    }
                    if let Some(lp) = current_port_map.get(key) {
                        tracing::info!(
                            port = lp.port,
                            protocol = %lp.protocol,
                            process = %lp.process_name,
                            "new listening port detected"
                        );
                        envelopes.push(security_event_envelope(
                            "PORT_CHANGE",
                            "low",
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
                    // A listener that already came and went once stays quiet.
                    let process = prev
                        .ports
                        .get(*key)
                        .map(|lp| lp.process_name.as_str())
                        .unwrap_or("");
                    if !self.should_alert(&mut seen, key, process) {
                        continue;
                    }
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

                if seen.ports.len() != before {
                    seen.save(self.policy.state_path.as_ref());
                }
                drop(seen);

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

            if prev_guard.is_none() {
                // Baseline: ports open at start are known, so their later
                // close/reopen stays quiet across restarts too.
                let mut seen = self.seen_ports.lock().await;
                let before = seen.ports.len();
                for key in current_port_map.keys() {
                    if !is_loopback(&key.bind_address) {
                        seen.ports.insert(key.clone());
                    }
                }
                if seen.ports.len() != before
                    || self.policy.state_path.as_ref().is_some_and(|p| !p.exists())
                {
                    seen.save(self.policy.state_path.as_ref());
                }
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

    #[test]
    fn loopback_binds_are_not_exposed() {
        for a in ["127.0.0.1", "127.0.0.53", "::1", "[::1]", "localhost"] {
            assert!(is_loopback(a), "{a}");
        }
        for a in ["0.0.0.0", "::", "192.168.0.10", "10.244.0.5"] {
            assert!(!is_loopback(a), "{a}");
        }
    }

    fn key(port: u16) -> PortKey {
        PortKey {
            port,
            protocol: "tcp".into(),
            bind_address: "0.0.0.0".into(),
        }
    }

    fn collector(policy: PortPolicy) -> SecurityCollector {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        SecurityCollector::new(platform, None).with_port_policy(policy)
    }

    #[tokio::test]
    async fn seen_port_survives_restart() {
        let dir = std::env::temp_dir().join(format!("seen-ports-{}", std::process::id()));
        let path = dir.join("seen_ports.json");
        let _ = std::fs::remove_dir_all(&dir);
        let policy = PortPolicy {
            state_path: Some(path.clone()),
            ..Default::default()
        };

        let first = collector(policy.clone());
        {
            let mut mem = first.seen_ports.lock().await;
            assert!(first.should_alert(&mut mem, &key(8080), "node"));
            mem.save(policy.state_path.as_ref());
        }

        // "Restart": a new collector loads the file and stays quiet.
        let second = collector(policy);
        let mut mem = second.seen_ports.lock().await;
        assert!(!second.should_alert(&mut mem, &key(8080), "node"));
        assert!(second.should_alert(&mut mem, &key(9090), "node"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn learning_window_and_allowlist_suppress() {
        let learning = collector(PortPolicy {
            learning: Duration::from_secs(24 * 3600),
            ..Default::default()
        });
        let mut mem = learning.seen_ports.lock().await;
        assert!(!learning.should_alert(&mut mem, &key(8080), "node"));
        assert!(mem.ports.contains(&key(8080)), "learned during baseline");
        drop(mem);

        let allow = collector(PortPolicy {
            allow_ports: [443].into_iter().collect(),
            allow_process_ports: [("nginx".to_string(), 8081)].into_iter().collect(),
            ..Default::default()
        });
        let mut mem = allow.seen_ports.lock().await;
        assert!(!allow.should_alert(&mut mem, &key(443), "x"));
        assert!(!allow.should_alert(&mut mem, &key(8081), "nginx"));
        // Same name on another port is not trusted.
        assert!(allow.should_alert(&mut mem, &key(8082), "nginx"));
        assert!(!allow.should_alert(
            &mut mem,
            &PortKey {
                bind_address: "127.0.0.1".into(),
                ..key(9000)
            },
            "x"
        ));
        assert!(allow.should_alert(&mut mem, &key(9001), "x"));
    }
}
