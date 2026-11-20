//! Log collector — HU026.
//!
//! Tails configured log file paths and produces Log envelopes. Auto-detects
//! log format (JSON, logfmt, syslog, plaintext). Extracts trace_id and
//! span_id when present. Enforces rate limits and truncation.
//!
//! Interval: 1 second (streaming approximation via polling).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;
use tokio::sync::Mutex;

use crate::helpers::log_envelope;

/// Split an optional `service=` prefix off a configured path entry.
///
/// `postgresql=/var/log/pg/*.log` tags every line from matching files with
/// source `postgresql`, which the log worker stores as the service id. A
/// plain path keeps the file path as source.
fn split_service(entry: &str) -> (Option<&str>, &str) {
    match entry.split_once('=') {
        Some((svc, path)) if !svc.is_empty() && !svc.contains('/') => {
            (Some(svc.trim()), path.trim())
        }
        _ => (None, entry),
    }
}

/// Kubernetes metadata parsed from a kubelet pod log path.
///
/// Kubelet writes container logs to
/// `/var/log/pods/<namespace>_<pod>_<uid>/<container>/<restart>.log`; the
/// agent may see that tree under a host prefix such as `/host`.
#[derive(Debug, PartialEq, Eq)]
struct PodLogMeta<'a> {
    namespace: &'a str,
    pod: &'a str,
    container: &'a str,
}

fn pod_log_meta(path: &str) -> Option<PodLogMeta<'_>> {
    let (_, rest) = path.split_once("/var/log/pods/")?;
    let mut parts = rest.split('/');
    let dir = parts.next()?;
    let container = parts.next()?;
    let file = parts.next()?;
    if container.is_empty() || !file.ends_with(".log") || parts.next().is_some() {
        return None;
    }
    let (namespace, rest) = dir.split_once('_')?;
    let (pod, uid) = rest.rsplit_once('_')?;
    if namespace.is_empty() || pod.is_empty() || uid.is_empty() {
        return None;
    }
    Some(PodLogMeta {
        namespace,
        pod,
        container,
    })
}

/// Expand a list of paths (which may include glob patterns) to concrete
/// `(file path, source)` pairs.
/// Glob patterns use the standard `*`, `?`, `[abc]` syntax.
/// Non-glob paths are included as-is (missing files are silently skipped at read time).
fn expand_paths(entries: &[String]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for entry in entries {
        let (service, path) = split_service(entry);
        // Without an explicit `service=` prefix, kubelet pod logs use the
        // container name as source instead of the file path.
        let source = |file: &str| {
            service
                .map(str::to_string)
                .or_else(|| pod_log_meta(file).map(|m| m.container.to_string()))
                .unwrap_or_else(|| file.to_string())
        };
        if path.contains('*') || path.contains('?') || path.contains('[') {
            match glob::glob(path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if let Some(s) = entry.to_str() {
                            result.push((s.to_string(), source(s)));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(pattern = %path, error = %e, "invalid glob pattern, skipping");
                }
            }
        } else {
            result.push((path.to_string(), source(path)));
        }
    }
    result
}

/// Maximum line length before truncation (16 KB).
const MAX_LINE_LENGTH: usize = 16 * 1024;

/// Default maximum lines per second (rate limit).
const DEFAULT_MAX_LINES_PER_SEC: usize = 10_000;

/// Tracked state per log file.
struct FileState {
    /// Current byte offset in the file.
    offset: u64,
    /// File size at last read — used to detect rotation (size shrinks).
    last_known_size: u64,
}

/// Log format auto-detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Json,
    Logfmt,
    Syslog,
    Plaintext,
}

/// Tails log files and produces Log envelopes with format auto-detection.
pub struct LogsCollector {
    platform: Arc<dyn Platform>,
    /// Raw path patterns (may include globs like `/host/var/log/containers/*.log`).
    log_path_patterns: Vec<String>,
    /// Per-file offset state for tailing.
    file_states: Mutex<HashMap<String, FileState>>,
    /// Maximum lines per collection interval.
    max_lines_per_sec: usize,
}

impl LogsCollector {
    /// Create a new log collector.
    ///
    /// - `log_paths`: Paths or glob patterns to tail.
    /// - `max_lines_per_sec`: Rate limit. Defaults to 10,000 if `None`.
    pub fn new(
        platform: Arc<dyn Platform>,
        log_paths: Vec<String>,
        max_lines_per_sec: Option<usize>,
    ) -> Self {
        Self {
            platform,
            log_path_patterns: log_paths,
            file_states: Mutex::new(HashMap::new()),
            max_lines_per_sec: max_lines_per_sec.unwrap_or(DEFAULT_MAX_LINES_PER_SEC),
        }
    }

    /// Detect the log format of a line.
    fn detect_format(line: &str) -> LogFormat {
        let trimmed = line.trim();

        // JSON: starts with {
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return LogFormat::Json;
        }

        // Syslog: starts with month abbreviation (e.g., "Mar  8 ...")
        // or RFC5424 format starting with "<" priority
        if trimmed.starts_with('<') || (trimmed.len() > 15 && Self::looks_like_syslog(trimmed)) {
            return LogFormat::Syslog;
        }

        // Logfmt: contains multiple key=value pairs
        if Self::looks_like_logfmt(trimmed) {
            return LogFormat::Logfmt;
        }

        LogFormat::Plaintext
    }

    /// Heuristic: does this line look like syslog (BSD format)?
    fn looks_like_syslog(line: &str) -> bool {
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        months.iter().any(|m| line.starts_with(m))
    }

    /// Heuristic: does this line look like logfmt (key=value pairs)?
    fn looks_like_logfmt(line: &str) -> bool {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return false;
        }
        let kv_count = parts.iter().filter(|p| p.contains('=')).count();
        kv_count >= 2
    }

    /// Extract trace_id and span_id from a JSON log line.
    fn extract_trace_context(line: &str) -> (Option<String>, Option<String>) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let trace_id = v
                .get("trace_id")
                .or_else(|| v.get("traceId"))
                .or_else(|| v.get("traceID"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let span_id = v
                .get("span_id")
                .or_else(|| v.get("spanId"))
                .or_else(|| v.get("spanID"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            (trace_id, span_id)
        } else {
            (None, None)
        }
    }

    /// Extract severity from a log line (best effort).
    fn extract_severity(line: &str, format: LogFormat) -> &'static str {
        match format {
            LogFormat::Json => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(level) = v
                        .get("level")
                        .or_else(|| v.get("severity"))
                        .or_else(|| v.get("log.level"))
                        .and_then(|v| v.as_str())
                    {
                        return Self::normalize_severity(level);
                    }
                }
                "INFO"
            }
            _ => {
                let upper = line.to_uppercase();
                if upper.contains("FATAL") || upper.contains("PANIC") || upper.contains("CRIT") {
                    "FATAL"
                } else if upper.contains("ERROR") || upper.contains("ERR") {
                    "ERROR"
                } else if upper.contains("WARN") {
                    "WARN"
                } else if upper.contains("DEBUG") {
                    "DEBUG"
                } else if upper.contains("TRACE") {
                    "TRACE"
                } else {
                    "INFO"
                }
            }
        }
    }

    /// Normalize severity string to canonical form.
    fn normalize_severity(s: &str) -> &'static str {
        match s.to_uppercase().as_str() {
            "TRACE" => "TRACE",
            "DEBUG" => "DEBUG",
            "INFO" | "INFORMATION" => "INFO",
            "WARN" | "WARNING" => "WARN",
            "ERROR" | "ERR" => "ERROR",
            "FATAL" | "CRITICAL" | "PANIC" | "CRIT" => "FATAL",
            _ => "INFO",
        }
    }

    /// Truncate a line if it exceeds MAX_LINE_LENGTH.
    fn truncate_line(line: &str) -> &str {
        if line.len() > MAX_LINE_LENGTH {
            // Find a safe UTF-8 boundary near MAX_LINE_LENGTH
            let mut end = MAX_LINE_LENGTH;
            while end > 0 && !line.is_char_boundary(end) {
                end -= 1;
            }
            &line[..end]
        } else {
            line
        }
    }
}

impl Collector for LogsCollector {
    fn name(&self) -> &str {
        "logs"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Log
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();
            let mut total_lines: usize = 0;
            let mut states = self.file_states.lock().await;

            // Re-expand glob patterns each cycle to pick up new log files
            let resolved_paths = expand_paths(&self.log_path_patterns);

            for (path, source) in &resolved_paths {
                let pod_meta = pod_log_meta(path);
                // Read the full file content via platform abstraction.
                // In production this would use seek + read from offset.
                // For MVP, we read the full file and track offset.
                let content = match self.platform.read_file_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::trace!(path = %path, error = %e, "could not read log file");
                        continue;
                    }
                };

                let current_size = content.len() as u64;

                // Get or create file state
                let state = states.entry(path.clone()).or_insert(FileState {
                    offset: 0,
                    last_known_size: 0,
                });

                // Detect log rotation: if file shrank, reset offset
                if current_size < state.last_known_size {
                    tracing::info!(path = %path, "log rotation detected, resetting offset");
                    state.offset = 0;
                }

                state.last_known_size = current_size;

                // Only process new content from offset
                let offset = state.offset as usize;
                if offset >= content.len() {
                    continue;
                }

                let new_content = &content[offset..];
                let lines: Vec<&str> = new_content.lines().collect();

                for line in lines {
                    if total_lines >= self.max_lines_per_sec {
                        tracing::warn!(
                            limit = self.max_lines_per_sec,
                            "log rate limit reached, dropping remaining lines"
                        );
                        break;
                    }

                    let line = Self::truncate_line(line);
                    if line.is_empty() {
                        continue;
                    }

                    let format = Self::detect_format(line);
                    let severity = Self::extract_severity(line, format);
                    let (trace_id, span_id) = Self::extract_trace_context(line);

                    let format_label = match format {
                        LogFormat::Json => "json",
                        LogFormat::Logfmt => "logfmt",
                        LogFormat::Syslog => "syslog",
                        LogFormat::Plaintext => "plaintext",
                    };

                    let mut attrs = vec![("format", format_label)];
                    if let Some(m) = &pod_meta {
                        attrs.push(("namespace", m.namespace));
                        attrs.push(("pod", m.pod));
                        attrs.push(("container", m.container));
                    }
                    envelopes.push(log_envelope(
                        line,
                        severity,
                        source,
                        &attrs,
                        trace_id.as_deref(),
                        span_id.as_deref(),
                    ));

                    total_lines += 1;
                }

                // Update offset to end of file
                state.offset = current_size;
            }

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

    #[test]
    fn detects_json_format() {
        assert_eq!(
            LogsCollector::detect_format(r#"{"level":"info","msg":"hello"}"#),
            LogFormat::Json
        );
    }

    #[test]
    fn detects_syslog_format() {
        assert_eq!(
            LogsCollector::detect_format("Mar  8 12:00:00 host sshd[1234]: Accepted publickey"),
            LogFormat::Syslog
        );
    }

    #[test]
    fn detects_logfmt_format() {
        assert_eq!(
            LogsCollector::detect_format("ts=2026-03-08 level=info msg=hello"),
            LogFormat::Logfmt
        );
    }

    #[test]
    fn detects_plaintext_format() {
        assert_eq!(
            LogsCollector::detect_format("just a plain text line"),
            LogFormat::Plaintext
        );
    }

    #[test]
    fn extracts_trace_context_from_json() {
        let line = r#"{"level":"info","trace_id":"abc123","span_id":"def456","msg":"hello"}"#;
        let (trace, span) = LogsCollector::extract_trace_context(line);
        assert_eq!(trace.as_deref(), Some("abc123"));
        assert_eq!(span.as_deref(), Some("def456"));
    }

    #[test]
    fn severity_from_json() {
        assert_eq!(
            LogsCollector::extract_severity(r#"{"level":"error","msg":"fail"}"#, LogFormat::Json),
            "ERROR"
        );
    }

    #[test]
    fn severity_from_plaintext() {
        assert_eq!(
            LogsCollector::extract_severity("ERROR: something failed", LogFormat::Plaintext),
            "ERROR"
        );
    }

    #[test]
    fn truncates_long_lines() {
        let long_line = "x".repeat(MAX_LINE_LENGTH + 100);
        let truncated = LogsCollector::truncate_line(&long_line);
        assert!(truncated.len() <= MAX_LINE_LENGTH);
    }

    #[tokio::test]
    async fn empty_paths_returns_empty() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = LogsCollector::new(platform, vec![], None);

        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn pod_log_meta_parses_kubelet_path() {
        assert_eq!(
            pod_log_meta("/host/var/log/pods/staging_api-7d9f-x2k_0a1b-c2d3/api/0.log"),
            Some(PodLogMeta {
                namespace: "staging",
                pod: "api-7d9f-x2k",
                container: "api",
            })
        );
        assert_eq!(pod_log_meta("/var/log/syslog"), None);
        assert_eq!(pod_log_meta("/var/log/pods/bad/api/0.log"), None);
        assert_eq!(pod_log_meta("/var/log/pods/ns_pod_uid/api/0.log.gz"), None);
    }

    #[test]
    fn expand_paths_uses_container_for_pod_logs() {
        let dir = std::env::temp_dir().join(format!("aegis-podlogs-{}", std::process::id()));
        let file = dir.join("var/log/pods/kong_gw-1_abc/proxy/0.log");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "x\n").unwrap();
        let pattern = format!("{}/var/log/pods/*/*/*.log", dir.display());
        let got = expand_paths(&[pattern.clone(), format!("svc={pattern}")]);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(got[0].1, "proxy");
        assert_eq!(got[1].1, "svc");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pod_log_lines_carry_k8s_fields() {
        use prost::Message;
        let dir = std::env::temp_dir().join(format!("aegis-podrun-{}", std::process::id()));
        let file = dir.join("var/log/pods/staging_api-1_uid9/api/0.log");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "ERROR boom\n").unwrap();
        let platform = Arc::new(agent_platform::linux::LinuxPlatform::new()) as Arc<dyn Platform>;
        let collector = LogsCollector::new(platform, vec![file.display().to_string()], None);
        let envelopes = collector.collect().await.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(envelopes.len(), 1);
        let log = crate::helpers::LogPayload::decode(envelopes[0].payload.as_slice()).unwrap();
        assert_eq!(
            log.fields.get("namespace").map(String::as_str),
            Some("staging")
        );
        assert_eq!(log.fields.get("pod").map(String::as_str), Some("api-1"));
        assert_eq!(log.fields.get("container").map(String::as_str), Some("api"));
    }

    #[test]
    fn service_prefix_sets_source() {
        assert_eq!(
            split_service("postgresql=/var/log/pg/*.log"),
            (Some("postgresql"), "/var/log/pg/*.log")
        );
        assert_eq!(
            split_service("/var/log/app.log"),
            (None, "/var/log/app.log")
        );
        assert_eq!(
            split_service("/var/log/a=b.log"),
            (None, "/var/log/a=b.log")
        );
        assert_eq!(
            expand_paths(&["redis=/nonexistent/r.log".into()]),
            vec![("/nonexistent/r.log".to_string(), "redis".to_string())]
        );
    }
}
