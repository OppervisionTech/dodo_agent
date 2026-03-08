use crate::LocalAgentConfig;

/// Merge remote config overrides into local config.
/// Remote values take precedence for hot-reloadable fields.
pub fn merge(local: &LocalAgentConfig, remote: &LocalAgentConfig) -> LocalAgentConfig {
    let mut merged = local.clone();

    // Hot-reloadable fields: remote overrides local
    if !remote.collectors.is_empty() {
        merged.collectors = remote.collectors.clone();
    }

    if !remote.labels.is_empty() {
        merged.labels = remote.labels.clone();
    }

    if !remote.redaction_patterns.is_empty() {
        merged.redaction_patterns = remote.redaction_patterns.clone();
    }

    // Buffer config: merge individual fields
    if remote.buffer.max_size_bytes > 0 {
        merged.buffer.max_size_bytes = remote.buffer.max_size_bytes;
    }
    if remote.buffer.flush_interval_ms > 0 {
        merged.buffer.flush_interval_ms = remote.buffer.flush_interval_ms;
    }
    if remote.buffer.max_batch_size > 0 {
        merged.buffer.max_batch_size = remote.buffer.max_batch_size;
    }

    // Logging: remote overrides
    if !remote.logging.level.is_empty() {
        merged.logging.level = remote.logging.level.clone();
    }

    // NON hot-reloadable: endpoint and TLS are NOT merged.
    // They keep local values. Changes to these require restart.

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_collectors_override() {
        let local = LocalAgentConfig::default();
        let mut remote = LocalAgentConfig::default();
        remote.collectors = vec![crate::CollectorLocalConfig {
            name: "cpu".to_string(),
            enabled: true,
            interval_seconds: 10,
            parameters: Default::default(),
        }];

        let merged = merge(&local, &remote);
        assert_eq!(merged.collectors.len(), 1);
        assert_eq!(merged.collectors[0].interval_seconds, 10);
    }

    #[test]
    fn test_merge_preserves_endpoint() {
        let mut local = LocalAgentConfig::default();
        local.endpoint.address = "kong.local:443".to_string();

        let mut remote = LocalAgentConfig::default();
        remote.endpoint.address = "kong.prod:443".to_string();

        let merged = merge(&local, &remote);
        // Endpoint is NOT hot-reloadable, keeps local value
        assert_eq!(merged.endpoint.address, "kong.local:443");
    }
}
