use crate::{ConfigError, ConfigResult, LocalAgentConfig};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Load configuration from a YAML file.
pub fn load_from_file(path: &str) -> ConfigResult<LocalAgentConfig> {
    let contents = std::fs::read_to_string(path)?;
    let config: LocalAgentConfig = serde_yaml::from_str(&contents)?;
    validate(&config)?;
    info!(path = path, "configuration loaded from file");
    Ok(config)
}

/// Load config with fallback to defaults if file doesn't exist.
pub fn load_or_default(path: &str) -> LocalAgentConfig {
    match load_from_file(path) {
        Ok(config) => config,
        Err(e) => {
            warn!(path = path, error = %e, "failed to load config, using defaults");
            LocalAgentConfig::default()
        }
    }
}

/// Validate configuration values.
pub fn validate(config: &LocalAgentConfig) -> ConfigResult<()> {
    // Validate collector intervals
    for c in &config.collectors {
        if c.enabled && c.interval_seconds == 0 {
            return Err(ConfigError::Validation(format!(
                "collector '{}' has interval_seconds=0, must be >= 1",
                c.name
            )));
        }
    }

    // Validate buffer
    if config.buffer.max_size_bytes < 1024 * 1024 {
        return Err(ConfigError::Validation(
            "buffer.max_size_bytes must be >= 1MB".to_string(),
        ));
    }

    if config.buffer.flush_interval_ms == 0 {
        return Err(ConfigError::Validation(
            "buffer.flush_interval_ms must be > 0".to_string(),
        ));
    }

    if config.buffer.max_batch_size == 0 {
        return Err(ConfigError::Validation(
            "buffer.max_batch_size must be > 0".to_string(),
        ));
    }

    // Validate endpoint
    if config.endpoint.timeout_ms == 0 {
        return Err(ConfigError::Validation(
            "endpoint.timeout_ms must be > 0".to_string(),
        ));
    }

    // Validate logging
    let valid_levels = ["debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.logging.level.as_str()) {
        return Err(ConfigError::Validation(format!(
            "logging.level must be one of: {:?}",
            valid_levels
        )));
    }

    // Validate redaction patterns (check they compile)
    for pattern in &config.redaction_patterns {
        if regex::Regex::new(pattern).is_err() {
            return Err(ConfigError::Validation(format!(
                "invalid redaction regex pattern: {pattern}"
            )));
        }
    }

    Ok(())
}

/// Compute SHA256 hash of serialized config (for change detection).
pub fn config_hash(config: &LocalAgentConfig) -> String {
    let serialized = serde_yaml::to_string(config).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    format!("{:x}", hasher.finalize())
}
