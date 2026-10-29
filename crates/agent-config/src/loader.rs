use crate::{ConfigError, ConfigResult, LocalAgentConfig};
use sha2::{Digest, Sha256};
use tracing::info;

/// Load configuration from a YAML file.
pub fn load_from_file(path: &str) -> ConfigResult<LocalAgentConfig> {
    let contents = std::fs::read_to_string(path)?;
    let config: LocalAgentConfig = serde_yaml::from_str(&contents)?;
    validate(&config)?;
    info!(path = path, "configuration loaded from file");
    Ok(config)
}

/// Missing files may use defaults plus explicit environment overrides. A present
/// malformed file is always an error; it must never start in another environment.
pub fn load_or_default(path: &str) -> ConfigResult<LocalAgentConfig> {
    let mut config = match load_from_file(path) {
        Ok(config) => config,
        Err(ConfigError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            LocalAgentConfig::default()
        }
        Err(e) => return Err(e),
    };
    if let Ok(address) = std::env::var("DODO_ENDPOINT") {
        config.endpoint.address = address;
    }
    if let Ok(endpoint) = std::env::var("DODO_ENROLLMENT_ENDPOINT") {
        config.enrollment_endpoint = endpoint;
    }
    validate(&config)?;
    Ok(config)
}

/// Validate configuration values.
pub fn validate(config: &LocalAgentConfig) -> ConfigResult<()> {
    let address = &config.endpoint.address;
    let authority = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))
        .unwrap_or(address);
    if address.contains("://") {
        return Err(ConfigError::Validation(
            "endpoint.address is host:port; configure TLS with tls.enabled".into(),
        ));
    }
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        return Err(ConfigError::Validation(
            "endpoint.address must be host:port".into(),
        ));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| ConfigError::Validation("endpoint.address must include a port".into()))?;
    if host.is_empty() || port.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
        return Err(ConfigError::Validation(
            "endpoint.address must be host:port with a valid port".into(),
        ));
    }
    let loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if (!config.tls.enabled || address.starts_with("http://")) && !loopback {
        return Err(ConfigError::Validation(
            "plaintext upstream is only permitted on loopback".into(),
        ));
    }
    if config.tls.enabled && !config.tls.verify_server {
        return Err(ConfigError::Validation(
            "TLS server verification cannot be disabled".into(),
        ));
    }
    if !config.enrollment_endpoint.is_empty()
        && (!config.enrollment_endpoint.starts_with("https://")
            || config.enrollment_endpoint.contains('@')
            || config.enrollment_endpoint.chars().any(char::is_whitespace))
    {
        return Err(ConfigError::Validation(
            "enrollment_endpoint must be an explicit HTTPS URL".into(),
        ));
    }
    if !config.enrollment_endpoint.is_empty() {
        let directory = std::path::Path::new(&config.tls.client_cert_path).parent();
        for (path, name) in [
            (&config.tls.ca_cert_path, "ca.pem"),
            (&config.tls.client_cert_path, "agent.pem"),
            (&config.tls.client_key_path, "agent-key.pem"),
        ] {
            let path = std::path::Path::new(path);
            if !path.is_absolute()
                || path.parent() != directory
                || path.file_name().and_then(|name| name.to_str()) != Some(name)
            {
                return Err(ConfigError::Validation("auto-enrollment certificate paths must share one absolute directory and canonical filenames ca.pem, agent.pem, agent-key.pem".into()));
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_addresses_state_layout_and_invalid_runtime_limits_fail_validation() {
        type InvalidCase = (&'static str, fn(&mut LocalAgentConfig));
        let cases: [InvalidCase; 14] = [
            ("empty address", |c| c.endpoint.address = String::new()),
            ("URL instead of authority", |c| {
                c.endpoint.address = "https://localhost:443".into()
            }),
            ("path in authority", |c| {
                c.endpoint.address = "localhost:443/path".into()
            }),
            ("invalid port", |c| {
                c.endpoint.address = "localhost:0".into()
            }),
            ("empty host", |c| c.endpoint.address = ":443".into()),
            ("credentials in enrollment URL", |c| {
                c.enrollment_endpoint = "https://user@example.test/v1/enroll".into()
            }),
            ("noncanonical certificate layout", |c| {
                c.enrollment_endpoint = "https://example.test/v1/enroll".into();
                c.tls.client_key_path = "relative/key.pem".into();
            }),
            ("zero enabled collector interval", |c| {
                c.collectors[0].interval_seconds = 0
            }),
            ("undersized buffer", |c| c.buffer.max_size_bytes = 1),
            ("zero flush interval", |c| c.buffer.flush_interval_ms = 0),
            ("zero batch size", |c| c.buffer.max_batch_size = 0),
            ("zero upstream timeout", |c| c.endpoint.timeout_ms = 0),
            ("invalid log level", |c| c.logging.level = "invalid".into()),
            ("invalid redaction regex", |c| {
                c.redaction_patterns = vec!["[".into()]
            }),
        ];
        for (label, mutate) in cases {
            let mut config = LocalAgentConfig::default();
            mutate(&mut config);
            assert!(validate(&config).is_err(), "{label}");
        }
        let mut config = LocalAgentConfig::default();
        config.endpoint.address = "[::1]:65535".into();
        config.tls.enabled = false;
        config.buffer.max_size_bytes = 1024 * 1024;
        config.buffer.flush_interval_ms = 1;
        config.buffer.max_batch_size = 1;
        validate(&config).unwrap();
        let before = config_hash(&config);
        assert_eq!(before.len(), 64);
        assert_eq!(config_hash(&config), before);
        config.logging.level = "debug".into();
        assert_ne!(config_hash(&config), before);
    }
    #[test]
    fn malformed_existing_config_never_falls_back() {
        let path = std::env::temp_dir().join(format!("dodo-bad-{}.yaml", std::process::id()));
        std::fs::write(&path, "collectors: {docker: true}").expect("fixture");
        assert!(load_or_default(path.to_str().expect("path")).is_err());
        std::fs::remove_file(path).expect("cleanup");
    }
    #[test]
    fn remote_plaintext_and_unverified_tls_are_rejected() {
        let mut config = LocalAgentConfig::default();
        config.endpoint.address = "example.invalid:443".into();
        config.tls.enabled = false;
        assert!(validate(&config).is_err());
        config.tls.enabled = true;
        config.tls.verify_server = false;
        assert!(validate(&config).is_err());
        config.tls.verify_server = true;
        config.enrollment_endpoint = "http://example.invalid/v1/enroll".into();
        assert!(validate(&config).is_err());
    }
}
