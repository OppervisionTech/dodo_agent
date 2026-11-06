pub mod loader;
pub mod merger;
pub mod watcher;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("config pull error: {0}")]
    Pull(String),
}

pub type ConfigResult<T> = Result<T, ConfigError>;

/// Local agent configuration (YAML).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalAgentConfig {
    #[serde(default = "default_endpoint")]
    pub endpoint: EndpointLocalConfig,
    #[serde(default)]
    pub tls: TlsLocalConfig,
    #[serde(default)]
    pub buffer: BufferLocalConfig,
    #[serde(default)]
    pub logging: LoggingLocalConfig,
    #[serde(default)]
    pub collectors: Vec<CollectorLocalConfig>,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub redaction_patterns: Vec<String>,
    #[serde(default = "default_config_pull_interval")]
    pub config_pull_interval_seconds: u32,
    #[serde(default = "default_agent_id_path")]
    pub agent_id_path: String,
    /// HTTPS endpoint for agent certificate auto-enrollment on first boot.
    /// Set to empty string to disable enrollment (manual cert management).
    #[serde(default = "default_enrollment_endpoint")]
    pub enrollment_endpoint: String,
}

/// Last-resort fallback only — not environment-aware. `get.sh` and the
/// `aegis-agent` Helm chart always write an explicit `enrollment_endpoint`
/// key into the generated config (deriving it per environment, since gRPC
/// ingest and HTTPS enrollment are not guaranteed to share a hostname
/// outside of production — see `derive_enrollment_endpoint()` in get.sh).
/// This default only matters for hand-written configs that omit the key
/// entirely, and always points at production.
fn default_enrollment_endpoint() -> String {
    "https://api.stg.dodo.oppervision.com.br/v1/enroll".to_string()
}

fn default_endpoint() -> EndpointLocalConfig {
    EndpointLocalConfig::default()
}

fn default_config_pull_interval() -> u32 {
    60
}

fn default_agent_id_path() -> String {
    "/var/lib/aegis/agent_id".to_string()
}

impl Default for LocalAgentConfig {
    fn default() -> Self {
        Self {
            endpoint: EndpointLocalConfig::default(),
            tls: TlsLocalConfig::default(),
            buffer: BufferLocalConfig::default(),
            logging: LoggingLocalConfig::default(),
            collectors: default_collectors(),
            labels: std::collections::HashMap::new(),
            redaction_patterns: Vec::new(),
            config_pull_interval_seconds: 60,
            agent_id_path: default_agent_id_path(),
            enrollment_endpoint: default_enrollment_endpoint(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EndpointLocalConfig {
    #[serde(default = "default_address")]
    pub address: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default = "default_retry_max")]
    pub retry_max: u32,
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u32,
}

fn default_address() -> String {
    "grpc.stg.dodo.oppervision.com.br:443".to_string()
}
fn default_timeout_ms() -> u32 {
    5000
}
fn default_retry_max() -> u32 {
    3
}
fn default_retry_backoff_ms() -> u32 {
    1000
}

impl Default for EndpointLocalConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            timeout_ms: default_timeout_ms(),
            retry_max: default_retry_max(),
            retry_backoff_ms: default_retry_backoff_ms(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsLocalConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub client_cert_path: String,
    #[serde(default)]
    pub client_key_path: String,
    #[serde(default = "bool_true")]
    pub verify_server: bool,
}

fn bool_true() -> bool {
    true
}

impl Default for TlsLocalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ca_cert_path: "/etc/aegis/certs/ca.pem".to_string(),
            client_cert_path: "/etc/aegis/certs/agent.pem".to_string(),
            client_key_path: "/etc/aegis/certs/agent-key.pem".to_string(),
            verify_server: true,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BufferLocalConfig {
    #[serde(default = "default_buffer_path")]
    pub path: String,
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u32,
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: u32,
}

fn default_buffer_path() -> String {
    "/var/lib/aegis/buffer".to_string()
}
fn default_max_size_bytes() -> u64 {
    512 * 1024 * 1024
}
fn default_flush_interval_ms() -> u32 {
    5000
}
fn default_max_batch_size() -> u32 {
    500
}

impl Default for BufferLocalConfig {
    fn default() -> Self {
        Self {
            path: default_buffer_path(),
            max_size_bytes: default_max_size_bytes(),
            flush_interval_ms: default_flush_interval_ms(),
            max_batch_size: default_max_batch_size(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingLocalConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_output")]
    pub output: String,
    #[serde(default)]
    pub file_path: String,
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_output() -> String {
    "stdout".to_string()
}

impl Default for LoggingLocalConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            output: default_log_output(),
            file_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollectorLocalConfig {
    pub name: String,
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default)]
    pub interval_seconds: u32,
    #[serde(default)]
    pub parameters: std::collections::HashMap<String, String>,
}

fn default_collectors() -> Vec<CollectorLocalConfig> {
    vec![
        CollectorLocalConfig {
            name: "cpu".into(),
            enabled: true,
            interval_seconds: 5,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "memory".into(),
            enabled: true,
            interval_seconds: 5,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "disk".into(),
            enabled: true,
            interval_seconds: 10,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "network".into(),
            enabled: true,
            interval_seconds: 5,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "process".into(),
            enabled: true,
            interval_seconds: 10,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "security".into(),
            enabled: true,
            interval_seconds: 15,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "certs".into(),
            enabled: true,
            interval_seconds: 3600,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "logs".into(),
            enabled: true,
            interval_seconds: 1,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "inventory".into(),
            enabled: true,
            interval_seconds: 3600,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "self_metrics".into(),
            enabled: true,
            interval_seconds: 30,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "heartbeat".into(),
            enabled: true,
            interval_seconds: 30,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "docker".into(),
            enabled: true,
            interval_seconds: 10,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "postgres".into(),
            enabled: true,
            interval_seconds: 15,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "mongodb".into(),
            enabled: true,
            interval_seconds: 15,
            parameters: Default::default(),
        },
        CollectorLocalConfig {
            name: "redis".into(),
            enabled: true,
            interval_seconds: 10,
            parameters: Default::default(),
        },
    ]
}

/// Items that support hot reload vs items that require restart.
pub fn is_hot_reloadable(field: &str) -> bool {
    matches!(
        field,
        "collectors" | "labels" | "buffer" | "logging" | "redaction_patterns"
    )
}

pub fn requires_restart(field: &str) -> bool {
    matches!(field, "endpoint" | "tls")
}
