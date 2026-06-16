//! Redis collector — HU263.
//!
//! Collects Redis metrics via the `INFO` command using raw RESP protocol over TCP.
//! Activated only when `DODO_AGENT_REDIS_URL` env var is set.
//!
//! # SECURITY
//! - URL is NEVER logged (may contain password)
//! - Only INFO command (read-only, no data access)
//! - Manual RESP implementation to avoid external dependency

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::helpers;

const COLLECT_INTERVAL_SECS: u64 = 10;
const URL_ENV_VAR: &str = "DODO_AGENT_REDIS_URL";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

struct RedisAddr {
    host: String,
    port: u16,
    password: Option<String>,
}

fn parse_redis_url(url: &str) -> Result<RedisAddr, CollectorError> {
    // Supports: redis://[:password@]host:port[/db]
    //           host:port
    let url = url.trim();

    if url.starts_with("redis://") || url.starts_with("rediss://") {
        let stripped = url
            .trim_start_matches("redis://")
            .trim_start_matches("rediss://");
        let (auth_part, host_part) = if let Some(at_pos) = stripped.rfind('@') {
            (Some(&stripped[..at_pos]), &stripped[at_pos + 1..])
        } else {
            (None, stripped)
        };

        let password = auth_part.and_then(|a| {
            let a = a.trim_start_matches(':');
            if a.is_empty() {
                None
            } else {
                Some(a.to_string())
            }
        });

        // Strip /db suffix
        let host_port = host_part.split('/').next().unwrap_or(host_part);
        let (host, port) = parse_host_port(host_port)?;

        Ok(RedisAddr {
            host,
            port,
            password,
        })
    } else {
        let (host, port) = parse_host_port(url)?;
        Ok(RedisAddr {
            host,
            port,
            password: None,
        })
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16), CollectorError> {
    if let Some(colon_pos) = s.rfind(':') {
        let host = s[..colon_pos].to_string();
        let port = s[colon_pos + 1..]
            .parse::<u16>()
            .map_err(|_| CollectorError::Failed("invalid port in Redis URL".into()))?;
        Ok((host, port))
    } else {
        Ok((s.to_string(), 6379))
    }
}

// ---------------------------------------------------------------------------
// RESP protocol (minimal for INFO + AUTH)
// ---------------------------------------------------------------------------

async fn resp_command(
    stream: &mut BufReader<TcpStream>,
    args: &[&str],
) -> Result<String, CollectorError> {
    // Encode RESP array
    let mut cmd = format!("*{}\r\n", args.len());
    for arg in args {
        cmd.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }

    stream
        .get_mut()
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| CollectorError::Io(e.to_string()))?;

    // Read response
    let mut first_line = String::new();
    stream
        .read_line(&mut first_line)
        .await
        .map_err(|e| CollectorError::Io(e.to_string()))?;
    let first_line = first_line.trim_end();

    match first_line.chars().next() {
        Some('+') => Ok(first_line[1..].to_string()),
        Some('-') => Err(CollectorError::Failed(format!(
            "Redis error: {}",
            &first_line[1..]
        ))),
        Some('$') => {
            let len: i64 = first_line[1..]
                .parse()
                .map_err(|_| CollectorError::Failed("invalid RESP bulk length".into()))?;
            if len < 0 {
                return Ok(String::new()); // nil bulk string
            }
            let mut buf = vec![0u8; len as usize + 2]; // +2 for \r\n
            tokio::io::AsyncReadExt::read_exact(stream, &mut buf)
                .await
                .map_err(|e| CollectorError::Io(e.to_string()))?;
            let s = String::from_utf8_lossy(&buf[..len as usize]).to_string();
            Ok(s)
        }
        _ => Err(CollectorError::Failed(format!(
            "unexpected RESP response: {first_line}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// INFO parser
// ---------------------------------------------------------------------------

fn parse_info(info: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in info.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

fn get_f64(info: &std::collections::HashMap<String, String>, key: &str) -> f64 {
    info.get(key)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn get_i64(info: &std::collections::HashMap<String, String>, key: &str) -> i64 {
    info.get(key)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Previous state for delta calculations
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PreviousState {
    keyspace_hits: i64,
    keyspace_misses: i64,
    evicted_keys: i64,
    rejected_connections: i64,
}

// ---------------------------------------------------------------------------
// RedisCollector
// ---------------------------------------------------------------------------

pub struct RedisCollector {
    host_id: String,
    url: Option<String>,
    previous: Mutex<Option<PreviousState>>,
}

impl RedisCollector {
    pub fn new(host_id: String) -> Self {
        let url = std::env::var(URL_ENV_VAR).ok();

        if url.is_some() {
            info!("Redis collector configured (URL from env)");
        } else {
            info!("Redis collector inactive (no URL configured)");
        }

        Self {
            host_id,
            url,
            previous: Mutex::new(None),
        }
    }

    async fn collect_impl(&self) -> Result<Vec<Envelope>, CollectorError> {
        let url = match &self.url {
            Some(u) => u,
            None => return Ok(Vec::new()),
        };

        let addr = parse_redis_url(url)?;
        let connect_addr = format!("{}:{}", addr.host, addr.port);

        let stream = tokio::time::timeout(DEFAULT_TIMEOUT, TcpStream::connect(&connect_addr))
            .await
            .map_err(|_| CollectorError::Timeout)?
            .map_err(|e| CollectorError::Io(e.to_string()))?;

        let mut reader = BufReader::new(stream);

        // AUTH if password provided
        if let Some(ref password) = addr.password {
            match resp_command(&mut reader, &["AUTH", password]).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Redis AUTH failed");
                    return Err(e);
                }
            }
        }

        // Send INFO command
        let info_str = resp_command(&mut reader, &["INFO"]).await?;
        let info = parse_info(&info_str);

        let mut envelopes = Vec::new();

        // Labels
        let redis_version = info
            .get("redis_version")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let role = info
            .get("role")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let labels: Vec<(&str, &str)> = vec![
            ("redis_version", &redis_version),
            ("role", &role),
            ("host_id", &self.host_id),
        ];

        // -- Connections --
        envelopes.push(helpers::metric_envelope(
            "redis.connections.connected_clients",
            get_f64(&info, "connected_clients"),
            &labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "redis.connections.blocked_clients",
            get_f64(&info, "blocked_clients"),
            &labels,
            "gauge",
        ));

        // -- Memory --
        let used_memory = get_f64(&info, "used_memory");
        let maxmemory = get_f64(&info, "maxmemory");
        let mem_percent = if maxmemory > 0.0 {
            (used_memory / maxmemory) * 100.0
        } else {
            0.0
        };
        let frag_ratio = get_f64(&info, "mem_fragmentation_ratio");

        envelopes.push(helpers::metric_envelope(
            "redis.memory.used_bytes",
            used_memory,
            &labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "redis.memory.max_bytes",
            maxmemory,
            &labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "redis.memory.percent",
            mem_percent,
            &labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "redis.memory.fragmentation_ratio",
            frag_ratio,
            &labels,
            "gauge",
        ));

        // -- Keyspace hits/misses (delta) --
        let hits = get_i64(&info, "keyspace_hits");
        let misses = get_i64(&info, "keyspace_misses");
        let evicted = get_i64(&info, "evicted_keys");
        let rejected = get_i64(&info, "rejected_connections");

        let mut prev_guard = self.previous.lock().await;
        if let Some(prev) = prev_guard.as_ref() {
            let d = |c: i64, p: i64| -> f64 { c.saturating_sub(p).max(0) as f64 };
            let hits_delta = d(hits, prev.keyspace_hits);
            let misses_delta = d(misses, prev.keyspace_misses);

            envelopes.push(helpers::metric_envelope(
                "redis.keyspace.hits",
                hits_delta,
                &labels,
                "counter",
            ));
            envelopes.push(helpers::metric_envelope(
                "redis.keyspace.misses",
                misses_delta,
                &labels,
                "counter",
            ));

            let total = hits_delta + misses_delta;
            let hit_ratio = if total > 0.0 {
                (hits_delta / total) * 100.0
            } else {
                100.0
            };
            envelopes.push(helpers::metric_envelope(
                "redis.keyspace.hit_ratio",
                hit_ratio,
                &labels,
                "gauge",
            ));

            envelopes.push(helpers::metric_envelope(
                "redis.evictions",
                d(evicted, prev.evicted_keys),
                &labels,
                "counter",
            ));
            envelopes.push(helpers::metric_envelope(
                "redis.connections.rejected",
                d(rejected, prev.rejected_connections),
                &labels,
                "counter",
            ));
        } else {
            debug!("Redis: first sample, deltas available next tick");
            // Still emit hit_ratio from cumulative values
            let total = hits + misses;
            let hit_ratio = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                100.0
            };
            envelopes.push(helpers::metric_envelope(
                "redis.keyspace.hit_ratio",
                hit_ratio,
                &labels,
                "gauge",
            ));
        }

        *prev_guard = Some(PreviousState {
            keyspace_hits: hits,
            keyspace_misses: misses,
            evicted_keys: evicted,
            rejected_connections: rejected,
        });
        drop(prev_guard);

        // -- Throughput --
        envelopes.push(helpers::metric_envelope(
            "redis.ops_per_sec",
            get_f64(&info, "instantaneous_ops_per_sec"),
            &labels,
            "gauge",
        ));

        // -- Latency (if available) --
        let latency = get_f64(&info, "latency_percentile_stats_p50");
        if latency > 0.0 {
            envelopes.push(helpers::metric_envelope(
                "redis.latency.usec",
                latency,
                &labels,
                "gauge",
            ));
        }

        // -- Replication --
        let connected_slaves = get_f64(&info, "connected_slaves");
        envelopes.push(helpers::metric_envelope(
            "redis.replication.connected_slaves",
            connected_slaves,
            &labels,
            "gauge",
        ));

        if role == "slave" {
            let lag = get_f64(&info, "master_repl_offset") - get_f64(&info, "slave_repl_offset");
            envelopes.push(helpers::metric_envelope(
                "redis.replication.offset_lag_bytes",
                lag.max(0.0),
                &labels,
                "gauge",
            ));
        }

        // -- Keyspace totals --
        let mut total_keys: i64 = 0;
        let mut total_expires: i64 = 0;
        for (key, value) in &info {
            if key.starts_with("db") && key[2..].chars().all(|c| c.is_ascii_digit()) {
                // Format: "keys=123,expires=45,avg_ttl=6789"
                for part in value.split(',') {
                    if let Some(v) = part.strip_prefix("keys=") {
                        total_keys += v.parse::<i64>().unwrap_or(0);
                    } else if let Some(v) = part.strip_prefix("expires=") {
                        total_expires += v.parse::<i64>().unwrap_or(0);
                    }
                }
            }
        }
        envelopes.push(helpers::metric_envelope(
            "redis.keys.total",
            total_keys as f64,
            &labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "redis.keys.expires",
            total_expires as f64,
            &labels,
            "gauge",
        ));

        Ok(envelopes)
    }
}

impl Collector for RedisCollector {
    fn name(&self) -> &str {
        "redis"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Metric
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(COLLECT_INTERVAL_SECS)
    }

    fn collect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>> {
        Box::pin(self.collect_impl())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_env_var_name() {
        assert_eq!(URL_ENV_VAR, "DODO_AGENT_REDIS_URL");
    }

    #[test]
    fn name_is_redis() {
        let collector = RedisCollector::new("test-host".to_string());
        assert_eq!(collector.name(), "redis");
    }

    #[test]
    fn interval_is_10s() {
        let collector = RedisCollector::new("test-host".to_string());
        assert_eq!(collector.interval(), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn inactive_without_url() {
        std::env::remove_var(URL_ENV_VAR);
        let collector = RedisCollector::new("test-host".to_string());
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn parse_redis_url_full() {
        let addr = parse_redis_url("redis://:mypassword@localhost:6380/0").unwrap();
        assert_eq!(addr.host, "localhost");
        assert_eq!(addr.port, 6380);
        assert_eq!(addr.password.as_deref(), Some("mypassword"));
    }

    #[test]
    fn parse_redis_url_no_auth() {
        let addr = parse_redis_url("redis://127.0.0.1:6379").unwrap();
        assert_eq!(addr.host, "127.0.0.1");
        assert_eq!(addr.port, 6379);
        assert!(addr.password.is_none());
    }

    #[test]
    fn parse_redis_url_plain() {
        let addr = parse_redis_url("10.0.0.1:6379").unwrap();
        assert_eq!(addr.host, "10.0.0.1");
        assert_eq!(addr.port, 6379);
    }

    #[test]
    fn parse_info_basic() {
        let info = "# Server\r\nredis_version:7.2.0\r\n# Clients\r\nconnected_clients:10\r\n";
        let map = parse_info(info);
        assert_eq!(map.get("redis_version").unwrap(), "7.2.0");
        assert_eq!(map.get("connected_clients").unwrap(), "10");
    }

    #[test]
    fn parse_info_keyspace() {
        let info =
            "db0:keys=100,expires=50,avg_ttl=1000\r\ndb1:keys=200,expires=30,avg_ttl=2000\r\n";
        let map = parse_info(info);

        let mut total_keys = 0i64;
        let mut total_expires = 0i64;
        for (key, value) in &map {
            if key.starts_with("db") && key[2..].chars().all(|c| c.is_ascii_digit()) {
                for part in value.split(',') {
                    if let Some(v) = part.strip_prefix("keys=") {
                        total_keys += v.parse::<i64>().unwrap_or(0);
                    } else if let Some(v) = part.strip_prefix("expires=") {
                        total_expires += v.parse::<i64>().unwrap_or(0);
                    }
                }
            }
        }
        assert_eq!(total_keys, 300);
        assert_eq!(total_expires, 80);
    }

    #[test]
    fn hit_ratio_calculation() {
        let hits = 950.0f64;
        let misses = 50.0f64;
        let total = hits + misses;
        let ratio = (hits / total) * 100.0;
        assert!((ratio - 95.0).abs() < 0.01);
    }

    #[test]
    fn memory_percent_calculation() {
        let used = 800_000_000.0f64;
        let max = 1_000_000_000.0f64;
        let percent = (used / max) * 100.0;
        assert!((percent - 80.0).abs() < 0.01);
    }
}
