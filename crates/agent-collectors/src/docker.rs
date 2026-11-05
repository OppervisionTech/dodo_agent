//! Docker container collector — HU261.
//!
//! Collects per-container metrics (CPU, memory, network, disk, status, restarts)
//! via the Docker Engine API over Unix socket (`/var/run/docker.sock`).
//!
//! # SECURITY
//! - NEVER expose container env vars (may contain secrets)
//! - NEVER log container commands/entrypoints without redaction
//! - If Docker socket is not accessible, collector is silently inactive

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::helpers;

const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const COLLECT_INTERVAL_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Docker API response types (minimal)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Debug)]
struct ContainerListEntry {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names")]
    names: Vec<String>,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "Status")]
    #[allow(dead_code)]
    status: String,
}

#[derive(serde::Deserialize, Debug)]
struct ContainerStats {
    #[serde(default)]
    cpu_stats: CpuStats,
    #[serde(default)]
    precpu_stats: CpuStats,
    #[serde(default)]
    memory_stats: MemoryStats,
    #[serde(default)]
    networks: Option<HashMap<String, NetworkStats>>,
    #[serde(default)]
    blkio_stats: BlkioStats,
}

#[derive(serde::Deserialize, Debug, Default)]
struct CpuStats {
    #[serde(default)]
    cpu_usage: CpuUsage,
    #[serde(default)]
    system_cpu_usage: u64,
    #[serde(default)]
    online_cpus: u64,
}

#[derive(serde::Deserialize, Debug, Default)]
struct CpuUsage {
    #[serde(default)]
    total_usage: u64,
}

#[derive(serde::Deserialize, Debug, Default)]
struct MemoryStats {
    #[serde(default)]
    usage: u64,
    #[serde(default)]
    limit: u64,
}

#[derive(serde::Deserialize, Debug, Default)]
struct NetworkStats {
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
}

#[derive(serde::Deserialize, Debug, Default)]
struct BlkioStats {
    #[serde(default)]
    io_service_bytes_recursive: Option<Vec<BlkioEntry>>,
}

#[derive(serde::Deserialize, Debug)]
struct BlkioEntry {
    #[serde(default)]
    op: String,
    #[serde(default)]
    value: u64,
}

#[derive(serde::Deserialize, Debug)]
struct ContainerInspect {
    #[serde(rename = "RestartCount", default)]
    restart_count: u64,
}

// ---------------------------------------------------------------------------
// Previous state for delta calculations
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PreviousContainerState {
    rx_bytes: u64,
    tx_bytes: u64,
    read_bytes: u64,
    write_bytes: u64,
}

// ---------------------------------------------------------------------------
// Docker API client (raw HTTP over Unix socket)
// ---------------------------------------------------------------------------

async fn docker_get(path: &str) -> Result<Vec<u8>, CollectorError> {
    let mut stream = tokio::net::UnixStream::connect(DOCKER_SOCKET)
        .await
        .map_err(|e| CollectorError::Io(e.to_string()))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| CollectorError::Io(e.to_string()))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| CollectorError::Io(e.to_string()))?;

    // Find body after \r\n\r\n
    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str
        .find("\r\n\r\n")
        .ok_or_else(|| CollectorError::Failed("invalid HTTP response from Docker".into()))?;
    let body = &response[body_start + 4..];

    // Handle chunked transfer encoding
    let is_chunked = response_str[..body_start]
        .to_lowercase()
        .contains("transfer-encoding: chunked");

    if is_chunked {
        Ok(decode_chunked(body))
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;
    let data_str = String::from_utf8_lossy(data);

    for line in data_str.split("\r\n") {
        if pos == 0 {
            // First token is chunk size in hex
            if let Ok(size) = usize::from_str_radix(line.trim(), 16) {
                if size == 0 {
                    break;
                }
                pos = size;
            }
        } else {
            let bytes = line.as_bytes();
            let take = bytes.len().min(pos);
            result.extend_from_slice(&bytes[..take]);
            pos = pos.saturating_sub(take);
        }
    }

    if result.is_empty() {
        // Fallback: try to find JSON directly
        if let Some(start) = data_str.find('[').or_else(|| data_str.find('{')) {
            return data_str[start..].as_bytes().to_vec();
        }
        data.to_vec()
    } else {
        result
    }
}

async fn docker_available() -> bool {
    tokio::net::UnixStream::connect(DOCKER_SOCKET).await.is_ok()
}

// ---------------------------------------------------------------------------
// DockerCollector
// ---------------------------------------------------------------------------

pub struct DockerCollector {
    host_id: String,
    previous: Mutex<HashMap<String, PreviousContainerState>>,
    active: Mutex<bool>,
    warned: Mutex<bool>,
}

impl DockerCollector {
    pub fn new(host_id: String) -> Self {
        Self {
            host_id,
            previous: Mutex::new(HashMap::new()),
            active: Mutex::new(true), // assume active, verify on first collect
            warned: Mutex::new(false),
        }
    }

    async fn collect_impl(&self) -> Result<Vec<Envelope>, CollectorError> {
        // Check if Docker is available
        if !docker_available().await {
            let mut active = self.active.lock().await;
            if *active {
                let mut warned = self.warned.lock().await;
                if !*warned {
                    info!("Docker not available, collector inactive");
                    *warned = true;
                }
                *active = false;
            }
            return Ok(Vec::new());
        }

        // Reactivate if Docker came back
        {
            let mut active = self.active.lock().await;
            if !*active {
                info!("Docker detected, activating collector");
                *active = true;
                *self.warned.lock().await = false;
            }
        }

        let mut envelopes = Vec::new();

        // List all containers (including stopped)
        let list_body = docker_get("/containers/json?all=true").await?;
        let containers: Vec<ContainerListEntry> = serde_json::from_slice(&list_body)
            .map_err(|e| CollectorError::Failed(format!("failed to parse container list: {e}")))?;

        let mut running = 0u64;
        let mut stopped = 0u64;
        let total = containers.len() as u64;

        let mut seen_ids: Vec<String> = Vec::new();

        // stats?stream=false blocks ~2s per container (Docker waits for a
        // second CPU sample), so fetching them one by one blows the
        // collection timeout on hosts with a dozen+ containers. Fetch all
        // running containers' stats concurrently up front.
        let mut stats_by_id: HashMap<String, Result<Vec<u8>, CollectorError>> = HashMap::new();
        {
            let mut set = tokio::task::JoinSet::new();
            for c in containers.iter().filter(|c| c.state == "running") {
                let id = c.id.clone();
                set.spawn(async move {
                    let res = docker_get(&format!("/containers/{id}/stats?stream=false")).await;
                    (id, res)
                });
            }
            while let Some(joined) = set.join_next().await {
                if let Ok((id, res)) = joined {
                    stats_by_id.insert(id, res);
                }
            }
        }

        for container in &containers {
            let short_id = &container.id[..12.min(container.id.len())];
            let name = container
                .names
                .first()
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| short_id.to_string());

            seen_ids.push(short_id.to_string());

            let labels: Vec<(&str, &str)> = vec![
                ("container_id", short_id),
                ("container_name", &name),
                ("image", &container.image),
                ("host_id", &self.host_id),
            ];

            if container.state == "running" {
                running += 1;

                // Get stats for running containers
                let stats = stats_by_id
                    .remove(&container.id)
                    .unwrap_or_else(|| Err(CollectorError::Failed("stats task failed".into())));
                match stats {
                    Ok(stats_body) => {
                        match serde_json::from_slice::<ContainerStats>(&stats_body) {
                            Ok(stats) => {
                                // CPU percent
                                let cpu_delta = stats
                                    .cpu_stats
                                    .cpu_usage
                                    .total_usage
                                    .saturating_sub(stats.precpu_stats.cpu_usage.total_usage);
                                let system_delta = stats
                                    .cpu_stats
                                    .system_cpu_usage
                                    .saturating_sub(stats.precpu_stats.system_cpu_usage);
                                let num_cpus = stats.cpu_stats.online_cpus.max(1);
                                let cpu_percent = if system_delta > 0 {
                                    (cpu_delta as f64 / system_delta as f64)
                                        * num_cpus as f64
                                        * 100.0
                                } else {
                                    0.0
                                };
                                envelopes.push(helpers::metric_envelope(
                                    "docker.container.cpu.percent",
                                    cpu_percent,
                                    &labels,
                                    "gauge",
                                ));

                                // Memory
                                let mem_usage = stats.memory_stats.usage as f64;
                                let mem_limit = stats.memory_stats.limit as f64;
                                let mem_percent = if mem_limit > 0.0 {
                                    (mem_usage / mem_limit) * 100.0
                                } else {
                                    0.0
                                };
                                envelopes.push(helpers::metric_envelope(
                                    "docker.container.memory.usage_bytes",
                                    mem_usage,
                                    &labels,
                                    "gauge",
                                ));
                                envelopes.push(helpers::metric_envelope(
                                    "docker.container.memory.limit_bytes",
                                    mem_limit,
                                    &labels,
                                    "gauge",
                                ));
                                envelopes.push(helpers::metric_envelope(
                                    "docker.container.memory.percent",
                                    mem_percent,
                                    &labels,
                                    "gauge",
                                ));

                                // Network (delta)
                                let (total_rx, total_tx) =
                                    if let Some(ref networks) = stats.networks {
                                        networks.values().fold((0u64, 0u64), |(rx, tx), n| {
                                            (rx + n.rx_bytes, tx + n.tx_bytes)
                                        })
                                    } else {
                                        (0, 0)
                                    };

                                // Disk I/O
                                let (read_bytes, write_bytes) = stats
                                    .blkio_stats
                                    .io_service_bytes_recursive
                                    .as_ref()
                                    .map(|entries| {
                                        let r = entries
                                            .iter()
                                            .filter(|e| e.op.eq_ignore_ascii_case("read"))
                                            .map(|e| e.value)
                                            .sum::<u64>();
                                        let w = entries
                                            .iter()
                                            .filter(|e| e.op.eq_ignore_ascii_case("write"))
                                            .map(|e| e.value)
                                            .sum::<u64>();
                                        (r, w)
                                    })
                                    .unwrap_or((0, 0));

                                // Compute deltas
                                let mut prev_guard = self.previous.lock().await;
                                if let Some(prev) = prev_guard.get(&short_id.to_string()) {
                                    let rx_delta = total_rx.saturating_sub(prev.rx_bytes);
                                    let tx_delta = total_tx.saturating_sub(prev.tx_bytes);
                                    let read_delta = read_bytes.saturating_sub(prev.read_bytes);
                                    let write_delta = write_bytes.saturating_sub(prev.write_bytes);

                                    envelopes.push(helpers::metric_envelope(
                                        "docker.container.network.rx_bytes",
                                        rx_delta as f64,
                                        &labels,
                                        "counter",
                                    ));
                                    envelopes.push(helpers::metric_envelope(
                                        "docker.container.network.tx_bytes",
                                        tx_delta as f64,
                                        &labels,
                                        "counter",
                                    ));
                                    envelopes.push(helpers::metric_envelope(
                                        "docker.container.disk.read_bytes",
                                        read_delta as f64,
                                        &labels,
                                        "counter",
                                    ));
                                    envelopes.push(helpers::metric_envelope(
                                        "docker.container.disk.write_bytes",
                                        write_delta as f64,
                                        &labels,
                                        "counter",
                                    ));
                                }

                                prev_guard.insert(
                                    short_id.to_string(),
                                    PreviousContainerState {
                                        rx_bytes: total_rx,
                                        tx_bytes: total_tx,
                                        read_bytes,
                                        write_bytes,
                                    },
                                );
                                drop(prev_guard);
                            }
                            Err(e) => {
                                debug!(container = %short_id, error = %e, "failed to parse container stats");
                            }
                        }
                    }
                    Err(e) => {
                        debug!(container = %short_id, error = %e, "failed to get container stats");
                    }
                }

                // Restart count (from inspect)
                let inspect_path = format!("/containers/{}/json", container.id);
                if let Ok(inspect_body) = docker_get(&inspect_path).await {
                    if let Ok(inspect) = serde_json::from_slice::<ContainerInspect>(&inspect_body) {
                        envelopes.push(helpers::metric_envelope(
                            "docker.container.restart_count",
                            inspect.restart_count as f64,
                            &labels,
                            "gauge",
                        ));
                    }
                }

                // Container status as metric label
                envelopes.push(helpers::metric_envelope(
                    "docker.container.status",
                    1.0,
                    &[
                        ("container_id", short_id),
                        ("container_name", &name),
                        ("image", &container.image),
                        ("host_id", &self.host_id),
                        ("status", &container.state),
                    ],
                    "gauge",
                ));
            } else {
                stopped += 1;
            }
        }

        // Clean up state for removed containers
        {
            let mut prev_guard = self.previous.lock().await;
            prev_guard.retain(|id, _| seen_ids.contains(id));
        }

        // Host-level aggregated metrics
        let host_labels: Vec<(&str, &str)> = vec![("host_id", &self.host_id)];
        envelopes.push(helpers::metric_envelope(
            "docker.host.containers_running",
            running as f64,
            &host_labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "docker.host.containers_stopped",
            stopped as f64,
            &host_labels,
            "gauge",
        ));
        envelopes.push(helpers::metric_envelope(
            "docker.host.containers_total",
            total as f64,
            &host_labels,
            "gauge",
        ));

        Ok(envelopes)
    }
}

impl Collector for DockerCollector {
    fn name(&self) -> &str {
        "docker"
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
    fn docker_socket_path() {
        assert_eq!(DOCKER_SOCKET, "/var/run/docker.sock");
    }

    #[test]
    fn decode_chunked_basic() {
        let chunked = b"a\r\n0123456789\r\n0\r\n\r\n";
        let decoded = decode_chunked(chunked);
        assert_eq!(decoded, b"0123456789");
    }

    #[test]
    fn decode_chunked_json_fallback() {
        let body = b"[{\"id\":\"abc\"}]";
        let decoded = decode_chunked(body);
        assert_eq!(decoded, b"[{\"id\":\"abc\"}]");
    }

    #[test]
    fn container_name_strips_slash() {
        let name = "/my-container";
        let cleaned = name.trim_start_matches('/');
        assert_eq!(cleaned, "my-container");
    }

    #[test]
    fn cpu_percent_calculation() {
        let cpu_delta = 500_000_000u64;
        let system_delta = 10_000_000_000u64;
        let num_cpus = 4u64;
        let percent = (cpu_delta as f64 / system_delta as f64) * num_cpus as f64 * 100.0;
        assert!((percent - 20.0).abs() < 0.01);
    }

    #[test]
    fn memory_percent_calculation() {
        let usage = 400_000_000.0f64;
        let limit = 512_000_000.0f64;
        let percent = (usage / limit) * 100.0;
        assert!((percent - 78.125).abs() < 0.01);
    }

    #[tokio::test]
    async fn collector_inactive_without_docker() {
        let collector = DockerCollector::new("test-host".to_string());
        // On CI/dev machine without Docker socket, should return empty
        let _envelopes = collector.collect().await.unwrap();
        // Either empty (no docker) or has metrics (docker present)
        // Just verify it doesn't crash
    }
}
