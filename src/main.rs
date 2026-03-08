use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    // Determine variant at compile time
    let variant = agent_variant();

    // Enforce mutually exclusive features at compile time
    #[cfg(all(feature = "linux", feature = "windows"))]
    compile_error!("features 'linux' and 'windows' are mutually exclusive");
    #[cfg(all(feature = "linux", feature = "lite"))]
    compile_error!("features 'linux' and 'lite' are mutually exclusive");
    #[cfg(all(feature = "windows", feature = "lite"))]
    compile_error!("features 'windows' and 'lite' are mutually exclusive");

    // Load config
    let config_path =
        std::env::var("AEGIS_CONFIG").unwrap_or_else(|_| "/etc/aegis/agent.yaml".to_string());
    let config = agent_config::loader::load_or_default(&config_path);

    // Initialize logging
    init_tracing(&config.logging);
    info!(
        version = AGENT_VERSION,
        variant = variant,
        config_path = config_path,
        "DoDo AegisOps Agent starting"
    );

    // Initialize platform
    let platform = agent_platform::create_platform();
    let platform_info = platform.info()?;
    info!(
        hostname = %platform_info.hostname,
        os = %platform_info.os_family,
        arch = %platform_info.architecture,
        "platform detected"
    );

    // Load or generate agent_id
    let agent_id = load_or_create_agent_id(&config.agent_id_path)?;
    info!(agent_id = %agent_id, "agent identity loaded");

    // Initialize agent state
    let agent_state = Arc::new(agent_core::AgentState::new(
        agent_id,
        AGENT_VERSION.to_string(),
        variant.to_string(),
        platform_info.hostname.clone(),
        platform_info.machine_id.clone(),
        platform_info.os_family.clone(),
    ));

    // Initialize redaction engine
    let redaction_engine = Arc::new(
        agent_core::RedactionEngine::new(&config.redaction_patterns)
            .expect("failed to compile redaction patterns"),
    );

    // Platform capabilities
    let capabilities = platform.capabilities().unwrap_or_else(|e| {
        warn!(error = %e, "failed to detect platform capabilities");
        agent_platform::PlatformCapabilities {
            ebpf_available: false,
            container_detected: false,
            cloud_detected: false,
            kernel_version_major: 0,
            kernel_version_minor: 0,
        }
    });

    if capabilities.container_detected {
        info!("running inside a container");
    }

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();

    // Build collector registry
    let platform_arc: Arc<dyn agent_platform::Platform> = Arc::from(platform);
    let mut registry = agent_core::CollectorRegistry::new();

    // Register collectors based on config
    register_collectors(
        &mut registry,
        &config,
        platform_arc.clone(),
        agent_state.clone(),
        redaction_engine.clone(),
    );

    let active_names: Vec<String> = registry
        .collectors()
        .iter()
        .map(|c| c.name().to_string())
        .collect();
    info!(
        collectors = ?active_names,
        count = active_names.len(),
        "collectors registered"
    );

    // Update agent state with active collectors
    {
        let mut ac = agent_state
            .active_collectors
            .write()
            .expect("lock poisoned");
        *ac = active_names;
    }

    // Set initial config hash
    {
        let hash = agent_config::loader::config_hash(&config);
        let mut ch = agent_state.config_hash.write().expect("lock poisoned");
        *ch = hash;
    }

    // Create channels
    let (envelope_tx, envelope_rx) = tokio::sync::mpsc::channel(10_000);
    let (batch_tx, mut batch_rx) = tokio::sync::mpsc::channel(100);

    // Batcher config
    let batcher_config = agent_core::BatcherConfig {
        flush_interval_ms: config.buffer.flush_interval_ms,
        max_batch_size: config.buffer.max_batch_size,
    };

    // Spawn scheduler (takes AgentState by value, not Arc)
    let scheduler_token = cancel_token.clone();
    let scheduler_state = (*agent_state).clone();
    let scheduler_handle = tokio::spawn(async move {
        if let Err(e) =
            agent_core::scheduler::run(registry, envelope_tx, scheduler_token, scheduler_state)
                .await
        {
            tracing::error!(error = %e, "scheduler exited with error");
        }
    });

    // Spawn batcher
    let batcher_token = cancel_token.clone();
    let batcher_handle = tokio::spawn(async move {
        if let Err(e) =
            agent_core::batcher::run(envelope_rx, batch_tx, batcher_config, batcher_token).await
        {
            tracing::error!(error = %e, "batcher exited with error");
        }
    });

    // Spawn batch consumer (transport layer)
    let transport_config = agent_transport::TransportConfig {
        endpoint_address: config.endpoint.address.clone(),
        timeout_ms: config.endpoint.timeout_ms,
        retry_max: config.endpoint.retry_max,
        retry_backoff_ms: config.endpoint.retry_backoff_ms,
        ca_cert_path: config.tls.ca_cert_path.clone(),
        client_cert_path: config.tls.client_cert_path.clone(),
        client_key_path: config.tls.client_key_path.clone(),
        verify_server: config.tls.verify_server,
    };

    let buffer_config = agent_transport::buffer::BufferConfig {
        path: config.buffer.path.clone(),
        max_size_bytes: config.buffer.max_size_bytes,
        drain_rate_per_second: 1,
    };

    let transport_token = cancel_token.clone();
    let transport_state = agent_state.clone();
    let transport_handle = tokio::spawn(async move {
        run_transport(
            &mut batch_rx,
            transport_config,
            buffer_config,
            transport_token,
            transport_state,
        )
        .await;
    });

    // Spawn config watcher
    let config_watcher_token = cancel_token.clone();
    let (config_tx, _config_rx) = tokio::sync::watch::channel(config.clone());
    let initial_hash = agent_config::loader::config_hash(&config);
    let watcher_config_path = config_path.clone();
    let watcher_poll_interval = config.config_pull_interval_seconds;
    let config_watcher_handle = tokio::spawn(async move {
        let mut watcher = agent_config::watcher::ConfigWatcher::new(
            watcher_config_path,
            watcher_poll_interval,
            initial_hash,
        );
        watcher.run(config_tx, config_watcher_token).await;
    });

    // Spawn eBPF manager (Linux only)
    #[cfg(feature = "linux")]
    let ebpf_handle = {
        let ebpf_token = cancel_token.clone();
        tokio::spawn(async move {
            let mut manager = agent_ebpf::EbpfManager::new();
            if agent_ebpf::EbpfManager::is_available() {
                let (ebpf_tx, _ebpf_rx) = tokio::sync::mpsc::channel(10_000);
                if let Err(e) = manager.start(ebpf_tx, ebpf_token).await {
                    warn!(error = %e, "eBPF failed to start, continuing without it");
                }
            } else {
                info!("eBPF not available, using polling-only mode");
                ebpf_token.cancelled().await;
            }
        })
    };

    // Wait for shutdown signal
    let shutdown_reason = agent_core::wait_for_shutdown().await;
    info!(reason = ?shutdown_reason, "shutdown signal received");

    // Begin graceful shutdown sequence
    info!("initiating graceful shutdown...");

    // 1. Stop accepting new work
    cancel_token.cancel();

    // 2. Wait for components (with timeout)
    let shutdown_timeout = std::time::Duration::from_secs(10);
    let shutdown_result = tokio::time::timeout(shutdown_timeout, async {
        // Wait for scheduler to finish current collections
        let _ = scheduler_handle.await;
        info!("scheduler stopped");

        // Wait for batcher to flush
        let _ = batcher_handle.await;
        info!("batcher flushed");

        // Wait for transport to finish sending
        let _ = transport_handle.await;
        info!("transport stopped");

        // Wait for config watcher
        let _ = config_watcher_handle.await;

        // Wait for eBPF
        #[cfg(feature = "linux")]
        {
            let _ = ebpf_handle.await;
            info!("eBPF programs unloaded");
        }
    })
    .await;

    match shutdown_result {
        Ok(()) => {
            info!(
                uptime_s = agent_state.uptime_seconds(),
                envelopes_sent = agent_state
                    .envelopes_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                "agent shutdown complete"
            );
        }
        Err(_) => {
            error!("shutdown timeout exceeded (10s), forcing exit");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn agent_variant() -> &'static str {
    #[cfg(feature = "linux")]
    return "linux";
    #[cfg(feature = "windows")]
    return "windows";
    #[cfg(feature = "lite")]
    return "lite";
    #[cfg(not(any(feature = "linux", feature = "windows", feature = "lite")))]
    return "unknown";
}

fn init_tracing(logging_config: &agent_config::LoggingLocalConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&logging_config.level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .json()
        .init();
}

fn load_or_create_agent_id(path: &str) -> Result<String> {
    // Try to read existing agent_id
    if let Ok(id) = std::fs::read_to_string(path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }

    // Generate new UUID v4
    let id = uuid::Uuid::new_v4().to_string();

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write to disk
    std::fs::write(path, &id)?;
    info!(agent_id = %id, path = path, "generated new agent_id");
    Ok(id)
}

fn register_collectors(
    registry: &mut agent_core::CollectorRegistry,
    config: &agent_config::LocalAgentConfig,
    platform: Arc<dyn agent_platform::Platform>,
    agent_state: Arc<agent_core::AgentState>,
    redaction_engine: Arc<agent_core::RedactionEngine>,
) {
    for cc in &config.collectors {
        if !cc.enabled {
            continue;
        }

        match cc.name.as_str() {
            "cpu" => {
                registry.register(Box::new(agent_collectors::CpuCollector::new(
                    platform.clone(),
                )));
            }
            "memory" => {
                registry.register(Box::new(agent_collectors::MemoryCollector::new(
                    platform.clone(),
                )));
            }
            "disk" => {
                registry.register(Box::new(agent_collectors::DiskCollector::new(
                    platform.clone(),
                )));
            }
            "network" => {
                registry.register(Box::new(agent_collectors::NetworkCollector::new(
                    platform.clone(),
                )));
            }
            "process" => {
                registry.register(Box::new(agent_collectors::ProcessCollector::new(
                    platform.clone(),
                    redaction_engine.clone(),
                    Some(10),
                )));
            }
            "security" => {
                let monitored_files = cc
                    .parameters
                    .get("monitored_files")
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());
                registry.register(Box::new(agent_collectors::SecurityCollector::new(
                    platform.clone(),
                    monitored_files,
                )));
            }
            "certs" => {
                let scan_paths = cc
                    .parameters
                    .get("scan_paths")
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());
                registry.register(Box::new(agent_collectors::CertsCollector::new(
                    platform.clone(),
                    scan_paths,
                )));
            }
            "logs" => {
                let log_paths: Vec<String> = cc
                    .parameters
                    .get("paths")
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                let max_lines = cc
                    .parameters
                    .get("max_lines_per_sec")
                    .and_then(|s| s.parse().ok());
                registry.register(Box::new(agent_collectors::LogsCollector::new(
                    platform.clone(),
                    log_paths,
                    max_lines,
                )));
            }
            "otel" => {
                registry.register(Box::new(agent_collectors::OtelCollector::new(
                    platform.clone(),
                )));
            }
            "kubernetes" => {
                registry.register(Box::new(agent_collectors::KubernetesCollector::new(
                    platform.clone(),
                )));
            }
            "inventory" => {
                registry.register(Box::new(agent_collectors::InventoryCollector::new(
                    platform.clone(),
                )));
            }
            "self_metrics" => {
                registry.register(Box::new(agent_collectors::SelfMetricsCollector::new(
                    platform.clone(),
                    agent_state.clone(),
                    None,
                )));
            }
            "heartbeat" => {
                registry.register(Box::new(agent_collectors::HeartbeatCollector::new(
                    agent_state.clone(),
                )));
            }
            unknown => {
                warn!(collector = unknown, "unknown collector name, skipping");
            }
        }
    }
}

async fn run_transport(
    batch_rx: &mut tokio::sync::mpsc::Receiver<Vec<agent_core::Envelope>>,
    transport_config: agent_transport::TransportConfig,
    buffer_config: agent_transport::buffer::BufferConfig,
    cancel_token: CancellationToken,
    agent_state: Arc<agent_core::AgentState>,
) {
    let grpc_client = agent_transport::grpc_client::GrpcClient::new(transport_config);

    // Initialize disk buffer (for offline resilience)
    let disk_buffer = match agent_transport::buffer::DiskBuffer::new(&buffer_config) {
        Ok(buf) => Some(buf),
        Err(e) => {
            warn!(error = %e, "failed to initialize disk buffer");
            None
        }
    };

    // First, drain any buffered data from previous run
    if let Some(ref buf) = disk_buffer {
        if buf.has_data() {
            info!("draining buffered data from previous run");
            match buf.drain(500) {
                Ok(envelopes) if !envelopes.is_empty() => {
                    info!(count = envelopes.len(), "drained buffered envelopes");
                    if let Err(e) = grpc_client.submit_batch(envelopes, &agent_state).await {
                        warn!(error = %e, "failed to send drained buffer data");
                    }
                }
                _ => {}
            }
        }
    }

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("transport shutting down");
                // Final drain attempt
                if let Some(batch) = batch_rx.recv().await {
                    if let Err(e) = grpc_client.submit_batch(batch, &agent_state).await {
                        warn!(error = %e, "final batch send failed, buffering");
                        // Buffer to disk if available
                    }
                }
                grpc_client.disconnect().await;
                return;
            }
            Some(batch) = batch_rx.recv() => {
                let batch_size = batch.len();
                match grpc_client.submit_batch(batch.clone(), &agent_state).await {
                    Ok(result) => {
                        agent_state.envelopes_sent.fetch_add(
                            result.accepted as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, batch_size = batch_size, "batch send failed, buffering to disk");
                        agent_state.envelopes_failed.fetch_add(
                            batch_size as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        // Buffer to disk
                        if let Some(ref buf) = disk_buffer {
                            if let Err(be) = buf.write(&batch) {
                                error!(error = %be, "failed to write to disk buffer");
                            } else {
                                agent_state.buffer_used_bytes.store(
                                    buf.used_bytes(),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
