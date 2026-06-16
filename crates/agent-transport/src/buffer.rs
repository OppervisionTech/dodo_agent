use crate::{TransportError, TransportResult};
use agent_core::{Envelope, SignalType};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Priority directories for buffer organization.
const PRIORITY_DIRS: &[(&str, &[SignalType])] = &[
    ("p0_security", &[SignalType::SecurityEvent]),
    ("p1_heartbeat", &[SignalType::Heartbeat]),
    ("p2_metric", &[SignalType::Metric]),
    ("p3_log", &[SignalType::Log]),
    (
        "p4_other",
        &[
            SignalType::Trace,
            SignalType::Event,
            SignalType::Inventory,
            SignalType::CustomEvent,
        ],
    ),
];

/// Local disk buffer for when Kong/ingestor is unreachable.
pub struct DiskBuffer {
    base_path: PathBuf,
    max_size_bytes: u64,
}

/// Configuration for the disk buffer.
#[derive(Debug, Clone)]
pub struct BufferConfig {
    pub path: String,
    pub max_size_bytes: u64,
    pub drain_rate_per_second: u32,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            path: "/var/lib/aegis/buffer".to_string(),
            max_size_bytes: 512 * 1024 * 1024, // 512MB
            drain_rate_per_second: 1,
        }
    }
}

impl DiskBuffer {
    pub fn new(config: &BufferConfig) -> TransportResult<Self> {
        let base_path = PathBuf::from(&config.path);

        // Create priority directories
        for (dir_name, _) in PRIORITY_DIRS {
            let dir = base_path.join(dir_name);
            std::fs::create_dir_all(&dir).map_err(|e| {
                TransportError::Buffer(format!(
                    "failed to create buffer dir {}: {e}",
                    dir.display()
                ))
            })?;
        }

        Ok(Self {
            base_path,
            max_size_bytes: config.max_size_bytes,
        })
    }

    /// Write envelopes to disk buffer, organized by priority.
    pub fn write(&self, envelopes: &[Envelope]) -> TransportResult<usize> {
        let current_size = self.used_bytes();
        if current_size >= self.max_size_bytes {
            // Try to evict low-priority data
            self.evict_lowest_priority()?;
            // Re-check after eviction — reject write if still full
            if self.used_bytes() >= self.max_size_bytes {
                return Err(TransportError::Buffer(
                    "buffer full after eviction, cannot write".to_string(),
                ));
            }
        }

        let mut written = 0;
        for envelope in envelopes {
            let dir = self.priority_dir(envelope.signal_type);
            let filename = format!(
                "{}_{}.buf",
                envelope.timestamp_unix_ns, envelope.signal_type as i32,
            );
            let path = dir.join(&filename);

            // Length-prefixed protobuf: 4-byte little-endian length + payload
            let data = &envelope.payload;
            let len_bytes = (data.len() as u32).to_le_bytes();

            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| {
                    TransportError::Buffer(format!("cannot open {}: {e}", path.display()))
                })?;

            let mut writer = BufWriter::new(file);
            writer
                .write_all(&len_bytes)
                .map_err(|e| TransportError::Buffer(format!("write error: {e}")))?;
            writer
                .write_all(data)
                .map_err(|e| TransportError::Buffer(format!("write error: {e}")))?;

            // Write signal_type and metadata
            let meta = (envelope.signal_type as i32).to_le_bytes();
            writer
                .write_all(&meta)
                .map_err(|e| TransportError::Buffer(format!("write error: {e}")))?;
            let ts = envelope.timestamp_unix_ns.to_le_bytes();
            writer
                .write_all(&ts)
                .map_err(|e| TransportError::Buffer(format!("write error: {e}")))?;

            writer
                .flush()
                .map_err(|e| TransportError::Buffer(format!("flush error: {e}")))?;

            // fsync for crash safety
            let file = writer
                .into_inner()
                .map_err(|e| TransportError::Buffer(format!("flush error: {e}")))?;
            file.sync_all()
                .map_err(|e| TransportError::Buffer(format!("fsync error: {e}")))?;

            written += 1;
        }

        if written > 0 {
            info!(
                count = written,
                buffer_used_bytes = self.used_bytes(),
                "envelopes buffered to disk"
            );
        }

        Ok(written)
    }

    /// Read and drain buffered envelopes in priority order.
    pub fn drain(&self, max_count: usize) -> TransportResult<Vec<Envelope>> {
        let mut results = Vec::new();

        for (dir_name, _signal_types) in PRIORITY_DIRS {
            if results.len() >= max_count {
                break;
            }
            let dir = self.base_path.join(dir_name);
            if !dir.exists() {
                continue;
            }

            let mut entries: Vec<_> = std::fs::read_dir(&dir)
                .map_err(|e| TransportError::Buffer(format!("cannot read dir: {e}")))?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "buf"))
                .collect();

            // Sort by filename (timestamp-based) for FIFO order
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                if results.len() >= max_count {
                    break;
                }
                let path = entry.path();
                match std::fs::read(&path) {
                    Ok(data) => {
                        if data.len() >= 16 {
                            // Parse: 4 bytes len + payload + 4 bytes signal_type + 8 bytes timestamp
                            let payload_len =
                                u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                            if data.len() >= 4 + payload_len + 12 {
                                let payload = data[4..4 + payload_len].to_vec();
                                let sig_offset = 4 + payload_len;
                                let signal_type_raw = i32::from_le_bytes([
                                    data[sig_offset],
                                    data[sig_offset + 1],
                                    data[sig_offset + 2],
                                    data[sig_offset + 3],
                                ]);
                                let ts_offset = sig_offset + 4;
                                let timestamp = i64::from_le_bytes([
                                    data[ts_offset],
                                    data[ts_offset + 1],
                                    data[ts_offset + 2],
                                    data[ts_offset + 3],
                                    data[ts_offset + 4],
                                    data[ts_offset + 5],
                                    data[ts_offset + 6],
                                    data[ts_offset + 7],
                                ]);

                                results.push(Envelope {
                                    signal_type: SignalType::from_i32(signal_type_raw),
                                    payload,
                                    timestamp_unix_ns: timestamp,
                                    buffered: true,
                                    retry_count: 1,
                                });
                            }
                        }
                        // Remove file after reading
                        let _ = std::fs::remove_file(&path);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "failed to read buffer file");
                    }
                }
            }
        }

        if !results.is_empty() {
            info!(count = results.len(), "drained envelopes from buffer");
        }

        Ok(results)
    }

    /// Calculate total bytes used by the buffer.
    pub fn used_bytes(&self) -> u64 {
        let mut total = 0u64;
        for (dir_name, _) in PRIORITY_DIRS {
            let dir = self.base_path.join(dir_name);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        total += meta.len();
                    }
                }
            }
        }
        total
    }

    /// Used percentage (0.0 to 100.0).
    pub fn used_percent(&self) -> f64 {
        if self.max_size_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes() as f64 / self.max_size_bytes as f64) * 100.0
    }

    /// Check if buffer has any data.
    pub fn has_data(&self) -> bool {
        self.used_bytes() > 0
    }

    fn priority_dir(&self, signal_type: SignalType) -> PathBuf {
        for (dir_name, types) in PRIORITY_DIRS {
            if types.contains(&signal_type) {
                return self.base_path.join(dir_name);
            }
        }
        self.base_path.join("p4_other")
    }

    fn evict_lowest_priority(&self) -> TransportResult<()> {
        // Evict from lowest priority first (p4, p3, p2...)
        for (dir_name, _) in PRIORITY_DIRS.iter().rev() {
            let dir = self.base_path.join(dir_name);
            if !dir.exists() {
                continue;
            }
            let mut entries: Vec<_> = std::fs::read_dir(&dir)
                .map_err(|e| TransportError::Buffer(format!("cannot read dir: {e}")))?
                .filter_map(|e| e.ok())
                .collect();

            // Sort oldest first
            entries.sort_by_key(|e| e.file_name());

            // Remove oldest 10% or at least 1 file
            let to_remove = std::cmp::max(1, entries.len() / 10);
            for entry in entries.into_iter().take(to_remove) {
                let path = entry.path();
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(path = %path.display(), error = %e, "failed to evict buffer file");
                } else {
                    debug!(path = %path.display(), "evicted old buffer file");
                }
            }

            if self.used_bytes() < self.max_size_bytes {
                return Ok(());
            }
        }
        warn!("buffer full, could not evict enough data");
        Err(TransportError::Buffer(
            "eviction failed to free enough space".to_string(),
        ))
    }
}
