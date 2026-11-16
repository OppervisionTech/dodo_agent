use crate::{TransportError, TransportResult};
use agent_core::{Envelope, SignalType};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

fn sync_directory(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

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
    // Cached total size. Scanning every directory per record made a write of
    // N records cost O(N x files on disk), which stalled the agent once the
    // buffer grew. Rescanned after deletions (ack, eviction), bumped on write.
    used: AtomicU64,
}

/// A read-only snapshot. Files remain durable until the upstream acknowledges
/// the batch and `acknowledge` is called. A crash before ack replays at least once.
pub struct PendingBatch {
    pub envelopes: Vec<Envelope>,
    receipts: Vec<(PathBuf, u64, u64)>, // path, consumed bytes, original length
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

        let buffer = Self {
            base_path,
            max_size_bytes: config.max_size_bytes,
            used: AtomicU64::new(0),
        };
        buffer.rescan();
        Ok(buffer)
    }

    /// Write envelopes to disk buffer, organized by priority.
    ///
    /// One file per priority per call, with one fsync, instead of one file and
    /// two fsyncs per record: a 500-record batch used to take ~30 s and block
    /// the transport loop. Records keep the length-prefixed layout that `peek`
    /// already reads from multi-record (legacy) files.
    pub fn write(&self, envelopes: &[Envelope]) -> TransportResult<usize> {
        for envelope in envelopes {
            let record_size = envelope.payload.len() as u64 + 16;
            if record_size > self.max_size_bytes || record_size > 4 * 1024 * 1024 + 16 {
                return Err(TransportError::Buffer(
                    "record exceeds buffer or upstream limit".into(),
                ));
            }
        }
        let mut written = 0;
        for (dir_name, _) in PRIORITY_DIRS {
            let group: Vec<&Envelope> = envelopes
                .iter()
                .filter(|envelope| self.priority_dir(envelope.signal_type).ends_with(dir_name))
                .collect();
            if group.is_empty() {
                continue;
            }
            let mut data = Vec::new();
            for envelope in &group {
                data.extend_from_slice(&(envelope.payload.len() as u32).to_le_bytes());
                data.extend_from_slice(&envelope.payload);
                data.extend_from_slice(&(envelope.signal_type as i32).to_le_bytes());
                data.extend_from_slice(&envelope.timestamp_unix_ns.to_le_bytes());
            }
            let size = data.len() as u64;
            if size > self.max_size_bytes {
                return Err(TransportError::Buffer("batch exceeds buffer size".into()));
            }
            while self.used_bytes().saturating_add(size) > self.max_size_bytes {
                self.evict_lowest_priority()?;
            }
            let dir = self.base_path.join(dir_name);
            let path = dir.join(format!(
                "{}_{}.buf",
                group[0].timestamp_unix_ns,
                uuid::Uuid::new_v4()
            ));
            let temporary = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));

            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options
                .open(&temporary)
                .map_err(|e| TransportError::Buffer(format!("cannot create buffer record: {e}")))?;
            let mut writer = BufWriter::new(file);
            writer
                .write_all(&data)
                .map_err(|e| TransportError::Buffer(format!("write error: {e}")))?;
            let file = writer
                .into_inner()
                .map_err(|e| TransportError::Buffer(format!("flush error: {e}")))?;
            // fsync for crash safety
            file.sync_all()
                .map_err(|e| TransportError::Buffer(format!("fsync error: {e}")))?;
            std::fs::rename(&temporary, &path)?;
            // Persist the directory entry as well as the record contents.
            sync_directory(&dir)?;
            self.used.fetch_add(size, Ordering::Relaxed);
            written += group.len();
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

    /// Read buffered records without deleting them. Legacy files may contain
    /// several appended records; each is decoded and acknowledged separately.
    pub fn peek(&self, max_count: usize) -> TransportResult<PendingBatch> {
        let mut batch = PendingBatch {
            envelopes: Vec::new(),
            receipts: Vec::new(),
        };
        for (dir_name, _) in PRIORITY_DIRS {
            if batch.envelopes.len() >= max_count {
                break;
            }
            let dir = self.base_path.join(dir_name);
            let mut paths: Vec<_> = std::fs::read_dir(&dir)?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "buf"))
                .collect();
            paths.sort();
            for path in paths {
                if batch.envelopes.len() >= max_count {
                    break;
                }
                let file = std::fs::File::open(&path)?;
                let original_length = file.metadata()?.len();
                let mut reader = BufReader::new(file);
                let mut consumed = 0;
                while batch.envelopes.len() < max_count && consumed < original_length {
                    let mut length = [0u8; 4];
                    reader.read_exact(&mut length)?;
                    let length = u32::from_le_bytes(length) as usize;
                    if length > 4 * 1024 * 1024 || consumed + length as u64 + 16 > original_length {
                        return Err(TransportError::Buffer(
                            "invalid or truncated disk record (retained for diagnosis)".into(),
                        ));
                    }
                    let mut payload = vec![0u8; length];
                    reader.read_exact(&mut payload)?;
                    let mut signal = [0u8; 4];
                    reader.read_exact(&mut signal)?;
                    let signal = i32::from_le_bytes(signal);
                    if !(0..=7).contains(&signal) {
                        return Err(TransportError::Buffer(
                            "invalid disk signal (retained)".into(),
                        ));
                    }
                    let mut timestamp = [0u8; 8];
                    reader.read_exact(&mut timestamp)?;
                    batch.envelopes.push(Envelope {
                        signal_type: SignalType::from_i32(signal),
                        payload,
                        timestamp_unix_ns: i64::from_le_bytes(timestamp),
                        buffered: true,
                        retry_count: 1,
                    });
                    consumed += length as u64 + 16;
                }
                if consumed > 0 {
                    batch.receipts.push((path, consumed, original_length));
                }
            }
        }
        Ok(batch)
    }

    /// Commit only after a complete upstream acknowledgement. On partial legacy
    /// files atomically keep the unconsumed suffix instead of deleting its data.
    pub fn acknowledge(&self, batch: &PendingBatch) -> TransportResult<()> {
        for (path, consumed, original_length) in &batch.receipts {
            if std::fs::metadata(path)?.len() != *original_length {
                return Err(TransportError::Buffer(
                    "buffer record changed before acknowledgement".into(),
                ));
            }
            let parent = path
                .parent()
                .ok_or_else(|| TransportError::Buffer("missing buffer parent".into()))?;
            if consumed == original_length {
                std::fs::remove_file(path)?;
            } else {
                let mut original = std::fs::File::open(path)?;
                original.seek(SeekFrom::Start(*consumed))?;
                let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut output = options.open(&temporary)?;
                std::io::copy(&mut original, &mut output)?;
                output.sync_all()?;
                std::fs::rename(temporary, path)?;
            }
            sync_directory(parent)?;
        }
        self.rescan();
        Ok(())
    }

    /// Compatibility helper for callers explicitly requesting destructive drain.
    /// Transport replay must use peek/acknowledge instead.
    pub fn drain(&self, max_count: usize) -> TransportResult<Vec<Envelope>> {
        let batch = self.peek(max_count)?;
        self.acknowledge(&batch)?;
        Ok(batch.envelopes)
    }

    /// Calculate total bytes used by the buffer.
    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Recount the bytes on disk (after deletions, or at startup).
    fn rescan(&self) {
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
        self.used.store(total, Ordering::Relaxed);
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

            self.rescan();
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

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (DiskBuffer, PathBuf) {
        let path = std::env::temp_dir().join(format!("dodo-buffer-{}", uuid::Uuid::new_v4()));
        let buffer = DiskBuffer::new(&BufferConfig {
            path: path.to_string_lossy().into_owned(),
            max_size_bytes: 1024 * 1024,
            ..Default::default()
        })
        .expect("buffer");
        (buffer, path)
    }
    fn envelope(payload: u8) -> Envelope {
        Envelope {
            signal_type: SignalType::Metric,
            payload: vec![payload],
            timestamp_unix_ns: 123,
            buffered: false,
            retry_count: 0,
        }
    }
    #[test]
    fn same_timestamp_and_restart_do_not_lose_unacknowledged_records() {
        let (buffer, path) = setup();
        buffer.write(&[envelope(1), envelope(2)]).expect("write");
        let pending = buffer.peek(10).expect("peek");
        assert_eq!(pending.envelopes.len(), 2);
        // Simulate network failure/crash: drop snapshot without ACK and reopen.
        drop(pending);
        drop(buffer);
        let buffer = DiskBuffer::new(&BufferConfig {
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .expect("reopen");
        let pending = buffer.peek(10).expect("replay");
        assert_eq!(pending.envelopes.len(), 2);
        assert!(pending.envelopes.iter().all(|env| env.buffered));
        buffer.acknowledge(&pending).expect("ack");
        assert!(buffer.peek(10).expect("empty").envelopes.is_empty());
        std::fs::remove_dir_all(path).expect("cleanup");
    }
    #[test]
    fn legacy_appended_records_are_preserved_across_partial_ack() {
        let (buffer, path) = setup();
        let file = path.join("p2_metric/123_0.buf");
        let mut bytes = Vec::new();
        for payload in [1, 2, 3] {
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(payload);
            bytes.extend_from_slice(&0i32.to_le_bytes());
            bytes.extend_from_slice(&123i64.to_le_bytes());
        }
        std::fs::write(file, &bytes).expect("legacy fixture");
        for payload in [1, 2, 3] {
            let pending = buffer.peek(1).expect("legacy peek");
            assert_eq!(pending.envelopes[0].payload, vec![payload]);
            buffer.acknowledge(&pending).expect("legacy ack");
        }
        assert!(!buffer.has_data());
        std::fs::remove_dir_all(path).expect("cleanup");
    }
    #[test]
    fn a_batch_is_one_file_per_priority_and_replays_in_order() {
        let (buffer, path) = setup();
        let mut log = envelope(9);
        log.signal_type = SignalType::Log;
        let batch: Vec<Envelope> = (0..50).map(envelope).chain([log]).collect();
        assert_eq!(buffer.write(&batch).expect("write"), 51);
        assert_eq!(
            std::fs::read_dir(path.join("p2_metric"))
                .expect("dir")
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_dir(path.join("p3_log")).expect("dir").count(),
            1
        );
        let on_disk = buffer.used_bytes();
        buffer.rescan();
        assert_eq!(buffer.used_bytes(), on_disk, "cached size matches disk");
        let first = buffer.peek(20).expect("peek");
        assert_eq!(first.envelopes[0].payload, vec![0]);
        assert_eq!(first.envelopes[19].payload, vec![19]);
        buffer.acknowledge(&first).expect("partial ack");
        let rest = buffer.peek(100).expect("rest");
        assert_eq!(rest.envelopes.len(), 31);
        assert_eq!(rest.envelopes[0].payload, vec![20]);
        buffer.acknowledge(&rest).expect("ack");
        assert_eq!(buffer.used_bytes(), 0);
        std::fs::remove_dir_all(path).expect("cleanup");
    }
    #[test]
    fn truncated_records_are_retained_and_oversized_writes_do_not_evict() {
        let (buffer, path) = setup();
        buffer.write(&[envelope(7)]).expect("write");
        let mut large = envelope(8);
        large.payload = vec![0; 1024 * 1024 + 1];
        assert!(buffer.write(&[large]).is_err());
        assert_eq!(buffer.peek(10).expect("valid remains").envelopes.len(), 1);
        let corrupt = path.join("p2_metric/000.buf");
        std::fs::write(&corrupt, [1, 2]).expect("truncated");
        assert!(buffer.peek(10).is_err());
        assert!(corrupt.exists());
        std::fs::remove_dir_all(path).expect("cleanup");
    }
}
