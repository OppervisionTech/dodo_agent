use crate::{loader, LocalAgentConfig};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Config watcher that polls for remote config changes.
pub struct ConfigWatcher {
    local_config_path: String,
    poll_interval_seconds: u32,
    current_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn watcher_only_publishes_valid_changes_and_stops_when_cancelled() {
        let path = std::env::temp_dir().join(format!(
            "dodo-watcher-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let file = Fixture(path);
        let mut config = LocalAgentConfig::default();
        std::fs::write(&file.0, serde_yaml::to_string(&config).unwrap()).unwrap();
        let initial = loader::config_hash(&config);
        let mut watcher = ConfigWatcher::new(file.0.to_str().unwrap().into(), 1, initial.clone());
        let (tx, mut rx) = tokio::sync::watch::channel(config.clone());
        watcher.check_for_changes(&tx).await;
        assert!(!rx.has_changed().unwrap());
        config.logging.level = "debug".into();
        std::fs::write(&file.0, serde_yaml::to_string(&config).unwrap()).unwrap();
        watcher.check_for_changes(&tx).await;
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().logging.level, "debug");
        let valid_hash = watcher.current_hash.clone();
        assert_ne!(valid_hash, initial);
        std::fs::write(&file.0, "collectors: {broken: true}").unwrap();
        watcher.check_for_changes(&tx).await;
        assert_eq!(watcher.current_hash, valid_hash);
        assert!(!rx.has_changed().unwrap());
        std::fs::write(&file.0, serde_yaml::to_string(&config).unwrap()).unwrap();
        drop(rx);
        config.logging.level = "error".into();
        std::fs::write(&file.0, serde_yaml::to_string(&config).unwrap()).unwrap();
        watcher.check_for_changes(&tx).await;
        for interval in [0, 1] {
            let mut watcher =
                ConfigWatcher::new(file.0.to_str().unwrap().into(), interval, String::new());
            let cancel = CancellationToken::new();
            cancel.cancel();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                watcher.run(tx.clone(), cancel),
            )
            .await
            .unwrap();
        }
    }
}

impl ConfigWatcher {
    pub fn new(
        local_config_path: String,
        poll_interval_seconds: u32,
        initial_hash: String,
    ) -> Self {
        Self {
            local_config_path,
            poll_interval_seconds,
            current_hash: initial_hash,
        }
    }

    /// Run the config watcher loop.
    /// Sends new config through the channel when changes are detected.
    /// If poll_interval_seconds is 0, config pull is disabled and this returns immediately.
    pub async fn run(
        &mut self,
        config_tx: tokio::sync::watch::Sender<LocalAgentConfig>,
        cancel_token: CancellationToken,
    ) {
        if self.poll_interval_seconds == 0 {
            debug!("config_pull_interval_seconds = 0, config watcher disabled");
            cancel_token.cancelled().await;
            return;
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            self.poll_interval_seconds as u64,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("config watcher shutting down");
                    return;
                }
                _ = interval.tick() => {
                    self.check_for_changes(&config_tx).await;
                }
            }
        }
    }

    async fn check_for_changes(
        &mut self,
        config_tx: &tokio::sync::watch::Sender<LocalAgentConfig>,
    ) {
        // For MVP: check local file changes (remote config pull via gRPC comes
        // when transport is fully integrated)
        match loader::load_from_file(&self.local_config_path) {
            Ok(new_config) => {
                let new_hash = loader::config_hash(&new_config);
                if new_hash == self.current_hash {
                    debug!(hash = %self.current_hash, "config unchanged");
                    return;
                }

                info!(
                    old_hash = %self.current_hash,
                    new_hash = %new_hash,
                    "config change detected, applying hot reload"
                );

                // Check for fields that require restart
                if let Ok(current_config) = loader::load_from_file(&self.local_config_path) {
                    if current_config.endpoint.address != new_config.endpoint.address {
                        warn!("endpoint.address changed — requires restart, skipping");
                    }
                    if current_config.tls.ca_cert_path != new_config.tls.ca_cert_path
                        || current_config.tls.client_cert_path != new_config.tls.client_cert_path
                    {
                        warn!("TLS config changed — requires restart, skipping");
                    }
                }

                self.current_hash = new_hash;
                if config_tx.send(new_config).is_err() {
                    error!("failed to send config update — receivers dropped");
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to reload config, keeping current");
            }
        }
    }
}
