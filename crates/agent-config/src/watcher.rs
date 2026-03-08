use crate::{loader, LocalAgentConfig};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Config watcher that polls for remote config changes.
pub struct ConfigWatcher {
    local_config_path: String,
    poll_interval_seconds: u32,
    current_hash: String,
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
    pub async fn run(
        &mut self,
        config_tx: tokio::sync::watch::Sender<LocalAgentConfig>,
        cancel_token: CancellationToken,
    ) {
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
