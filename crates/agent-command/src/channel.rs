//! CommandChannel — maintains the bidirectional gRPC stream with CommandService.
//!
//! Connects on startup, reconnects with exponential backoff on failure.
//! Reads AgentCommand from server, dispatches to CommandExecutor, sends results back.

use std::sync::Arc;
use std::time::Duration;

use agent_transport::proto::{AgentCommandResult, CommandServiceClient};
use agent_transport::tls::build_grpc_channel;
use agent_transport::TransportConfig;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

use crate::executor::CommandExecutor;
use crate::CommandError;

/// Manages the persistent bidirectional command stream.
/// Spawn via [`CommandChannel::run`] as a background task.
pub struct CommandChannel {
    agent_id: String,
    config: TransportConfig,
    executor: Arc<CommandExecutor>,
}

impl CommandChannel {
    pub fn new(agent_id: String, config: TransportConfig) -> Self {
        Self {
            agent_id,
            config,
            executor: Arc::new(CommandExecutor),
        }
    }

    /// Run the command channel loop. Reconnects automatically.
    /// Exits only when the cancellation token is triggered.
    pub async fn run(self, cancel: tokio_util::sync::CancellationToken) {
        let mut backoff = Duration::from_secs(1);
        const MAX_BACKOFF: Duration = Duration::from_secs(60);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!(agent_id = %self.agent_id, "CommandChannel shutting down");
                    return;
                }
                _ = async {} => {}
            }

            info!(agent_id = %self.agent_id, "connecting CommandStream");

            match self.connect_and_run(&cancel).await {
                Ok(()) => {
                    info!(agent_id = %self.agent_id, "CommandStream closed cleanly");
                    if cancel.is_cancelled() {
                        return;
                    }
                }
                Err(e) => {
                    if cancel.is_cancelled() {
                        return;
                    }
                    warn!(
                        agent_id = %self.agent_id,
                        error = %e,
                        backoff_s = backoff.as_secs(),
                        "CommandStream error, reconnecting"
                    );
                }
            }

            // Exponential backoff before reconnect
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn connect_and_run(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), CommandError> {
        let channel = build_grpc_channel(&self.config)
            .await
            .map_err(|e| CommandError::Transport(e.to_string()))?;

        let mut client = CommandServiceClient::new(channel);

        // Channel for result messages from executor → stream sender
        let (result_tx, result_rx) = mpsc::channel::<AgentCommandResult>(32);

        // Send a registration ping so the server learns our agent_id
        result_tx
            .send(AgentCommandResult {
                command_id: String::new(),
                agent_id: self.agent_id.clone(),
                success: true,
                output: String::new(),
                error: String::new(),
            })
            .await
            .map_err(|_| CommandError::Transport("result channel closed".into()))?;

        let outbound = ReceiverStream::new(result_rx);

        let response = client
            .command_stream(outbound)
            .await
            .map_err(|e| CommandError::Transport(e.to_string()))?;

        let mut inbound = response.into_inner();

        // Reset backoff on successful connect (done by caller via Ok return)
        info!(agent_id = %self.agent_id, "CommandStream established");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = inbound.message() => {
                    match result {
                        Ok(Some(cmd)) => {
                            let agent_id = self.agent_id.clone();
                            let executor = self.executor.clone();
                            let tx = result_tx.clone();

                            tokio::spawn(async move {
                                let command_id = cmd.command_id.clone();
                                let timeout_s = cmd.timeout_s;

                                let (success, output, error) = if let Some(ref payload) = cmd.payload {
                                    match executor.execute(payload, timeout_s).await {
                                        Ok(out) => (true, out, String::new()),
                                        Err(e) => (false, String::new(), e.to_string()),
                                    }
                                } else {
                                    (false, String::new(), "no command payload".into())
                                };

                                let result = AgentCommandResult {
                                    command_id,
                                    agent_id,
                                    success,
                                    output,
                                    error,
                                };

                                if let Err(e) = tx.send(result).await {
                                    error!(error = %e, "failed to send command result");
                                }
                            });
                        }
                        Ok(None) => {
                            info!(agent_id = %self.agent_id, "CommandStream server closed");
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(CommandError::Transport(e.to_string()));
                        }
                    }
                }
            }
        }
    }
}
