//! Agent Command Channel — receives and executes platform commands.
//!
//! Maintains a persistent bidirectional gRPC stream with the ingestor's
//! CommandService. The platform sends AgentCommand messages; this crate
//! dispatches them to the CommandExecutor, then sends AgentCommandResult
//! back on the stream.
//!
//! Reconnects automatically with exponential backoff if the stream drops.

mod channel;
mod executor;

pub use channel::CommandChannel;
pub use executor::CommandExecutor;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("unknown command type")]
    UnknownCommand,
}

#[cfg(test)]
#[path = "../../../tests/support/network.rs"]
mod test_network;
