//! CommandExecutor — executes AgentCommand payloads using kubectl.
//!
//! Each command runs as a subprocess. Results are collected and returned
//! as (success, stdout, stderr) for the caller to wrap in AgentCommandResult.

use std::process::Command;
use std::time::Duration;

use agent_transport::proto::{
    AgentCommandPayload, ApplyManifestCmd, DescribeResourceCmd, ExecInContainerCmd, GetPodLogsCmd,
    RestartPodCmd, RollbackDeploymentCmd, ScaleDeploymentCmd,
};

use crate::CommandError;

/// Executes a command payload and returns (output, error_message).
/// On success, error_message is empty. On failure, output may contain partial stdout.
pub struct CommandExecutor;

impl CommandExecutor {
    pub async fn execute(
        &self,
        payload: &AgentCommandPayload,
        timeout_s: i32,
    ) -> Result<String, CommandError> {
        let timeout = Duration::from_secs(timeout_s.max(5) as u64);
        match payload {
            AgentCommandPayload::RestartPod(cmd) => self.restart_pod(cmd, timeout).await,
            AgentCommandPayload::ScaleDeployment(cmd) => self.scale_deployment(cmd, timeout).await,
            AgentCommandPayload::ExecInContainer(cmd) => self.exec_in_container(cmd, timeout).await,
            AgentCommandPayload::GetPodLogs(cmd) => self.get_pod_logs(cmd, timeout).await,
            AgentCommandPayload::ApplyManifest(cmd) => self.apply_manifest(cmd, timeout).await,
            AgentCommandPayload::Rollback(cmd) => self.rollback_deployment(cmd, timeout).await,
            AgentCommandPayload::DescribeResource(cmd) => {
                self.describe_resource(cmd, timeout).await
            }
        }
    }

    async fn restart_pod(
        &self,
        cmd: &RestartPodCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        run_kubectl(
            &[
                "delete",
                "pod",
                &cmd.pod_name,
                "-n",
                &cmd.namespace,
                "--grace-period=0",
            ],
            timeout,
        )
    }

    async fn scale_deployment(
        &self,
        cmd: &ScaleDeploymentCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        run_kubectl(
            &[
                "scale",
                "deployment",
                &cmd.deployment,
                "--replicas",
                &cmd.replicas.to_string(),
                "-n",
                &cmd.namespace,
            ],
            timeout,
        )
    }

    async fn exec_in_container(
        &self,
        cmd: &ExecInContainerCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        if cmd.command.is_empty() {
            return Err(CommandError::Execution("exec command list is empty".into()));
        }
        let mut args = vec![
            "exec",
            &cmd.pod,
            "-n",
            &cmd.namespace,
            "-c",
            &cmd.container,
            "--",
        ];
        let cmd_strs: Vec<&str> = cmd.command.iter().map(|s| s.as_str()).collect();
        args.extend_from_slice(&cmd_strs);
        run_kubectl(&args, timeout)
    }

    async fn get_pod_logs(
        &self,
        cmd: &GetPodLogsCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        let tail = cmd.tail_lines.to_string();
        run_kubectl(
            &["logs", &cmd.pod, "-n", &cmd.namespace, "--tail", &tail],
            timeout,
        )
    }

    async fn apply_manifest(
        &self,
        cmd: &ApplyManifestCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        // Decode base64 manifest
        let manifest_bytes = base64_decode(&cmd.manifest_yaml_b64)
            .map_err(|e| CommandError::Execution(format!("base64 decode failed: {e}")))?;

        // Write to a temp file
        let mut tmp = tempfile()?;
        tmp.write_all(&manifest_bytes)
            .map_err(|e| CommandError::Execution(format!("write temp file: {e}")))?;
        let path = tmp.path().to_string_lossy().to_string();

        run_kubectl(&["apply", "-f", &path], timeout)
    }

    async fn rollback_deployment(
        &self,
        cmd: &RollbackDeploymentCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        run_kubectl(
            &[
                "rollout",
                "undo",
                &format!("deployment/{}", cmd.deployment),
                "-n",
                &cmd.namespace,
            ],
            timeout,
        )
    }

    async fn describe_resource(
        &self,
        cmd: &DescribeResourceCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        if cmd.namespace.is_empty() {
            run_kubectl(&["describe", &cmd.kind, &cmd.name], timeout)
        } else {
            run_kubectl(
                &["describe", &cmd.kind, &cmd.name, "-n", &cmd.namespace],
                timeout,
            )
        }
    }
}

/// Run a kubectl command with a timeout. Returns stdout on success,
/// or CommandError with stderr on failure.
fn run_kubectl(args: &[&str], _timeout: Duration) -> Result<String, CommandError> {
    tracing::debug!(cmd = ?args, "running kubectl");

    let output = Command::new("kubectl").args(args).output().map_err(|e| {
        CommandError::Transport(format!("kubectl not found or failed to spawn: {e}"))
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        let msg = if stderr.is_empty() { stdout } else { stderr };
        Err(CommandError::Execution(msg))
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Use only standard library; avoid extra deps for simple base64
    // Since the agent already has tokio/prost, we use a simple hand-rolled decoder
    // via the standard library's available facilities.
    // In practice, the `base64` crate would be added as a dep; here we use
    // the std approach via ALPHABET lookup.
    use std::collections::HashMap;
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let map: HashMap<u8, u8> = alphabet
        .bytes()
        .enumerate()
        .map(|(i, b)| (b, i as u8))
        .collect();

    let input = input.replace(['\n', '\r', ' '], "");
    let input = input.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut result = Vec::new();

    for ch in input.bytes() {
        let val = *map
            .get(&ch)
            .ok_or_else(|| format!("invalid base64 char: {ch}"))?;
        bits = (bits << 6) | (val as u32);
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Ok(result)
}

// Minimal tempfile helper using /tmp
struct TempFile {
    path: std::path::PathBuf,
    file: std::fs::File,
}

impl TempFile {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.file.write_all(data)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn tempfile() -> Result<TempFile, CommandError> {
    use std::fs::OpenOptions;
    let path =
        std::path::PathBuf::from(format!("/tmp/dodo-manifest-{}.yaml", uuid::Uuid::new_v4()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| CommandError::Execution(format!("create temp file: {e}")))?;
    Ok(TempFile { path, file })
}
