//! CommandExecutor — executes AgentCommand payloads using kubectl.
//!
//! Each command runs as a subprocess. Results are collected and returned
//! as (success, stdout, stderr) for the caller to wrap in AgentCommandResult.

use std::time::Duration;

use agent_transport::proto::{
    AgentCommandPayload, ApplyManifestCmd, DescribeResourceCmd, ExecInContainerCmd, GetPodLogsCmd,
    RestartPodCmd, RollbackDeploymentCmd, ScaleDeploymentCmd,
};

use crate::CommandError;

/// Executes a command payload and returns (output, error_message).
/// On success, error_message is empty. On failure, output may contain partial stdout.
pub struct CommandExecutor {
    kubectl: std::path::PathBuf,
}

impl Default for CommandExecutor {
    fn default() -> Self {
        Self {
            kubectl: "kubectl".into(),
        }
    }
}

impl CommandExecutor {
    pub async fn execute(
        &self,
        payload: &AgentCommandPayload,
        timeout_s: i32,
    ) -> Result<String, CommandError> {
        validate_payload(payload)?;
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
            &self.kubectl,
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
        .await
    }

    async fn scale_deployment(
        &self,
        cmd: &ScaleDeploymentCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        run_kubectl(
            &self.kubectl,
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
        .await
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
        run_kubectl(&self.kubectl, &args, timeout).await
    }

    async fn get_pod_logs(
        &self,
        cmd: &GetPodLogsCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        let tail = cmd.tail_lines.to_string();
        run_kubectl(
            &self.kubectl,
            &["logs", &cmd.pod, "-n", &cmd.namespace, "--tail", &tail],
            timeout,
        )
        .await
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

        run_kubectl(&self.kubectl, &["apply", "-f", &path], timeout).await
    }

    async fn rollback_deployment(
        &self,
        cmd: &RollbackDeploymentCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        run_kubectl(
            &self.kubectl,
            &[
                "rollout",
                "undo",
                &format!("deployment/{}", cmd.deployment),
                "-n",
                &cmd.namespace,
            ],
            timeout,
        )
        .await
    }

    async fn describe_resource(
        &self,
        cmd: &DescribeResourceCmd,
        timeout: Duration,
    ) -> Result<String, CommandError> {
        let mut args = vec!["describe", &cmd.kind];
        // AI Core uses an empty name to enumerate pods in a namespace.
        // Omit it instead of passing an empty resource-name argument.
        if !cmd.name.is_empty() {
            args.push(&cmd.name);
        }
        if !cmd.namespace.is_empty() {
            args.extend_from_slice(&["-n", &cmd.namespace]);
        }
        run_kubectl(&self.kubectl, &args, timeout).await
    }
}

/// Identity fields become kubectl arguments, so passing them without a shell
/// does not by itself prevent option injection (for example pod="--all").
/// Validate the identity before spawning; exec's command array is intentionally
/// left untouched because it follows kubectl's explicit `--` separator.
fn validate_payload(payload: &AgentCommandPayload) -> Result<(), CommandError> {
    match payload {
        AgentCommandPayload::RestartPod(cmd) => {
            validate_namespace(&cmd.namespace)?;
            validate_resource_name(&cmd.pod_name)
        }
        AgentCommandPayload::ScaleDeployment(cmd) => {
            validate_namespace(&cmd.namespace)?;
            validate_resource_name(&cmd.deployment)
        }
        AgentCommandPayload::ExecInContainer(cmd) => {
            validate_namespace(&cmd.namespace)?;
            validate_resource_name(&cmd.pod)?;
            // An empty container selects the pod's default container, as in
            // kubectl itself; an explicitly named container is a DNS label.
            if !cmd.container.is_empty() && !valid_dns_label(&cmd.container, 63) {
                return Err(CommandError::Execution("invalid container name".into()));
            }
            Ok(())
        }
        AgentCommandPayload::GetPodLogs(cmd) => {
            validate_namespace(&cmd.namespace)?;
            validate_resource_name(&cmd.pod)
        }
        AgentCommandPayload::ApplyManifest(_) => Ok(()),
        AgentCommandPayload::Rollback(cmd) => {
            validate_namespace(&cmd.namespace)?;
            validate_resource_name(&cmd.deployment)
        }
        AgentCommandPayload::DescribeResource(cmd) => {
            // Empty namespace is intentional for cluster-scoped resources.
            if !cmd.namespace.is_empty() {
                validate_namespace(&cmd.namespace)?;
            }
            // Read-only enumeration may omit the name. RBAC resource names
            // follow path-segment rules rather than DNS-only resource rules.
            if !cmd.name.is_empty() && !valid_describe_name(&cmd.name) {
                return Err(CommandError::Execution("invalid resource name".into()));
            }
            // Accept kinds/aliases and qualified forms such as Deployment,
            // deployments.apps and jobs.v1.batch, including CRD API groups.
            // A resource (63) + version (63) + group (253) needs at most 381
            // characters with the two separators.
            if cmd.kind.len() > 381
                || !cmd
                    .kind
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                || !cmd.kind.split('.').all(valid_kind_segment)
            {
                return Err(CommandError::Execution("invalid resource kind".into()));
            }
            Ok(())
        }
    }
}

fn validate_namespace(namespace: &str) -> Result<(), CommandError> {
    if valid_dns_label(namespace, 63) {
        Ok(())
    } else {
        Err(CommandError::Execution("invalid namespace".into()))
    }
}

fn validate_resource_name(name: &str) -> Result<(), CommandError> {
    // Kubernetes DNS-subdomain names are at most 253 characters. The API's
    // subdomain check bounds the complete name rather than individual labels.
    if name.len() <= 253 && name.split('.').all(|label| valid_dns_label(label, 253)) {
        Ok(())
    } else {
        Err(CommandError::Execution("invalid resource name".into()))
    }
}

fn valid_dns_label(value: &str, max_length: usize) -> bool {
    let bytes = value.as_bytes();
    let alphanumeric = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= max_length
        && bytes.first().is_some_and(alphanumeric)
        && bytes.last().is_some_and(alphanumeric)
        && bytes.iter().all(|b| alphanumeric(b) || *b == b'-')
}

fn valid_kind_segment(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

fn valid_describe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('-')
        && !matches!(value, "." | "..")
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@' | b'+')
        })
}

/// Run a kubectl command with a timeout. Returns stdout on success,
/// or CommandError with stderr on failure.
async fn run_kubectl(
    program: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CommandError> {
    tracing::debug!(cmd = ?args, "running kubectl");

    let mut command = tokio::process::Command::new(program);
    command.args(args).kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| CommandError::Execution("kubectl deadline exceeded".into()))?
        .map_err(|e| {
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
    let path = std::env::temp_dir().join(format!("dodo-manifest-{}.yaml", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|e| CommandError::Execution(format!("create temp file: {e}")))?;
    Ok(TempFile { path, file })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // Tests that write a script and then exec it must not overlap: a fork in a
    // parallel test can inherit the still-open write fd, and exec then fails
    // with ETXTBSY ("Text file busy").
    static EXEC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn executable(
        directory: &crate::test_network::Directory,
        name: &str,
        body: &str,
    ) -> std::path::PathBuf {
        let path = directory.0.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn kubernetes_identity_validation_preserves_supported_names_and_qualified_kinds() {
        for value in ["default", "team-1", "0", &"a".repeat(63)] {
            assert!(validate_namespace(value).is_ok(), "{value}");
        }
        for value in ["", "--all", "a.b", "Name", "a_1", &"a".repeat(64)] {
            assert!(validate_namespace(value).is_err(), "{value}");
        }
        for value in [
            "pod-1",
            "release.v1",
            "ip-10-20-30-40.ec2.internal",
            &"a".repeat(253),
        ] {
            assert!(validate_resource_name(value).is_ok(), "{value}");
        }
        for value in [
            "",
            ".pod",
            "pod.",
            "pod..name",
            "pod/name",
            "-pod",
            "pod-",
            "POD",
            "pód",
            &"a".repeat(254),
        ] {
            assert!(validate_resource_name(value).is_err(), "{value}");
        }
        for kind in ["pod", "Deployment", "deployments.apps", "jobs.v1.batch"] {
            assert!(validate_payload(&AgentCommandPayload::DescribeResource(
                DescribeResourceCmd {
                    kind: kind.into(),
                    namespace: String::new(),
                    name: "resource-1".into(),
                }
            ))
            .is_ok());
        }
        for kind in ["", "1pod", ".pod", "pod.", "pod..apps", &"a".repeat(382)] {
            assert!(validate_payload(&AgentCommandPayload::DescribeResource(
                DescribeResourceCmd {
                    kind: kind.into(),
                    namespace: String::new(),
                    name: "resource-1".into(),
                }
            ))
            .is_err());
        }
    }

    #[tokio::test]
    async fn flag_shaped_and_malformed_identity_fields_never_spawn_kubectl() {
        let _exec = EXEC_LOCK.lock().await;
        let directory = crate::test_network::Directory::new();
        let kubectl = executable(
            &directory,
            "kubectl",
            "printf invoked > \"$0.invoked\"; printf '%s\\n' \"$@\"",
        );
        let marker = directory.0.join("kubectl.invoked");
        let executor = CommandExecutor { kubectl };
        for value in [
            "--all",
            "--raw=/api/v1/pods",
            "bad name",
            "pod\n--all",
            "pod; echo injected",
        ] {
            let payloads = [
                AgentCommandPayload::RestartPod(RestartPodCmd {
                    namespace: value.into(),
                    pod_name: "pod".into(),
                }),
                AgentCommandPayload::RestartPod(RestartPodCmd {
                    namespace: "ns".into(),
                    pod_name: value.into(),
                }),
                AgentCommandPayload::ScaleDeployment(ScaleDeploymentCmd {
                    namespace: value.into(),
                    deployment: "app".into(),
                    replicas: 1,
                }),
                AgentCommandPayload::ScaleDeployment(ScaleDeploymentCmd {
                    namespace: "ns".into(),
                    deployment: value.into(),
                    replicas: 1,
                }),
                AgentCommandPayload::ExecInContainer(ExecInContainerCmd {
                    namespace: value.into(),
                    pod: "pod".into(),
                    container: "app".into(),
                    command: vec!["true".into()],
                }),
                AgentCommandPayload::ExecInContainer(ExecInContainerCmd {
                    namespace: "ns".into(),
                    pod: value.into(),
                    container: "app".into(),
                    command: vec!["true".into()],
                }),
                AgentCommandPayload::ExecInContainer(ExecInContainerCmd {
                    namespace: "ns".into(),
                    pod: "pod".into(),
                    container: value.into(),
                    command: vec!["true".into()],
                }),
                AgentCommandPayload::GetPodLogs(GetPodLogsCmd {
                    namespace: value.into(),
                    pod: "pod".into(),
                    tail_lines: 1,
                }),
                AgentCommandPayload::GetPodLogs(GetPodLogsCmd {
                    namespace: "ns".into(),
                    pod: value.into(),
                    tail_lines: 1,
                }),
                AgentCommandPayload::Rollback(RollbackDeploymentCmd {
                    namespace: value.into(),
                    deployment: "app".into(),
                }),
                AgentCommandPayload::Rollback(RollbackDeploymentCmd {
                    namespace: "ns".into(),
                    deployment: value.into(),
                }),
                AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                    namespace: "ns".into(),
                    kind: value.into(),
                    name: "pod".into(),
                }),
                AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                    namespace: "ns".into(),
                    kind: "pod".into(),
                    name: value.into(),
                }),
                AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                    namespace: value.into(),
                    kind: "pod".into(),
                    name: "pod".into(),
                }),
            ];
            for payload in payloads {
                assert!(executor.execute(&payload, 1).await.is_err(), "{payload:?}");
                assert!(!marker.exists(), "invalid identity must not spawn kubectl");
            }
        }

        // Options and URLs inside the explicitly separated exec command are
        // literal argv, not identity fields; default-container selection stays
        // supported. This also proves the marker executable itself works.
        let output = executor
            .execute(
                &AgentCommandPayload::ExecInContainer(ExecInContainerCmd {
                    namespace: "team-1".into(),
                    pod: "pod-1".into(),
                    container: String::new(),
                    command: vec![
                        "curl".into(),
                        "--silent".into(),
                        "https://example.invalid/path?x=1&y=2".into(),
                    ],
                }),
                1,
            )
            .await
            .unwrap();
        assert!(marker.exists());
        assert_eq!(
            output,
            "exec\npod-1\n-n\nteam-1\n-c\n\n--\ncurl\n--silent\nhttps://example.invalid/path?x=1&y=2"
        );
    }

    #[tokio::test]
    async fn describe_preserves_pod_enumeration_and_rbac_names_without_relaxing_writes() {
        let _exec = EXEC_LOCK.lock().await;
        let directory = crate::test_network::Directory::new();
        let kubectl = executable(
            &directory,
            "kubectl",
            "printf invoked > \"$0.invoked\"; printf '%s\\n' \"$@\"",
        );
        let marker = directory.0.join("kubectl.invoked");
        let executor = CommandExecutor { kubectl };
        for (kind, namespace, name, expected) in [
            // Matches AI Core SolutionTools::_list_k8s_pods exactly.
            ("pods", "default", "", "describe\npods\n-n\ndefault"),
            (
                "ClusterRole",
                "",
                "system:discovery",
                "describe\nClusterRole\nsystem:discovery",
            ),
        ] {
            let result = executor
                .execute(
                    &AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                        kind: kind.into(),
                        namespace: namespace.into(),
                        name: name.into(),
                    }),
                    1,
                )
                .await
                .unwrap();
            assert_eq!(result, expected);
            assert!(marker.exists());
            std::fs::remove_file(&marker).unwrap();
        }

        for name in [
            "--all",
            "--raw=/api/v1/pods",
            ".",
            "..",
            "../pod",
            "pods/name",
            "name%2Fpath",
            "pod\n--all",
            "bad name",
        ] {
            assert!(executor
                .execute(
                    &AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                        kind: "pods".into(),
                        namespace: "default".into(),
                        name: name.into(),
                    }),
                    1,
                )
                .await
                .is_err());
            assert!(
                !marker.exists(),
                "invalid read identity must not spawn kubectl"
            );
        }

        // Empty and RBAC-style names are read-only exceptions. Commands that
        // can change workloads still require an explicit DNS resource name.
        for name in ["", "system:discovery", "--all"] {
            for payload in [
                AgentCommandPayload::RestartPod(RestartPodCmd {
                    namespace: "default".into(),
                    pod_name: name.into(),
                }),
                AgentCommandPayload::ScaleDeployment(ScaleDeploymentCmd {
                    namespace: "default".into(),
                    deployment: name.into(),
                    replicas: 1,
                }),
                AgentCommandPayload::ExecInContainer(ExecInContainerCmd {
                    namespace: "default".into(),
                    pod: name.into(),
                    container: "app".into(),
                    command: vec!["true".into()],
                }),
                AgentCommandPayload::Rollback(RollbackDeploymentCmd {
                    namespace: "default".into(),
                    deployment: name.into(),
                }),
            ] {
                assert!(executor.execute(&payload, 1).await.is_err(), "{payload:?}");
                assert!(
                    !marker.exists(),
                    "invalid write identity must not spawn kubectl"
                );
            }
        }
    }

    #[tokio::test]
    async fn every_payload_preserves_argument_boundaries_without_a_real_cluster() {
        let _exec = EXEC_LOCK.lock().await;
        let directory = crate::test_network::Directory::new();
        let kubectl = executable(&directory, "kubectl", "if [ \"$1\" = apply ]; then printf 'path=%s\\n' \"$3\"; cat \"$3\"; else printf '%s\\n' \"$@\"; fi");
        let executor = CommandExecutor { kubectl };
        let cases = [
            (
                AgentCommandPayload::RestartPod(RestartPodCmd {
                    namespace: "ns".into(),
                    pod_name: "pod".into(),
                }),
                "delete\npod\npod\n-n\nns\n--grace-period=0",
            ),
            (
                AgentCommandPayload::ScaleDeployment(ScaleDeploymentCmd {
                    namespace: "ns".into(),
                    deployment: "app".into(),
                    replicas: 3,
                }),
                "scale\ndeployment\napp\n--replicas\n3\n-n\nns",
            ),
            (
                AgentCommandPayload::ExecInContainer(ExecInContainerCmd {
                    namespace: "ns".into(),
                    pod: "pod".into(),
                    container: "app".into(),
                    command: vec!["printf".into(), "literal; echo injected".into()],
                }),
                "exec\npod\n-n\nns\n-c\napp\n--\nprintf\nliteral; echo injected",
            ),
            (
                AgentCommandPayload::GetPodLogs(GetPodLogsCmd {
                    namespace: "ns".into(),
                    pod: "pod".into(),
                    tail_lines: 25,
                }),
                "logs\npod\n-n\nns\n--tail\n25",
            ),
            (
                AgentCommandPayload::Rollback(RollbackDeploymentCmd {
                    namespace: "ns".into(),
                    deployment: "app".into(),
                }),
                "rollout\nundo\ndeployment/app\n-n\nns",
            ),
            (
                AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                    kind: "node".into(),
                    namespace: String::new(),
                    name: "n".into(),
                }),
                "describe\nnode\nn",
            ),
            (
                AgentCommandPayload::DescribeResource(DescribeResourceCmd {
                    kind: "pod".into(),
                    namespace: "ns".into(),
                    name: "p".into(),
                }),
                "describe\npod\np\n-n\nns",
            ),
        ];
        for (payload, expected) in cases {
            assert_eq!(executor.execute(&payload, 1).await.unwrap(), expected);
        }
        let applied = executor
            .execute(
                &AgentCommandPayload::ApplyManifest(ApplyManifestCmd {
                    manifest_yaml_b64: "a2luZDogUG9kCg==".into(),
                }),
                1,
            )
            .await
            .unwrap();
        let (path, manifest) = applied.split_once('\n').unwrap();
        assert_eq!(manifest, "kind: Pod");
        assert!(!std::path::Path::new(path.strip_prefix("path=").unwrap()).exists());
        assert!(executor
            .execute(
                &AgentCommandPayload::ExecInContainer(ExecInContainerCmd::default()),
                0
            )
            .await
            .is_err());
        assert!(executor
            .execute(
                &AgentCommandPayload::ApplyManifest(ApplyManifestCmd {
                    manifest_yaml_b64: "!invalid".into()
                }),
                0
            )
            .await
            .is_err());
        assert_eq!(
            CommandExecutor::default().kubectl,
            std::path::Path::new("kubectl")
        );
    }

    #[tokio::test]
    async fn process_failures_deadlines_and_private_manifest_cleanup_are_visible() {
        let _exec = EXEC_LOCK.lock().await;
        let directory = crate::test_network::Directory::new();
        for (name, body, expected) in [
            ("stderr", "echo private-error >&2; exit 2", "private-error"),
            ("stdout", "echo output-error; exit 1", "output-error"),
        ] {
            let program = executable(&directory, name, body);
            let error = run_kubectl(&program, &[], Duration::from_secs(1))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
        assert!(matches!(
            run_kubectl(&directory.0.join("missing"), &[], Duration::from_secs(1)).await,
            Err(CommandError::Transport(_))
        ));
        let program = executable(
            &directory,
            "slow",
            "printf '%s' \"$$\" > \"$1\"; exec sleep 20",
        );
        let pid_file = directory.0.join("owned-child.pid");
        let started = std::time::Instant::now();
        let error = run_kubectl(
            &program,
            &[pid_file.to_str().unwrap()],
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(pid > 0);
        tokio::time::timeout(Duration::from_secs(2), async {
            // SAFETY: signal 0 only queries the owned fake subprocess's PID.
            while unsafe { libc::kill(pid, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed-out owned process must be killed and reaped");
        let path;
        {
            let mut file = tempfile().unwrap();
            file.write_all(b"synthetic manifest").unwrap();
            path = file.path().to_path_buf();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"synthetic manifest");
        }
        assert!(!path.exists());
        assert_eq!(base64_decode("aG Vs\nbG8=\r").unwrap(), b"hello");
    }
}
