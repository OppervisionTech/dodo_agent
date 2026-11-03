#![cfg(target_os = "linux")]

#[path = "support/network.rs"]
mod network;

use agent_transport::proto::{SubmitBatchRequest, SubmitBatchResponse};
use prost::Message;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn child(config: &std::path::Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_aegis-agent"));
    command
        .env("AEGIS_CONFIG", config)
        .env_remove("DODO_ENDPOINT")
        .env_remove("DODO_ENROLLMENT_ENDPOINT")
        .env_remove("DODO_API_KEY")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

#[tokio::test]
async fn executable_forwards_heartbeat_shuts_down_and_restarts_with_same_identity() {
    let directory = network::Directory::new();
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let server = network::grpc(move |request| {
        if request.uri().path() != "/dodo.proto.v1.IngestorService/SubmitBatch" {
            return (12, vec![]);
        }
        let batch = SubmitBatchRequest::decode(&request.body()[5..]).unwrap();
        let count = batch.envelopes.len();
        captured.lock().unwrap().extend(batch.envelopes);
        (
            0,
            SubmitBatchResponse {
                accepted: count as u32,
                rejected: 0,
                errors: vec![],
            }
            .encode_to_vec(),
        )
    })
    .await;
    let config = directory.0.join("agent.yaml");
    let agent_id = directory.0.join("agent-id");
    std::fs::write(
        &config,
        format!(
            r#"
endpoint:
  address: '{}'
  timeout_ms: 2000
  retry_max: 0
tls:
  enabled: false
buffer:
  path: '{}'
  max_size_bytes: 1048576
  flush_interval_ms: 50
  max_batch_size: 10
agent_id_path: '{}'
config_pull_interval_seconds: 1
collectors:
  - name: heartbeat
    enabled: true
    interval_seconds: 1
"#,
            server.address,
            directory.0.join("buffer").display(),
            agent_id.display()
        ),
    )
    .unwrap();
    let mut identity = None;
    let mut host_identity = None;
    for _ in 0..2 {
        let baseline = received.lock().unwrap().len();
        let mut process = child(&config).spawn().unwrap();
        let ready = tokio::time::timeout(Duration::from_secs(20), async {
            while received.lock().unwrap().len() <= baseline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if ready.is_err() {
            let _ = process.kill().await;
            let output = process.wait_with_output().await.unwrap();
            panic!(
                "child failed readiness: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let current = std::fs::read_to_string(&agent_id).unwrap();
        assert!(uuid::Uuid::parse_str(&current).is_ok());
        if let Some(expected) = &identity {
            assert_eq!(&current, expected);
        }
        identity = Some(current.clone());
        let pid = i32::try_from(process.id().unwrap()).unwrap();
        assert!(pid > 0);
        // SAFETY: checked positive PID from the still-owned Child above;
        // never a process group. Child has no graceful SIGTERM API on Unix.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let output = tokio::time::timeout(Duration::from_secs(20), process.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let records = received.lock().unwrap();
        assert_eq!(records[baseline].agent_id, current);
        assert_eq!(records[baseline].signal_type, 6);
        assert_eq!(records[baseline].compression, 1);
        assert!(!records[baseline].payload.is_empty());
        assert!(!records[baseline].host_id.is_empty());
        if let Some(expected) = &host_identity {
            assert_eq!(&records[baseline].host_id, expected);
        }
        host_identity = Some(records[baseline].host_id.clone());
    }
}

#[tokio::test]
async fn executable_rejects_malformed_configuration_before_creating_identity() {
    let directory = network::Directory::new();
    let config = directory.0.join("invalid.yaml");
    std::fs::write(&config, "collectors: {wrong: true}").unwrap();
    let output = tokio::time::timeout(Duration::from_secs(10), child(&config).output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(!directory.0.join("agent-id").exists());
    assert!(!output.stderr.is_empty());
}
