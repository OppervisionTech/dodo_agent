//! Kubernetes collector — HU032, HU278.
//!
//! Detects if the agent is running inside Kubernetes (by checking for
//! `KUBERNETES_SERVICE_HOST`) and, through the in-cluster API with the
//! agent's read-only ServiceAccount, reports:
//!
//! 1. **Rollouts** — a Deployment, StatefulSet or DaemonSet whose container
//!    images change becomes a `deploy.rollout` event (routed by the ingestor
//!    to `deploy-events`). Aegis correlates incidents with these deploys and
//!    rolls back to the previous version. Every agent of the DaemonSet sees
//!    the same rollout; the backend deduplicates on (workload, revision).
//! 2. **Pod resources on this node** — requests, limits and usage (from
//!    metrics.k8s.io) per container, the input for container rightsizing.
//! 3. **This node** — allocatable CPU/memory and its instance type, so cost
//!    can be attributed to workloads.
//!
//! # SECURITY
//! - Read-only ServiceAccount (see the chart's ClusterRole): get/list only.
//! - Token and CA are read from the standard service-account mount; the API
//!   server's certificate is verified against that CA (no system roots).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;
use serde_json::{json, Value};

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// Pod/node resource metrics every Nth tick (15s ticks → once a minute).
const RESOURCES_EVERY: u64 = 4;
const WORKLOAD_KINDS: [(&str, &str); 3] = [
    ("Deployment", "/apis/apps/v1/deployments?limit=500"),
    ("StatefulSet", "/apis/apps/v1/statefulsets?limit=500"),
    ("DaemonSet", "/apis/apps/v1/daemonsets?limit=500"),
];

/// Minimal in-cluster API client: bearer token + cluster CA.
struct K8sApi {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl K8sApi {
    fn in_cluster() -> Option<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let token = std::fs::read_to_string(format!("{SA_DIR}/token")).ok()?;
        let ca = std::fs::read(format!("{SA_DIR}/ca.crt")).ok()?;
        let cert = reqwest::Certificate::from_pem(&ca).ok()?;
        let client = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Some(Self {
            base: format!("https://{host}:{port}"),
            token: token.trim().to_string(),
            client,
        })
    }

    async fn get(&self, path: &str) -> Result<Value, CollectorError> {
        let resp = self
            .client
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CollectorError::Failed(format!("k8s api {path}: {e}")))?;
        if !resp.status().is_success() {
            return Err(CollectorError::Failed(format!(
                "k8s api {path}: HTTP {}",
                resp.status()
            )));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| CollectorError::Failed(format!("k8s api {path}: {e}")))
    }
}

/// What the collector remembers about a workload between scans.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkloadState {
    images: Vec<String>,
    revision: String,
}

/// A workload as seen in one scan.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkloadSnapshot {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub service: String,
    pub images: Vec<String>,
    pub revision: String,
}

impl WorkloadSnapshot {
    fn key(&self) -> String {
        format!("{}/{}/{}", self.kind, self.namespace, self.name)
    }
}

/// Kubernetes collector.
pub struct KubernetesCollector {
    #[allow(dead_code)]
    platform: Arc<dyn Platform>,
    in_kubernetes: bool,
    pod_name: Option<String>,
    namespace: Option<String>,
    node_name: Option<String>,
    api: Option<K8sApi>,
    /// key → last seen state; None until the first scan primed it (the
    /// first scan never emits: an agent restart is not a rollout).
    workloads: Mutex<Option<HashMap<String, WorkloadState>>>,
    ticks: AtomicU64,
}

impl KubernetesCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        let in_kubernetes = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();
        let pod_name = std::env::var("HOSTNAME").ok();
        let namespace = std::env::var("POD_NAMESPACE")
            .or_else(|_| std::env::var("KUBERNETES_NAMESPACE"))
            .ok();
        let node_name = std::env::var("NODE_NAME").ok();
        let api = if in_kubernetes {
            K8sApi::in_cluster()
        } else {
            None
        };

        if in_kubernetes {
            tracing::info!(
                pod = ?pod_name,
                namespace = ?namespace,
                node = ?node_name,
                api = api.is_some(),
                "Kubernetes environment detected"
            );
            if api.is_none() {
                tracing::warn!("in-cluster API unavailable (no service-account token/CA mounted)");
            }
        } else {
            tracing::debug!("not running in Kubernetes (KUBERNETES_SERVICE_HOST not set)");
        }

        Self {
            platform,
            in_kubernetes,
            pod_name,
            namespace,
            node_name,
            api,
            workloads: Mutex::new(None),
            ticks: AtomicU64::new(0),
        }
    }

    /// Whether the agent detected a Kubernetes environment.
    pub fn is_kubernetes(&self) -> bool {
        self.in_kubernetes
    }

    async fn scan_workloads(&self, api: &K8sApi) -> Vec<Envelope> {
        let mut current = Vec::new();
        for (kind, path) in WORKLOAD_KINDS {
            match api.get(path).await {
                Ok(list) => current.extend(workload_snapshots(kind, &list)),
                Err(e) => {
                    tracing::debug!(error = %e, kind, "workload list failed");
                    return Vec::new(); // partial scans would look like rollouts later
                }
            }
        }
        let mut guard = match self.workloads.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let changed = match guard.as_ref() {
            Some(prev) => diff_rollouts(prev, &current),
            None => Vec::new(),
        };
        let next: HashMap<String, WorkloadState> = current
            .iter()
            .map(|w| {
                (
                    w.key(),
                    WorkloadState {
                        images: w.images.clone(),
                        revision: w.revision.clone(),
                    },
                )
            })
            .collect();
        let previous = guard.replace(next).unwrap_or_default();
        drop(guard);

        changed
            .into_iter()
            .map(|w| rollout_envelope(&w, previous.get(&w.key())))
            .collect()
    }

    async fn scan_resources(&self, api: &K8sApi, node: &str) -> Vec<Envelope> {
        let mut out = Vec::new();
        let node_obj = api.get(&format!("/api/v1/nodes/{node}")).await.ok();
        let instance_type = node_obj
            .as_ref()
            .and_then(|n| label(n, "node.kubernetes.io/instance-type"))
            .unwrap_or_default();
        if let Some(n) = node_obj.as_ref() {
            out.extend(node_metrics(n, node, &instance_type));
        }
        let pods = match api
            .get(&format!(
                "/api/v1/pods?fieldSelector=spec.nodeName%3D{node}&limit=500"
            ))
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "pod list failed");
                return out;
            }
        };
        // metrics-server may not be installed: requests/limits still report.
        let usage = api.get("/apis/metrics.k8s.io/v1beta1/pods").await.ok();
        out.extend(pod_resource_metrics(
            &pods,
            usage.as_ref(),
            node,
            &instance_type,
        ));
        out
    }
}

impl Collector for KubernetesCollector {
    fn name(&self) -> &str {
        "kubernetes"
    }

    fn signal_type(&self) -> SignalType {
        // Produces both Metric and Event envelopes; we report Metric as primary.
        SignalType::Metric
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(15)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            if !self.in_kubernetes {
                // Not in K8s — silently return empty (not an error).
                return Ok(Vec::new());
            }

            let pod_label = self.pod_name.as_deref().unwrap_or("unknown");
            let ns_label = self.namespace.as_deref().unwrap_or("unknown");
            let node_label = self.node_name.as_deref().unwrap_or("unknown");

            let mut envelopes = vec![crate::helpers::metric_envelope(
                "kubernetes.collector.active",
                1.0,
                &[
                    ("pod", pod_label),
                    ("namespace", ns_label),
                    ("node", node_label),
                ],
                "gauge",
            )];

            let Some(api) = self.api.as_ref() else {
                return Ok(envelopes);
            };
            envelopes.extend(self.scan_workloads(api).await);

            let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
            if tick % RESOURCES_EVERY == 0 {
                if let Some(node) = self.node_name.as_deref() {
                    envelopes.extend(self.scan_resources(api, node).await);
                }
            }
            Ok(envelopes)
        })
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (unit tested)
// ---------------------------------------------------------------------------

/// Workloads in a Deployment/StatefulSet/DaemonSet list response.
pub(crate) fn workload_snapshots(kind: &str, list: &Value) -> Vec<WorkloadSnapshot> {
    let Some(items) = list.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let meta = item.get("metadata")?;
            let name = meta.get("name")?.as_str()?.to_string();
            let namespace = meta
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let images: Vec<String> = item
                .pointer("/spec/template/spec/containers")
                .and_then(Value::as_array)
                .map(|cs| {
                    cs.iter()
                        .filter_map(|c| c.get("image").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let revision = match kind {
                "Deployment" => meta
                    .pointer("/annotations/deployment.kubernetes.io~1revision")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                "StatefulSet" => item
                    .pointer("/status/updateRevision")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                _ => meta
                    .get("generation")
                    .and_then(Value::as_i64)
                    .map(|g| g.to_string())
                    .unwrap_or_default(),
            };
            let service = label(item, "app.kubernetes.io/name")
                .or_else(|| label(item, "app"))
                .unwrap_or_else(|| name.clone());
            Some(WorkloadSnapshot {
                kind: kind.to_string(),
                namespace,
                name,
                service,
                images,
                revision,
            })
        })
        .collect()
}

/// Workloads whose images changed since the previous scan (new workloads
/// are not rollouts of anything).
pub(crate) fn diff_rollouts(
    prev: &HashMap<String, WorkloadState>,
    current: &[WorkloadSnapshot],
) -> Vec<WorkloadSnapshot> {
    current
        .iter()
        .filter(|w| prev.get(&w.key()).is_some_and(|p| p.images != w.images))
        .cloned()
        .collect()
}

/// The version an image reference carries: its tag, or a short digest.
pub(crate) fn image_version(image: &str) -> String {
    if let Some((_, digest)) = image.split_once('@') {
        let hex = digest.split_once(':').map_or(digest, |(_, h)| h);
        return hex.chars().take(12).collect();
    }
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.rsplit_once(':') {
        Some((_, tag)) if !tag.is_empty() => tag.to_string(),
        _ => "latest".to_string(),
    }
}

fn rollout_envelope(w: &WorkloadSnapshot, previous: Option<&WorkloadState>) -> Envelope {
    let image = w.images.first().cloned().unwrap_or_default();
    let version = image_version(&image);
    let previous_image = previous
        .and_then(|p| p.images.first().cloned())
        .unwrap_or_default();
    let summary = format!(
        "{} {}/{} rolled out {}",
        w.kind, w.namespace, w.name, version
    );
    crate::helpers::event_envelope(
        "deploy.rollout",
        &summary,
        json!({
            "service": w.service,
            "namespace": w.namespace,
            "workload": w.name,
            "kind": w.kind,
            "revision": w.revision,
            "image": image,
            "version": version,
            "previous_image": previous_image,
            "previous_version": if previous_image.is_empty() { String::new() } else { image_version(&previous_image) },
        }),
    )
}

/// CPU quantity ("250m", "2", "1.5") in cores.
pub(crate) fn parse_cpu(q: &str) -> Option<f64> {
    let q = q.trim();
    if let Some(n) = q.strip_suffix('n') {
        return n.parse::<f64>().ok().map(|v| v / 1e9);
    }
    if let Some(u) = q.strip_suffix('u') {
        return u.parse::<f64>().ok().map(|v| v / 1e6);
    }
    if let Some(m) = q.strip_suffix('m') {
        return m.parse::<f64>().ok().map(|v| v / 1000.0);
    }
    q.parse::<f64>().ok()
}

/// Memory quantity ("512Mi", "1G", "1048576") in bytes.
pub(crate) fn parse_memory(q: &str) -> Option<f64> {
    let q = q.trim();
    const UNITS: [(&str, f64); 12] = [
        ("Ki", 1024.0),
        ("Mi", 1048576.0),
        ("Gi", 1073741824.0),
        ("Ti", 1099511627776.0),
        ("Pi", 1125899906842624.0),
        ("Ei", 1152921504606846976.0),
        ("k", 1e3),
        ("K", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
        ("P", 1e15),
    ];
    for (suffix, mult) in UNITS {
        if let Some(n) = q.strip_suffix(suffix) {
            return n.parse::<f64>().ok().map(|v| v * mult);
        }
    }
    q.parse::<f64>().ok()
}

fn label(obj: &Value, key: &str) -> Option<String> {
    obj.pointer("/metadata/labels")
        .and_then(|l| l.get(key))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The workload a pod belongs to — (kind, name): its owner, minus the
/// ReplicaSet hash (a ReplicaSet's pods belong to a Deployment).
fn pod_workload(pod: &Value) -> (String, String) {
    let owner = pod
        .pointer("/metadata/ownerReferences/0")
        .and_then(|o| Some((o.get("kind")?.as_str()?, o.get("name")?.as_str()?)));
    match owner {
        Some(("ReplicaSet", name)) => (
            "Deployment".to_string(),
            name.rsplit_once('-')
                .map_or(name, |(base, _)| base)
                .to_string(),
        ),
        Some((kind, name)) => (kind.to_string(), name.to_string()),
        None => (
            "Pod".to_string(),
            pod.pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
    }
}

fn node_metrics(node_obj: &Value, node: &str, instance_type: &str) -> Vec<Envelope> {
    let zone = label(node_obj, "topology.kubernetes.io/zone").unwrap_or_default();
    let labels = [
        ("node", node),
        ("instance_type", instance_type),
        ("zone", zone.as_str()),
    ];
    let mut out = Vec::new();
    let cpu = node_obj
        .pointer("/status/allocatable/cpu")
        .and_then(Value::as_str)
        .and_then(parse_cpu);
    let mem = node_obj
        .pointer("/status/allocatable/memory")
        .and_then(Value::as_str)
        .and_then(parse_memory);
    if let Some(v) = cpu {
        out.push(crate::helpers::metric_envelope(
            "k8s.node.cpu.allocatable_cores",
            v,
            &labels,
            "gauge",
        ));
    }
    if let Some(v) = mem {
        out.push(crate::helpers::metric_envelope(
            "k8s.node.memory.allocatable_bytes",
            v,
            &labels,
            "gauge",
        ));
    }
    out
}

/// Requests, limits and (when metrics-server answers) usage for every
/// container of the pods on this node.
pub(crate) fn pod_resource_metrics(
    pods: &Value,
    usage: Option<&Value>,
    node: &str,
    instance_type: &str,
) -> Vec<Envelope> {
    // (namespace, pod, container) → (cpu cores, memory bytes)
    type Usage = HashMap<(String, String, String), (Option<f64>, Option<f64>)>;
    let mut used: Usage = HashMap::new();
    if let Some(items) = usage.and_then(|u| u.get("items")).and_then(Value::as_array) {
        for pm in items {
            let ns = pm
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("");
            let pod = pm
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            for c in pm
                .get("containers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let cname = c.get("name").and_then(Value::as_str).unwrap_or("");
                let cpu = c
                    .pointer("/usage/cpu")
                    .and_then(Value::as_str)
                    .and_then(parse_cpu);
                let mem = c
                    .pointer("/usage/memory")
                    .and_then(Value::as_str)
                    .and_then(parse_memory);
                used.insert((ns.into(), pod.into(), cname.into()), (cpu, mem));
            }
        }
    }

    let mut out = Vec::new();
    for pod in pods
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if pod.pointer("/status/phase").and_then(Value::as_str) != Some("Running") {
            continue;
        }
        let ns = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("");
        let pod_name = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let (workload_kind, workload) = pod_workload(pod);
        for c in pod
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let cname = c.get("name").and_then(Value::as_str).unwrap_or("");
            let labels = [
                ("namespace", ns),
                ("pod", pod_name),
                ("container", cname),
                ("workload", workload.as_str()),
                ("workload_kind", workload_kind.as_str()),
                ("node", node),
                ("instance_type", instance_type),
            ];
            let mut emit = |name: &str, v: Option<f64>| {
                if let Some(v) = v {
                    out.push(crate::helpers::metric_envelope(name, v, &labels, "gauge"));
                }
            };
            let res = c.get("resources");
            let q = |path: &str| res.and_then(|r| r.pointer(path)).and_then(Value::as_str);
            emit(
                "k8s.container.cpu.request_cores",
                q("/requests/cpu").and_then(parse_cpu),
            );
            emit(
                "k8s.container.cpu.limit_cores",
                q("/limits/cpu").and_then(parse_cpu),
            );
            emit(
                "k8s.container.memory.request_bytes",
                q("/requests/memory").and_then(parse_memory),
            );
            emit(
                "k8s.container.memory.limit_bytes",
                q("/limits/memory").and_then(parse_memory),
            );
            if let Some((cpu, mem)) =
                used.get(&(ns.to_string(), pod_name.to_string(), cname.to_string()))
            {
                emit("k8s.container.cpu.usage_cores", *cpu);
                emit("k8s.container.memory.usage_bytes", *mem);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agent_platform::common::MockPlatform;

    #[tokio::test]
    async fn returns_empty_outside_k8s() {
        // Ensure we're not in K8s for this test.
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::new());
        let collector = KubernetesCollector::new(platform);
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn name_is_kubernetes() {
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::new());
        let collector = KubernetesCollector::new(platform);
        assert_eq!(collector.name(), "kubernetes");
    }

    #[test]
    fn interval_is_15s() {
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::new());
        let collector = KubernetesCollector::new(platform);
        assert_eq!(collector.interval(), Duration::from_secs(15));
    }

    fn deployments(image: &str, revision: &str) -> Value {
        json!({"items": [{
            "metadata": {
                "name": "checkout-api", "namespace": "prod",
                "labels": {"app.kubernetes.io/name": "checkout-api"},
                "annotations": {"deployment.kubernetes.io/revision": revision}
            },
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": image}]}}}
        }]})
    }

    #[test]
    fn snapshots_read_images_revision_and_service() {
        let w = workload_snapshots("Deployment", &deployments("reg/checkout:v4.21", "7"));
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].service, "checkout-api");
        assert_eq!(w[0].images, vec!["reg/checkout:v4.21".to_string()]);
        assert_eq!(w[0].revision, "7");
    }

    #[test]
    fn image_change_is_a_rollout_new_workload_is_not() {
        let before = workload_snapshots("Deployment", &deployments("reg/checkout:v4.20", "6"));
        let prev: HashMap<String, WorkloadState> = before
            .iter()
            .map(|w| {
                (
                    w.key(),
                    WorkloadState {
                        images: w.images.clone(),
                        revision: w.revision.clone(),
                    },
                )
            })
            .collect();
        let after = workload_snapshots("Deployment", &deployments("reg/checkout:v4.21", "7"));
        assert_eq!(diff_rollouts(&prev, &after).len(), 1);
        assert!(diff_rollouts(&prev, &before).is_empty());
        assert!(diff_rollouts(&HashMap::new(), &after).is_empty());
    }

    #[test]
    fn rollout_event_carries_versions() {
        let w = &workload_snapshots("Deployment", &deployments("reg/checkout:v4.21", "7"))[0];
        let prev = WorkloadState {
            images: vec!["reg/checkout:v4.20".into()],
            revision: "6".into(),
        };
        let env = rollout_envelope(w, Some(&prev));
        let payload: Value = serde_json::from_slice(&env.payload).unwrap();
        assert_eq!(payload["event_type"], "deploy.rollout");
        assert_eq!(payload["details"]["version"], "v4.21");
        assert_eq!(payload["details"]["previous_version"], "v4.20");
        assert_eq!(payload["details"]["service"], "checkout-api");
    }

    #[test]
    fn image_versions() {
        assert_eq!(image_version("registry:5000/team/checkout:v4.21"), "v4.21");
        assert_eq!(image_version("checkout"), "latest");
        assert_eq!(image_version("registry:5000/checkout"), "latest");
        assert_eq!(
            image_version("checkout@sha256:abcdef0123456789ffff"),
            "abcdef012345"
        );
    }

    #[test]
    fn quantities() {
        assert_eq!(parse_cpu("250m"), Some(0.25));
        assert_eq!(parse_cpu("2"), Some(2.0));
        assert_eq!(parse_cpu("150000000n"), Some(0.15));
        assert_eq!(parse_memory("512Mi"), Some(536870912.0));
        assert_eq!(parse_memory("1G"), Some(1e9));
        assert_eq!(parse_memory("1024"), Some(1024.0));
    }

    #[test]
    fn pod_resources_join_requests_and_usage() {
        let pods = json!({"items": [{
            "metadata": {"name": "checkout-api-7d9f8-abcde", "namespace": "prod",
                         "ownerReferences": [{"kind": "ReplicaSet", "name": "checkout-api-7d9f8"}]},
            "status": {"phase": "Running"},
            "spec": {"containers": [{"name": "app", "resources": {
                "requests": {"cpu": "1", "memory": "2Gi"}, "limits": {"cpu": "2"}}}]}
        }]});
        let usage = json!({"items": [{
            "metadata": {"name": "checkout-api-7d9f8-abcde", "namespace": "prod"},
            "containers": [{"name": "app", "usage": {"cpu": "120m", "memory": "300Mi"}}]
        }]});
        let envs = pod_resource_metrics(&pods, Some(&usage), "node-1", "m5.large");
        // cpu req, cpu limit, mem req, cpu usage, mem usage (no memory limit)
        assert_eq!(envs.len(), 5);
        assert!(envs.iter().all(|e| e.signal_type == SignalType::Metric));
        assert_eq!(
            pod_workload(&pods["items"][0]),
            ("Deployment".to_string(), "checkout-api".to_string())
        );
    }
}
