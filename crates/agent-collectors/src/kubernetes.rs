//! Kubernetes collector — HU032.
//!
//! Detects if the agent is running inside Kubernetes (by checking for
//! `KUBERNETES_SERVICE_HOST` env var) and collects K8s-specific metrics
//! and events.
//!
//! # Full implementation plan (post-MVP)
//!
//! 1. **Pod/Container metrics**:
//!    - Use the `kube` crate with in-cluster config (service account token).
//!    - Query the Kubelet summary API (localhost:10255/stats/summary) for
//!      per-container CPU, memory, network, and filesystem metrics.
//!    - These complement cgroup metrics from the CPU/memory collectors.
//!
//! 2. **K8s events**:
//!    - Watch the K8s Events API for the node and pod's namespace.
//!    - Convert K8s events (Warning, Normal) to DoDo Event envelopes.
//!    - Filter out noise (e.g., periodic Scheduled events).
//!
//! 3. **Pod metadata enrichment**:
//!    - Read pod name, namespace, node, labels, annotations from the
//!      Downward API or K8s API.
//!    - Attach as labels to all envelopes produced by all collectors.
//!
//! 4. **Topology discovery**:
//!    - Discover Services, Endpoints, and Ingress objects.
//!    - Build service dependency graph edges.
//!
//! 5. **CRD support**:
//!    - Watch for DoDo CRDs (MonitoringPolicy, AlertRule) if installed.
//!
//! # SECURITY
//! - Agent uses a read-only ServiceAccount (NEVER writes to the cluster)
//! - Token is mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
//! - Only queries resources in the agent's own namespace + node-level APIs

use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;

/// Kubernetes collector (MVP stub with K8s detection).
pub struct KubernetesCollector {
    #[allow(dead_code)]
    platform: Arc<dyn Platform>,
    in_kubernetes: bool,
    pod_name: Option<String>,
    namespace: Option<String>,
    node_name: Option<String>,
}

impl KubernetesCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        let in_kubernetes = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();
        let pod_name = std::env::var("HOSTNAME").ok();
        let namespace = std::env::var("POD_NAMESPACE")
            .or_else(|_| std::env::var("KUBERNETES_NAMESPACE"))
            .ok();
        let node_name = std::env::var("NODE_NAME").ok();

        if in_kubernetes {
            tracing::info!(
                pod = ?pod_name,
                namespace = ?namespace,
                node = ?node_name,
                "Kubernetes environment detected"
            );
        } else {
            tracing::debug!("not running in Kubernetes (KUBERNETES_SERVICE_HOST not set)");
        }

        Self {
            platform,
            in_kubernetes,
            pod_name,
            namespace,
            node_name,
        }
    }

    /// Whether the agent detected a Kubernetes environment.
    pub fn is_kubernetes(&self) -> bool {
        self.in_kubernetes
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

            // MVP stub: return mock metadata metrics to demonstrate the
            // collector is active. Post-MVP will use the kube crate.
            let mut envelopes = Vec::new();

            let pod_label = self.pod_name.as_deref().unwrap_or("unknown");
            let ns_label = self.namespace.as_deref().unwrap_or("unknown");
            let node_label = self.node_name.as_deref().unwrap_or("unknown");

            // Report that the K8s collector is active
            envelopes.push(crate::helpers::metric_envelope(
                "kubernetes.collector.active",
                1.0,
                &[
                    ("pod", pod_label),
                    ("namespace", ns_label),
                    ("node", node_label),
                ],
                "gauge",
            ));

            // Post-MVP: query Kubelet metrics API, K8s Events API,
            // pod metadata, service topology, etc.

            Ok(envelopes)
        })
    }
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
        // In test environment, KUBERNETES_SERVICE_HOST should not be set
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = KubernetesCollector::new(platform);

        assert!(!collector.is_kubernetes());
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn name_is_kubernetes() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = KubernetesCollector::new(platform);
        assert_eq!(collector.name(), "kubernetes");
    }

    #[test]
    fn interval_is_15s() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = KubernetesCollector::new(platform);
        assert_eq!(collector.interval(), Duration::from_secs(15));
    }
}
