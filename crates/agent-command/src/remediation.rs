//! Kubernetes remediation run by the agent inside the cluster
//! (`apiVersion: dodo.io/v1`, `kind: Remediation`, via `apply_manifest`).
//!
//! The platform decides (policy, risk, approvals); the agent only executes,
//! with its own ServiceAccount, so no kubeconfig ever leaves the cluster.
//!
//! # SECURITY
//! - Off unless `DODO_ALLOW_REMEDIATION=true`.
//! - Only namespaces listed in `DODO_REMEDIATION_NAMESPACES` (comma
//!   separated); empty list = nothing allowed.
//! - Closed set of actions, each a fixed kubectl argv (no shell); names are
//!   validated as DNS labels/subdomains before kubectl is spawned.
//! - What the ServiceAccount may change is still bounded by its RBAC Role.

use std::time::Duration;

use serde_json::Value;

use crate::executor::{run_kubectl, validate_namespace, validate_resource_name};
use crate::CommandError;

const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REPLICAS: u64 = 50;

fn err(msg: impl Into<String>) -> CommandError {
    CommandError::Execution(msg.into())
}

/// kubectl argv for a Remediation spec, after every check.
pub(crate) fn argv(
    spec: &Value,
    allowed: bool,
    namespaces: &str,
) -> Result<Vec<String>, CommandError> {
    if !allowed {
        return Err(err(
            "remediation is disabled on this agent (set DODO_ALLOW_REMEDIATION=true)",
        ));
    }
    let s = |k: &str| spec.get(k).and_then(Value::as_str).unwrap_or("");
    let (action, ns, deployment) = (s("action"), s("namespace"), s("deployment"));
    validate_namespace(ns)?;
    validate_resource_name(deployment)?;
    if !namespaces
        .split(',')
        .map(str::trim)
        .any(|allowed_ns| !allowed_ns.is_empty() && allowed_ns == ns)
    {
        return Err(err(format!(
            "namespace {ns} is not in DODO_REMEDIATION_NAMESPACES"
        )));
    }
    let target = format!("deployment/{deployment}");
    let mut args: Vec<String> = match action {
        "rollout_restart" => vec!["rollout".into(), "restart".into(), target],
        "rollback" => {
            let mut a = vec!["rollout".into(), "undo".into(), target];
            if let Some(rev) = spec.get("revision").and_then(Value::as_u64) {
                a.push(format!("--to-revision={rev}"));
            }
            a
        }
        "scale" => {
            let replicas = spec
                .get("replicas")
                .and_then(Value::as_u64)
                .ok_or_else(|| err("scale needs replicas"))?;
            if replicas > MAX_REPLICAS {
                return Err(err(format!("replicas above {MAX_REPLICAS} refused")));
            }
            vec!["scale".into(), target, format!("--replicas={replicas}")]
        }
        other => return Err(err(format!("unsupported remediation action {other:?}"))),
    };
    args.extend(["-n".into(), ns.into()]);
    if spec
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        args.push("--dry-run=server".into());
    }
    Ok(args)
}

pub(crate) async fn run(spec: &Value) -> Result<String, CommandError> {
    let allowed = std::env::var("DODO_ALLOW_REMEDIATION")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let namespaces = std::env::var("DODO_REMEDIATION_NAMESPACES").unwrap_or_default();
    let args = argv(spec, allowed, &namespaces)?;
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_kubectl(std::path::Path::new("kubectl"), &refs, TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(spec: Value) -> Vec<String> {
        argv(&spec, true, "shop, other").expect("allowed")
    }

    #[test]
    fn builds_fixed_argv() {
        assert_eq!(
            ok(json!({"action": "rollout_restart", "namespace": "shop", "deployment": "api"})),
            ["rollout", "restart", "deployment/api", "-n", "shop"]
        );
        assert_eq!(
            ok(
                json!({"action": "scale", "namespace": "shop", "deployment": "api",
                      "replicas": 3, "dry_run": true})
            ),
            [
                "scale",
                "deployment/api",
                "--replicas=3",
                "-n",
                "shop",
                "--dry-run=server"
            ]
        );
        assert_eq!(
            ok(
                json!({"action": "rollback", "namespace": "shop", "deployment": "api", "revision": 4})
            ),
            [
                "rollout",
                "undo",
                "deployment/api",
                "--to-revision=4",
                "-n",
                "shop"
            ]
        );
    }

    #[test]
    fn refuses_when_disabled_or_outside_allowlist() {
        let spec = json!({"action": "rollout_restart", "namespace": "shop", "deployment": "api"});
        assert!(argv(&spec, false, "shop").is_err());
        assert!(argv(&spec, true, "").is_err());
        assert!(argv(&spec, true, "kube-system").is_err());
    }

    #[test]
    fn refuses_bad_names_actions_and_sizes() {
        for spec in [
            json!({"action": "rollout_restart", "namespace": "shop", "deployment": "--all"}),
            json!({"action": "rollout_restart", "namespace": "-n", "deployment": "api"}),
            json!({"action": "delete", "namespace": "shop", "deployment": "api"}),
            json!({"action": "scale", "namespace": "shop", "deployment": "api", "replicas": 500}),
            json!({"action": "scale", "namespace": "shop", "deployment": "api"}),
        ] {
            assert!(argv(&spec, true, "shop").is_err(), "{spec}");
        }
    }
}
