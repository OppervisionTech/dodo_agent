//! Inventory collector — HU028.
//!
//! Runs on first boot and then hourly. Collects comprehensive host
//! inventory: OS info, cloud metadata, network interfaces, installed
//! packages, system services, and local users.
//!
//! SECURITY: NEVER includes password hashes, SSH keys, or env vars.
//! All user data is limited to username, UID, groups, and shell.

use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;

use crate::helpers::inventory_envelope;

/// Collects comprehensive host inventory for the CMDB.
pub struct InventoryCollector {
    platform: Arc<dyn Platform>,
}

impl InventoryCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self { platform }
    }
}

impl Collector for InventoryCollector {
    fn name(&self) -> &str {
        "inventory"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Inventory
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(3600)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();

            // ------------------------------------------------------------------
            // Host information
            // ------------------------------------------------------------------
            let info = self.platform.info()?;
            envelopes.push(inventory_envelope(
                "host",
                serde_json::json!({
                    "hostname": info.hostname,
                    "os_family": info.os_family,
                    "os_version": info.os_version,
                    "kernel_version": info.kernel_version,
                    "architecture": info.architecture,
                    "machine_id": info.machine_id,
                    "cpu_count_logical": info.cpu_count_logical,
                    "cpu_count_physical": info.cpu_count_physical,
                    "total_memory_bytes": info.total_memory_bytes,
                    "boot_time_unix": info.boot_time_unix,
                }),
            ));

            // ------------------------------------------------------------------
            // Platform capabilities
            // ------------------------------------------------------------------
            match self.platform.capabilities() {
                Ok(caps) => {
                    envelopes.push(inventory_envelope(
                        "capabilities",
                        serde_json::json!({
                            "ebpf_available": caps.ebpf_available,
                            "container_detected": caps.container_detected,
                            "cloud_detected": caps.cloud_detected,
                            "kernel_version_major": caps.kernel_version_major,
                            "kernel_version_minor": caps.kernel_version_minor,
                        }),
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read platform capabilities");
                }
            }

            // ------------------------------------------------------------------
            // Cloud metadata (optional)
            // ------------------------------------------------------------------
            match self.platform.cloud_info() {
                Ok(Some(cloud)) => {
                    envelopes.push(inventory_envelope(
                        "cloud",
                        serde_json::json!({
                            "provider": cloud.provider,
                            "region": cloud.region,
                            "instance_type": cloud.instance_type,
                            "instance_id": cloud.instance_id,
                            "vpc_id": cloud.vpc_id,
                        }),
                    ));
                }
                Ok(None) => {
                    tracing::debug!("no cloud metadata available");
                }
                Err(e) => {
                    tracing::debug!(error = %e, "cloud metadata detection failed");
                }
            }

            // ------------------------------------------------------------------
            // Network interfaces
            // ------------------------------------------------------------------
            match self.platform.network_interfaces() {
                Ok(interfaces) => {
                    let ifaces_json: Vec<serde_json::Value> = interfaces
                        .iter()
                        .map(|iface| {
                            serde_json::json!({
                                "name": iface.name,
                                "mac": iface.mac,
                                "ipv4": iface.ipv4,
                                "ipv6": iface.ipv6,
                                "mtu": iface.mtu,
                            })
                        })
                        .collect();

                    envelopes.push(inventory_envelope(
                        "network_interfaces",
                        serde_json::json!({ "interfaces": ifaces_json }),
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read network interfaces");
                }
            }

            // ------------------------------------------------------------------
            // Installed packages
            // ------------------------------------------------------------------
            match self.platform.packages() {
                Ok(packages) => {
                    if !packages.is_empty() {
                        let pkgs_json: Vec<serde_json::Value> = packages
                            .iter()
                            .map(|pkg| {
                                serde_json::json!({
                                    "name": pkg.name,
                                    "version": pkg.version,
                                    "manager": pkg.manager,
                                })
                            })
                            .collect();

                        envelopes.push(inventory_envelope(
                            "packages",
                            serde_json::json!({
                                "count": packages.len(),
                                "packages": pkgs_json,
                            }),
                        ));
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to read installed packages");
                }
            }

            // ------------------------------------------------------------------
            // System services
            // ------------------------------------------------------------------
            match self.platform.services() {
                Ok(services) => {
                    if !services.is_empty() {
                        let svcs_json: Vec<serde_json::Value> = services
                            .iter()
                            .map(|svc| {
                                serde_json::json!({
                                    "name": svc.name,
                                    "status": svc.status,
                                    "enabled": svc.enabled,
                                })
                            })
                            .collect();

                        envelopes.push(inventory_envelope(
                            "services",
                            serde_json::json!({
                                "count": services.len(),
                                "services": svcs_json,
                            }),
                        ));
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to read system services");
                }
            }

            // ------------------------------------------------------------------
            // Local users (SECURITY: no password hashes, no SSH keys, no env vars)
            // ------------------------------------------------------------------
            match self.platform.users() {
                Ok(users) => {
                    if !users.is_empty() {
                        let users_json: Vec<serde_json::Value> = users
                            .iter()
                            .map(|u| {
                                serde_json::json!({
                                    "username": u.username,
                                    "uid": u.uid,
                                    "groups": u.groups,
                                    "shell": u.shell,
                                    // SECURITY: Never include password hashes, SSH keys,
                                    // home directory contents, or environment variables.
                                })
                            })
                            .collect();

                        envelopes.push(inventory_envelope(
                            "users",
                            serde_json::json!({
                                "count": users.len(),
                                "users": users_json,
                            }),
                        ));
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "failed to read local users");
                }
            }

            tracing::info!(envelopes = envelopes.len(), "inventory collection complete");

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
    async fn collects_host_inventory() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = InventoryCollector::new(platform);

        let envelopes = collector.collect().await.unwrap();
        assert!(!envelopes.is_empty());

        // Check that host inventory is present
        let has_host = envelopes.iter().any(|e| {
            let v: serde_json::Value = serde_json::from_slice(&e.payload).unwrap_or_default();
            v["inventory_type"].as_str() == Some("host")
        });
        assert!(has_host);
    }

    #[tokio::test]
    async fn all_envelopes_are_inventory_type() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = InventoryCollector::new(platform);

        let envelopes = collector.collect().await.unwrap();
        for env in &envelopes {
            assert_eq!(env.signal_type, SignalType::Inventory);
        }
    }

    #[test]
    fn interval_is_one_hour() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = InventoryCollector::new(platform);
        assert_eq!(collector.interval(), Duration::from_secs(3600));
    }
}
