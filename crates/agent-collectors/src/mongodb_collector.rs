//! MongoDB collector — HU262.
//!
//! Collects database metrics via `serverStatus` command using the MongoDB driver.
//! Activated only when `DODO_AGENT_MONGODB_URI` env var is set.
//!
//! # SECURITY
//! - URI is NEVER logged (contains credentials)
//! - Requires `clusterMonitor` role (read-only)
//! - Only serverStatus command (no data access)

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::client_config::optional_target_from_env;
use crate::delta::counter_delta;
use crate::helpers;

const COLLECT_INTERVAL_SECS: u64 = 15;
const URI_ENV_VAR: &str = "DODO_AGENT_MONGODB_URI";

// ---------------------------------------------------------------------------
// Previous state for delta calculations
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PreviousState {
    insert: i64,
    query: i64,
    update: i64,
    delete: i64,
    bytes_in: i64,
    bytes_out: i64,
}

// ---------------------------------------------------------------------------
// MongodbCollector
// ---------------------------------------------------------------------------

pub struct MongodbCollector {
    host_id: String,
    uri: Option<String>,
    #[cfg(feature = "mongodb")]
    client: Mutex<Option<mongodb::Client>>,
    previous: Mutex<Option<PreviousState>>,
}

impl MongodbCollector {
    pub fn new(host_id: String) -> Self {
        let uri = optional_target_from_env(URI_ENV_VAR, "MongoDB", "URI");

        Self {
            host_id,
            uri,
            #[cfg(feature = "mongodb")]
            client: Mutex::new(None),
            previous: Mutex::new(None),
        }
    }

    #[cfg(feature = "mongodb")]
    async fn ensure_connection(&self) -> Result<(), CollectorError> {
        let mut client_guard = self.client.lock().await;
        if client_guard.is_some() {
            return Ok(());
        }

        let uri = self
            .uri
            .as_ref()
            .ok_or_else(|| CollectorError::Failed("no URI configured".into()))?;

        let options = mongodb::options::ClientOptions::parse(uri)
            .await
            .map_err(|e| CollectorError::Failed(format!("MongoDB URI parse failed: {e}")))?;

        let client = mongodb::Client::with_options(options)
            .map_err(|e| CollectorError::Failed(format!("MongoDB client creation failed: {e}")))?;

        *client_guard = Some(client);
        info!("MongoDB connection established");
        Ok(())
    }

    #[cfg(feature = "mongodb")]
    async fn collect_impl(&self) -> Result<Vec<Envelope>, CollectorError> {
        if self.uri.is_none() {
            return Ok(Vec::new());
        }

        if let Err(e) = self.ensure_connection().await {
            debug!(error = %e, "MongoDB not available, skipping");
            *self.client.lock().await = None;
            return Ok(Vec::new());
        }

        let client_guard = self.client.lock().await;
        let client = client_guard.as_ref().expect("connection ensured above");

        let db = client.database("admin");
        let cmd = mongodb::bson::doc! { "serverStatus": 1 };

        let status = match db.run_command(cmd).await {
            Ok(doc) => doc,
            Err(e) => {
                warn!(error = %e, "MongoDB serverStatus failed");
                drop(client_guard);
                *self.client.lock().await = None;
                return Ok(Vec::new());
            }
        };

        let mut envelopes = Vec::new();

        // Detect replica set for labels
        let repl_set = status
            .get_document("repl")
            .ok()
            .and_then(|r| r.get_str("setName").ok())
            .map(|s| s.to_string());

        // `service` matches the db.system / peer.service name OTEL spans use, so
        // the metric worker files these under the same service id as the
        // topology node (/services/{name} timeline).
        let mut base_labels: Vec<(&str, &str)> = vec![("host_id", &self.host_id), ("service", "mongodb")];
        let repl_set_str;
        if let Some(ref rs) = repl_set {
            repl_set_str = rs.clone();
            base_labels.push(("replica_set", &repl_set_str));
        }

        // -- Connections --
        if let Ok(connections) = status.get_document("connections") {
            let current = connections.get_i32("current").unwrap_or(0) as f64;
            let available = connections.get_i32("available").unwrap_or(0) as f64;

            envelopes.push(helpers::metric_envelope(
                "mongodb.connections.current",
                current,
                &base_labels,
                "gauge",
            ));
            envelopes.push(helpers::metric_envelope(
                "mongodb.connections.available",
                available,
                &base_labels,
                "gauge",
            ));
        }

        // -- Opcounters (delta) --
        if let Ok(opcounters) = status.get_document("opcounters") {
            let insert = get_i64_from_doc(opcounters, "insert");
            let query = get_i64_from_doc(opcounters, "query");
            let update = get_i64_from_doc(opcounters, "update");
            let delete = get_i64_from_doc(opcounters, "delete");

            let mut prev_guard = self.previous.lock().await;
            if let Some(prev) = prev_guard.as_ref() {
                envelopes.push(helpers::metric_envelope(
                    "mongodb.opcounters.insert",
                    counter_delta(insert, prev.insert),
                    &base_labels,
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "mongodb.opcounters.query",
                    counter_delta(query, prev.query),
                    &base_labels,
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "mongodb.opcounters.update",
                    counter_delta(update, prev.update),
                    &base_labels,
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "mongodb.opcounters.delete",
                    counter_delta(delete, prev.delete),
                    &base_labels,
                    "counter",
                ));
            } else {
                debug!("MongoDB: first sample, deltas available next tick");
            }

            // Network bytes (also delta)
            let bytes_in = status
                .get_document("network")
                .ok()
                .and_then(|n| n.get_i64("bytesIn").ok())
                .unwrap_or(0);
            let bytes_out = status
                .get_document("network")
                .ok()
                .and_then(|n| n.get_i64("bytesOut").ok())
                .unwrap_or(0);

            if let Some(prev) = prev_guard.as_ref() {
                envelopes.push(helpers::metric_envelope(
                    "mongodb.network.bytes_in",
                    counter_delta(bytes_in, prev.bytes_in),
                    &base_labels,
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "mongodb.network.bytes_out",
                    counter_delta(bytes_out, prev.bytes_out),
                    &base_labels,
                    "counter",
                ));
            }

            *prev_guard = Some(PreviousState {
                insert,
                query,
                update,
                delete,
                bytes_in,
                bytes_out,
            });
        }

        // -- Memory --
        if let Ok(mem) = status.get_document("mem") {
            let resident = mem.get_i32("resident").unwrap_or(0) as f64;
            let virtual_mb = mem.get_i32("virtual").unwrap_or(0) as f64;

            envelopes.push(helpers::metric_envelope(
                "mongodb.memory.resident_mb",
                resident,
                &base_labels,
                "gauge",
            ));
            envelopes.push(helpers::metric_envelope(
                "mongodb.memory.virtual_mb",
                virtual_mb,
                &base_labels,
                "gauge",
            ));
        }

        // -- Replication lag --
        if repl_set.is_some() {
            if let Ok(repl) = status.get_document("repl") {
                // Lag is computed from optime differences on replicas
                if let (Ok(my_time), Ok(primary_time)) = (
                    repl.get_document("lastAppliedOpTime"),
                    repl.get_document("optimeDate"),
                ) {
                    // Simplified: check if we can get lag from the status
                    let lag = my_time
                        .get_i64("ts")
                        .ok()
                        .and_then(|my_ts| {
                            primary_time
                                .get_i64("ts")
                                .ok()
                                .map(|p_ts| (p_ts.saturating_sub(my_ts)).max(0) as f64)
                        })
                        .unwrap_or(0.0);

                    envelopes.push(helpers::metric_envelope(
                        "mongodb.replication.lag_seconds",
                        lag,
                        &base_labels,
                        "gauge",
                    ));
                }
            }
        }

        // -- Global lock --
        if let Ok(global_lock) = status.get_document("globalLock") {
            if let Ok(active_clients) = global_lock.get_document("activeClients") {
                let total = active_clients.get_i32("total").unwrap_or(0) as f64;
                envelopes.push(helpers::metric_envelope(
                    "mongodb.globallock.active_clients.total",
                    total,
                    &base_labels,
                    "gauge",
                ));
            }
        }

        // -- Cursors --
        if let Ok(metrics_doc) = status.get_document("metrics") {
            if let Ok(cursor) = metrics_doc.get_document("cursor") {
                if let Ok(open) = cursor.get_document("open") {
                    let total = open.get_i32("total").unwrap_or(0) as f64;
                    envelopes.push(helpers::metric_envelope(
                        "mongodb.cursors.open",
                        total,
                        &base_labels,
                        "gauge",
                    ));
                }
            }
        }

        Ok(envelopes)
    }

    #[cfg(not(feature = "mongodb"))]
    async fn collect_impl(&self) -> Result<Vec<Envelope>, CollectorError> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "mongodb")]
fn get_i64_from_doc(doc: &mongodb::bson::Document, key: &str) -> i64 {
    doc.get_i64(key)
        .or_else(|_| doc.get_i32(key).map(|v| v as i64))
        .unwrap_or(0)
}

impl Collector for MongodbCollector {
    fn name(&self) -> &str {
        "mongodb"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Metric
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(COLLECT_INTERVAL_SECS)
    }

    fn collect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>> {
        Box::pin(self.collect_impl())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_env_var_name() {
        assert_eq!(URI_ENV_VAR, "DODO_AGENT_MONGODB_URI");
    }

    #[test]
    fn interval_is_15s() {
        let collector = MongodbCollector::new("test-host".to_string());
        assert_eq!(collector.interval(), Duration::from_secs(15));
    }

    #[test]
    fn name_is_mongodb() {
        let collector = MongodbCollector::new("test-host".to_string());
        assert_eq!(collector.name(), "mongodb");
    }

    #[tokio::test]
    async fn inactive_without_uri() {
        std::env::remove_var(URI_ENV_VAR);
        let collector = MongodbCollector::new("test-host".to_string());
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }
}
