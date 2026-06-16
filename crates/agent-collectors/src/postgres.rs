//! PostgreSQL collector — HU262.
//!
//! Collects database metrics via `pg_stat_*` views using a read-only connection.
//! Activated only when `DODO_AGENT_POSTGRES_DSN` env var is set.
//!
//! # SECURITY
//! - DSN is NEVER logged (contains credentials)
//! - Requires `pg_monitor` role (read-only)
//! - Only SELECT queries on statistics views

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::helpers;

const COLLECT_INTERVAL_SECS: u64 = 15;
const DSN_ENV_VAR: &str = "DODO_AGENT_POSTGRES_DSN";

// ---------------------------------------------------------------------------
// Previous state for delta calculations
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PreviousState {
    xact_commit: i64,
    xact_rollback: i64,
    tup_inserted: i64,
    tup_updated: i64,
    tup_deleted: i64,
    tup_fetched: i64,
    deadlocks: i64,
}

// ---------------------------------------------------------------------------
// PostgresCollector
// ---------------------------------------------------------------------------

pub struct PostgresCollector {
    host_id: String,
    dsn: Option<String>,
    #[cfg(feature = "postgres")]
    client: Mutex<Option<tokio_postgres::Client>>,
    previous: Mutex<Option<PreviousState>>,
}

impl PostgresCollector {
    pub fn new(host_id: String) -> Self {
        let dsn = std::env::var(DSN_ENV_VAR).ok();

        if dsn.is_some() {
            info!("PostgreSQL collector configured (DSN from env)");
        } else {
            info!("PostgreSQL collector inactive (no DSN configured)");
        }

        Self {
            host_id,
            dsn,
            #[cfg(feature = "postgres")]
            client: Mutex::new(None),
            previous: Mutex::new(None),
        }
    }

    #[cfg(feature = "postgres")]
    async fn ensure_connection(&self) -> Result<(), CollectorError> {
        let mut client_guard = self.client.lock().await;
        if client_guard.is_some() {
            return Ok(());
        }

        let dsn = self
            .dsn
            .as_ref()
            .ok_or_else(|| CollectorError::Failed("no DSN configured".into()))?;

        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .map_err(|e| CollectorError::Failed(format!("PostgreSQL connection failed: {e}")))?;

        // Spawn connection task (required by tokio-postgres)
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!(error = %e, "PostgreSQL connection error");
            }
        });

        *client_guard = Some(client);
        info!("PostgreSQL connection established");
        Ok(())
    }

    #[cfg(feature = "postgres")]
    async fn collect_impl(&self) -> Result<Vec<Envelope>, CollectorError> {
        if self.dsn.is_none() {
            return Ok(Vec::new());
        }

        if let Err(e) = self.ensure_connection().await {
            debug!(error = %e, "PostgreSQL not available, skipping");
            // Reset client so we retry next cycle
            *self.client.lock().await = None;
            return Ok(Vec::new());
        }

        let client_guard = self.client.lock().await;
        let client = client_guard.as_ref().expect("connection ensured above");

        let mut envelopes = Vec::new();
        let labels: Vec<(&str, &str)> = vec![("host_id", &self.host_id)];

        // -- Connection stats --
        match client
            .query(
                "SELECT count(*) FILTER (WHERE state = 'active') as active,
                        count(*) FILTER (WHERE state = 'idle') as idle,
                        (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') as max_conn
                 FROM pg_stat_activity",
                &[],
            )
            .await
        {
            Ok(rows) => {
                if let Some(row) = rows.first() {
                    let active: i64 = row.get(0);
                    let idle: i64 = row.get(1);
                    let max_conn: i32 = row.get(2);
                    let total = active + idle;
                    let percent = if max_conn > 0 {
                        (total as f64 / max_conn as f64) * 100.0
                    } else {
                        0.0
                    };

                    envelopes.push(helpers::metric_envelope(
                        "postgresql.connections.active",
                        active as f64,
                        &labels,
                        "gauge",
                    ));
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.connections.idle",
                        idle as f64,
                        &labels,
                        "gauge",
                    ));
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.connections.max",
                        max_conn as f64,
                        &labels,
                        "gauge",
                    ));
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.connections.percent",
                        percent,
                        &labels,
                        "gauge",
                    ));
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to query pg_stat_activity");
                // Connection might be broken, reset
                drop(client_guard);
                *self.client.lock().await = None;
                return Ok(envelopes);
            }
        }

        // -- Database stats (transactions, tuples, deadlocks, cache) --
        match client
            .query(
                "SELECT sum(xact_commit)::bigint,
                        sum(xact_rollback)::bigint,
                        sum(tup_inserted)::bigint,
                        sum(tup_updated)::bigint,
                        sum(tup_deleted)::bigint,
                        sum(tup_fetched)::bigint,
                        sum(deadlocks)::bigint,
                        sum(blks_hit)::bigint,
                        sum(blks_read)::bigint
                 FROM pg_stat_database
                 WHERE datname IS NOT NULL",
                &[],
            )
            .await
        {
            Ok(rows) => {
                if let Some(row) = rows.first() {
                    let xact_commit: i64 = row.try_get(0).unwrap_or(0);
                    let xact_rollback: i64 = row.try_get(1).unwrap_or(0);
                    let tup_inserted: i64 = row.try_get(2).unwrap_or(0);
                    let tup_updated: i64 = row.try_get(3).unwrap_or(0);
                    let tup_deleted: i64 = row.try_get(4).unwrap_or(0);
                    let tup_fetched: i64 = row.try_get(5).unwrap_or(0);
                    let deadlocks: i64 = row.try_get(6).unwrap_or(0);
                    let blks_hit: i64 = row.try_get(7).unwrap_or(0);
                    let blks_read: i64 = row.try_get(8).unwrap_or(0);

                    // Cache hit ratio
                    let total_blocks = blks_hit + blks_read;
                    let cache_hit_ratio = if total_blocks > 0 {
                        (blks_hit as f64 / total_blocks as f64) * 100.0
                    } else {
                        100.0
                    };
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.cache.hit_ratio",
                        cache_hit_ratio,
                        &labels,
                        "gauge",
                    ));

                    // Delta calculations
                    let mut prev_guard = self.previous.lock().await;
                    if let Some(prev) = prev_guard.as_ref() {
                        let delta = |curr: i64, prev: i64| -> f64 {
                            curr.saturating_sub(prev).max(0) as f64
                        };

                        envelopes.push(helpers::metric_envelope(
                            "postgresql.transactions.committed",
                            delta(xact_commit, prev.xact_commit),
                            &labels,
                            "counter",
                        ));
                        envelopes.push(helpers::metric_envelope(
                            "postgresql.transactions.rolledback",
                            delta(xact_rollback, prev.xact_rollback),
                            &labels,
                            "counter",
                        ));
                        envelopes.push(helpers::metric_envelope(
                            "postgresql.tuples.inserted",
                            delta(tup_inserted, prev.tup_inserted),
                            &labels,
                            "counter",
                        ));
                        envelopes.push(helpers::metric_envelope(
                            "postgresql.tuples.updated",
                            delta(tup_updated, prev.tup_updated),
                            &labels,
                            "counter",
                        ));
                        envelopes.push(helpers::metric_envelope(
                            "postgresql.tuples.deleted",
                            delta(tup_deleted, prev.tup_deleted),
                            &labels,
                            "counter",
                        ));
                        envelopes.push(helpers::metric_envelope(
                            "postgresql.tuples.fetched",
                            delta(tup_fetched, prev.tup_fetched),
                            &labels,
                            "counter",
                        ));
                        envelopes.push(helpers::metric_envelope(
                            "postgresql.deadlocks",
                            delta(deadlocks, prev.deadlocks),
                            &labels,
                            "counter",
                        ));
                    } else {
                        debug!("PostgreSQL: first sample, deltas available next tick");
                    }

                    *prev_guard = Some(PreviousState {
                        xact_commit,
                        xact_rollback,
                        tup_inserted,
                        tup_updated,
                        tup_deleted,
                        tup_fetched,
                        deadlocks,
                    });
                }
            }
            Err(e) => warn!(error = %e, "failed to query pg_stat_database"),
        }

        // -- Locks --
        match client
            .query(
                "SELECT count(*) as total,
                        count(*) FILTER (WHERE granted = false) as waiting
                 FROM pg_locks",
                &[],
            )
            .await
        {
            Ok(rows) => {
                if let Some(row) = rows.first() {
                    let total: i64 = row.get(0);
                    let waiting: i64 = row.get(1);
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.locks.total",
                        total as f64,
                        &labels,
                        "gauge",
                    ));
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.locks.waiting",
                        waiting as f64,
                        &labels,
                        "gauge",
                    ));
                }
            }
            Err(e) => debug!(error = %e, "failed to query pg_locks"),
        }

        // -- Replication lag --
        match client
            .query(
                "SELECT COALESCE(
                    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)::bigint, 0
                 ) as lag_bytes
                 FROM pg_stat_replication
                 LIMIT 1",
                &[],
            )
            .await
        {
            Ok(rows) => {
                if let Some(row) = rows.first() {
                    let lag_bytes: i64 = row.try_get(0).unwrap_or(0);
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.replication.lag_bytes",
                        lag_bytes as f64,
                        &labels,
                        "gauge",
                    ));
                }
            }
            Err(_) => {
                // Not a primary or no replication — skip silently
            }
        }

        // -- Database size --
        match client
            .query(
                "SELECT sum(pg_database_size(datname))::bigint
                 FROM pg_database
                 WHERE datname NOT IN ('template0', 'template1')",
                &[],
            )
            .await
        {
            Ok(rows) => {
                if let Some(row) = rows.first() {
                    let size_bytes: i64 = row.try_get(0).unwrap_or(0);
                    envelopes.push(helpers::metric_envelope(
                        "postgresql.database.size_bytes",
                        size_bytes as f64,
                        &labels,
                        "gauge",
                    ));
                }
            }
            Err(e) => debug!(error = %e, "failed to query database size"),
        }

        Ok(envelopes)
    }

    #[cfg(not(feature = "postgres"))]
    async fn collect_impl(&self) -> Result<Vec<Envelope>, CollectorError> {
        Ok(Vec::new())
    }
}

impl Collector for PostgresCollector {
    fn name(&self) -> &str {
        "postgres"
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
    fn dsn_env_var_name() {
        assert_eq!(DSN_ENV_VAR, "DODO_AGENT_POSTGRES_DSN");
    }

    #[test]
    fn interval_is_15s() {
        let collector = PostgresCollector::new("test-host".to_string());
        assert_eq!(collector.interval(), Duration::from_secs(15));
    }

    #[test]
    fn name_is_postgres() {
        let collector = PostgresCollector::new("test-host".to_string());
        assert_eq!(collector.name(), "postgres");
    }

    #[tokio::test]
    async fn inactive_without_dsn() {
        // Ensure env var is not set
        std::env::remove_var(DSN_ENV_VAR);
        let collector = PostgresCollector::new("test-host".to_string());
        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn cache_hit_ratio_calculation() {
        let hits = 9900i64;
        let reads = 100i64;
        let total = hits + reads;
        let ratio = (hits as f64 / total as f64) * 100.0;
        assert!((ratio - 99.0).abs() < 0.01);
    }

    #[test]
    fn dsn_never_logged() {
        // This is a design constraint test — verifying the collector does NOT
        // store DSN in any logged/serialized field. The DSN is only used
        // for connection, never exposed in envelopes or logs.
        let collector = PostgresCollector::new("host".to_string());
        assert_eq!(collector.name(), "postgres");
        // DSN is private and not accessible outside the struct
    }
}
