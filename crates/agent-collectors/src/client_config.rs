//! Shared "env var → optional connection target" pattern.
//!
//! `RedisCollector`/`PostgresCollector`/`MongodbCollector` all read a single
//! env var at construction time and stay inactive (no-op collect) until it's
//! set — same log shape, different var/label per collector.

use tracing::info;

/// Read `env_var`; logs whether `collector_name` is configured or inactive.
pub fn optional_target_from_env(
    env_var: &str,
    collector_name: &str,
    source_label: &str,
) -> Option<String> {
    let value = std::env::var(env_var).ok();
    if value.is_some() {
        info!("{collector_name} collector configured ({source_label} from env)");
    } else {
        info!("{collector_name} collector inactive (no {source_label} configured)");
    }
    value
}
