//! Shared counter-delta helper for collectors that track a previous sample.
//!
//! `RedisCollector`/`PostgresCollector`/`MongodbCollector` each redefined an
//! identical local closure for this. Counters can reset (process restart,
//! stat reset) between samples, so a plain subtraction could go negative —
//! `saturating_sub` + clamp to `0` treats a reset as "no delta this tick"
//! rather than a huge negative/wrapped value.

/// Saturating counter delta, clamped to `>= 0.0`.
pub fn counter_delta(current: i64, previous: i64) -> f64 {
    current.saturating_sub(previous).max(0) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_increase() {
        assert_eq!(counter_delta(150, 100), 50.0);
    }

    #[test]
    fn no_change() {
        assert_eq!(counter_delta(100, 100), 0.0);
    }

    #[test]
    fn counter_reset_clamps_to_zero() {
        // Current < previous (process restarted, counter reset) — must not
        // go negative.
        assert_eq!(counter_delta(10, 100), 0.0);
    }

    #[test]
    fn negative_previous_still_saturates() {
        assert_eq!(counter_delta(0, i64::MAX), 0.0);
    }
}
