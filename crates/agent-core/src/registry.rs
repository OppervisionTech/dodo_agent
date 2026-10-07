//! Collector registry — stores and manages all registered collectors.
//!
//! Part of HU013 (core loop, scheduler, collector trait).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::{Collector, CollectorError, Envelope, SignalType};

/// Registry that holds all collector instances.
///
/// Collectors are registered at startup (before the scheduler begins) and
/// then consumed via `into_collectors()` when the scheduler takes ownership.
pub struct CollectorRegistry {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    /// Register a new collector. Logs the registration at info level.
    pub fn register(&mut self, collector: Box<dyn Collector>) {
        tracing::info!(
            collector = collector.name(),
            signal_type = %collector.signal_type(),
            interval_ms = collector.interval().as_millis() as u64,
            "registered collector"
        );
        self.collectors.push(collector);
    }

    /// Register a collector, running it every `interval_seconds` from the
    /// agent config instead of its built-in default (0 = keep the default).
    /// Collectors hard-code a fallback interval; the config value — what
    /// operators actually tune, and what the platform's COGS model assumes —
    /// must win.
    pub fn register_with_interval(&mut self, collector: Box<dyn Collector>, interval_seconds: u32) {
        let configured = Duration::from_secs(u64::from(interval_seconds));
        if interval_seconds == 0 || configured == collector.interval() {
            self.register(collector);
        } else {
            self.register(Box::new(IntervalOverride {
                inner: collector,
                interval: configured,
            }));
        }
    }

    /// Borrow the list of registered collectors.
    pub fn collectors(&self) -> &[Box<dyn Collector>] {
        &self.collectors
    }

    /// Number of registered collectors.
    pub fn len(&self) -> usize {
        self.collectors.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty()
    }

    /// Consume the registry and return the owned collector list.
    /// Used by the scheduler to take ownership of each collector for
    /// spawning into individual tasks.
    pub fn into_collectors(self) -> Vec<Box<dyn Collector>> {
        self.collectors
    }
}

/// Wraps a collector to run it on a different schedule; everything else is
/// delegated unchanged.
struct IntervalOverride {
    inner: Box<dyn Collector>,
    interval: Duration,
}

impl Collector for IntervalOverride {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn signal_type(&self) -> SignalType {
        self.inner.signal_type()
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>> {
        self.inner.collect()
    }
}

impl Default for CollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyCollector {
        name: &'static str,
    }

    impl Collector for DummyCollector {
        fn name(&self) -> &str {
            self.name
        }

        fn signal_type(&self) -> SignalType {
            SignalType::Metric
        }

        fn interval(&self) -> Duration {
            Duration::from_secs(5)
        }

        fn collect(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>>
        {
            Box::pin(async { Ok(vec![]) })
        }
    }

    #[test]
    fn register_and_count() {
        let mut reg = CollectorRegistry::new();
        assert!(reg.is_empty());

        reg.register(Box::new(DummyCollector { name: "cpu" }));
        reg.register(Box::new(DummyCollector { name: "memory" }));

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.collectors()[0].name(), "cpu");
        assert_eq!(reg.collectors()[1].name(), "memory");
    }

    #[test]
    fn into_collectors_consumes() {
        let mut reg = CollectorRegistry::new();
        reg.register(Box::new(DummyCollector { name: "disk" }));

        let collectors = reg.into_collectors();
        assert_eq!(collectors.len(), 1);
        assert_eq!(collectors[0].name(), "disk");
    }

    #[tokio::test]
    async fn config_interval_overrides_the_builtin_default() {
        let mut reg = CollectorRegistry::new();
        reg.register_with_interval(Box::new(DummyCollector { name: "cpu" }), 15);
        reg.register_with_interval(Box::new(DummyCollector { name: "memory" }), 0);
        reg.register_with_interval(Box::new(DummyCollector { name: "disk" }), 5);

        let c = reg.collectors();
        assert_eq!(c[0].interval(), Duration::from_secs(15));
        assert_eq!(c[0].name(), "cpu");
        assert_eq!(c[0].signal_type(), SignalType::Metric);
        assert!(c[0].collect().await.unwrap().is_empty());
        assert_eq!(
            c[1].interval(),
            Duration::from_secs(5),
            "0 keeps the default"
        );
        assert_eq!(c[2].interval(), Duration::from_secs(5));
    }
}
