//! Collector registry — stores and manages all registered collectors.
//!
//! Part of HU013 (core loop, scheduler, collector trait).

use crate::Collector;

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
    use crate::{CollectorError, Envelope, SignalType};
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

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
}
