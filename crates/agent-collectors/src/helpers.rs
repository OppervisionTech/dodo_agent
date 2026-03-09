//! Helper functions for constructing Envelope instances.
//!
//! Provides factory functions for each signal type so that collectors
//! can focus on data collection logic rather than boilerplate serialization.
//! For MVP, payloads are serialized as JSON. In production these will be
//! converted to protobuf via the dodo_proto schemas.

use std::collections::HashMap;
use std::time::SystemTime;

use agent_core::{Envelope, SignalType};

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

/// Returns the current time as nanoseconds since the Unix epoch.
pub fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

// ---------------------------------------------------------------------------
// Metric envelope
// ---------------------------------------------------------------------------

/// Create a metric envelope with the given name, value, labels, and metric type.
///
/// `metric_type` should be one of: "gauge", "counter", "histogram", "summary".
pub fn metric_envelope(
    name: &str,
    value: f64,
    labels: &[(&str, &str)],
    metric_type: &str,
) -> Envelope {
    let ts = now_unix_ns();
    let label_map: HashMap<String, String> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let payload = serde_json::json!({
        "name": name,
        "value": value,
        "labels": label_map,
        "metric_type": metric_type,
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::Metric,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Log envelope
// ---------------------------------------------------------------------------

/// Create a log envelope from raw log data.
///
/// `severity` should be one of: "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL".
pub fn log_envelope(
    message: &str,
    severity: &str,
    source: &str,
    attributes: &[(&str, &str)],
    trace_id: Option<&str>,
    span_id: Option<&str>,
) -> Envelope {
    let ts = now_unix_ns();
    let attr_map: HashMap<String, String> = attributes
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let payload = serde_json::json!({
        "message": message,
        "severity": severity,
        "source": source,
        "attributes": attr_map,
        "trace_id": trace_id,
        "span_id": span_id,
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::Log,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Trace envelope
// ---------------------------------------------------------------------------

/// Create a trace envelope from span data.
pub fn trace_envelope(
    trace_id: &str,
    span_id: &str,
    parent_span_id: &str,
    operation_name: &str,
    service_name: &str,
    kind: &str,
    start_time_unix_ns: i64,
    end_time_unix_ns: i64,
    attributes: &[(&str, &str)],
    status_code: &str,
) -> Envelope {
    let ts = now_unix_ns();
    let attr_map: HashMap<String, String> = attributes
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let payload = serde_json::json!({
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "operation_name": operation_name,
        "service_name": service_name,
        "kind": kind,
        "start_time_unix_ns": start_time_unix_ns,
        "end_time_unix_ns": end_time_unix_ns,
        "duration_ns": end_time_unix_ns.saturating_sub(start_time_unix_ns),
        "attributes": attr_map,
        "status_code": status_code,
        "source": "otel",
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::Trace,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Event envelope
// ---------------------------------------------------------------------------

/// Create a generic event envelope.
pub fn event_envelope(event_type: &str, summary: &str, details: serde_json::Value) -> Envelope {
    let ts = now_unix_ns();
    let payload = serde_json::json!({
        "event_type": event_type,
        "summary": summary,
        "details": details,
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::Event,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Security event envelope
// ---------------------------------------------------------------------------

/// Create a security event envelope.
///
/// `severity` should be one of: "low", "medium", "high", "critical".
pub fn security_event_envelope(
    event_type: &str,
    severity: &str,
    summary: &str,
    details: serde_json::Value,
) -> Envelope {
    let ts = now_unix_ns();
    let payload = serde_json::json!({
        "event_type": event_type,
        "severity": severity,
        "summary": summary,
        "details": details,
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::SecurityEvent,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Inventory envelope
// ---------------------------------------------------------------------------

/// Create an inventory envelope with an arbitrary JSON payload.
pub fn inventory_envelope(inventory_type: &str, data: serde_json::Value) -> Envelope {
    let ts = now_unix_ns();
    let payload = serde_json::json!({
        "inventory_type": inventory_type,
        "data": data,
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::Inventory,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Heartbeat envelope
// ---------------------------------------------------------------------------

/// Create a heartbeat envelope.
pub fn heartbeat_envelope(data: serde_json::Value) -> Envelope {
    let ts = now_unix_ns();
    let payload = serde_json::json!({
        "heartbeat": data,
        "timestamp_unix_ns": ts,
    });

    Envelope {
        signal_type: SignalType::Heartbeat,
        payload: serde_json::to_vec(&payload).unwrap_or_default(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_envelope_serializes_correctly() {
        let env = metric_envelope("cpu.usage.percent", 42.5, &[("host", "h1")], "gauge");
        assert_eq!(env.signal_type, SignalType::Metric);
        assert!(!env.payload.is_empty());
        assert!(!env.buffered);
        assert_eq!(env.retry_count, 0);

        let parsed: serde_json::Value = serde_json::from_slice(&env.payload).unwrap();
        assert_eq!(parsed["name"], "cpu.usage.percent");
        assert_eq!(parsed["value"], 42.5);
        assert_eq!(parsed["metric_type"], "gauge");
    }

    #[test]
    fn log_envelope_includes_trace_context() {
        let env = log_envelope(
            "test message",
            "INFO",
            "/var/log/app.log",
            &[("app", "myapp")],
            Some("abc123"),
            Some("def456"),
        );
        assert_eq!(env.signal_type, SignalType::Log);
        let parsed: serde_json::Value = serde_json::from_slice(&env.payload).unwrap();
        assert_eq!(parsed["trace_id"], "abc123");
        assert_eq!(parsed["span_id"], "def456");
    }

    #[test]
    fn security_event_envelope_has_correct_type() {
        let env = security_event_envelope(
            "PORT_CHANGE",
            "medium",
            "New port detected: 8080",
            serde_json::json!({"port": 8080}),
        );
        assert_eq!(env.signal_type, SignalType::SecurityEvent);
    }

    #[test]
    fn heartbeat_envelope_has_correct_type() {
        let env = heartbeat_envelope(serde_json::json!({"version": "0.1.0"}));
        assert_eq!(env.signal_type, SignalType::Heartbeat);
    }

    #[test]
    fn inventory_envelope_has_correct_type() {
        let env = inventory_envelope("host", serde_json::json!({"hostname": "test"}));
        assert_eq!(env.signal_type, SignalType::Inventory);
    }

    #[test]
    fn now_unix_ns_is_positive() {
        assert!(now_unix_ns() > 0);
    }
}
