//! Helper functions for constructing Envelope instances.
//!
//! Payloads are serialized as protobuf matching the dodo_proto schemas,
//! so that downstream workers can deserialize them directly.

use std::collections::HashMap;
use std::time::SystemTime;

use agent_core::{Envelope, SignalType};
use prost::Message;

// ---------------------------------------------------------------------------
// Protobuf types matching dodo.proto.v1
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetricPayload {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(double, tag = "2")]
    pub value: f64,
    #[prost(map = "string, string", tag = "3")]
    pub labels: HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    #[prost(int64, tag = "4")]
    pub timestamp_unix_ns: i64,
    #[prost(enumeration = "MetricType", tag = "5")]
    pub metric_type: i32,
    #[prost(string, tag = "6")]
    pub unit: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetricBatch {
    #[prost(message, repeated, tag = "1")]
    pub metrics: Vec<MetricPayload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MetricType {
    Unspecified = 0,
    Gauge = 1,
    Counter = 2,
    Histogram = 3,
    Summary = 4,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HeartbeatPayload {
    #[prost(string, tag = "1")]
    pub agent_version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub uptime_seconds: u64,
    #[prost(string, tag = "3")]
    pub config_hash: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "4")]
    pub collectors_active: Vec<::prost::alloc::string::String>,
    #[prost(double, tag = "5")]
    pub buffer_used_mb: f64,
    #[prost(uint64, tag = "6")]
    pub send_errors_total: u64,
    #[prost(uint64, tag = "7")]
    pub redactions_total: u64,
    #[prost(uint64, tag = "8")]
    pub envelopes_sent_total: u64,
    #[prost(double, tag = "9")]
    pub cpu_usage_percent: f64,
    #[prost(double, tag = "10")]
    pub memory_usage_mb: f64,
}

/// LogLevel enum values matching dodo.proto.v1.LogLevel.
/// Field 2 must be varint (i32) to match the proto definition.
#[allow(dead_code)]
pub mod log_level {
    pub const UNSPECIFIED: i32 = 0;
    pub const TRACE: i32 = 1;
    pub const DEBUG: i32 = 2;
    pub const INFO: i32 = 3;
    pub const WARN: i32 = 4;
    pub const ERROR: i32 = 5;
    pub const FATAL: i32 = 6;

    pub fn from_str(s: &str) -> i32 {
        match s {
            "TRACE" => TRACE,
            "DEBUG" => DEBUG,
            "INFO" => INFO,
            "WARN" => WARN,
            "ERROR" => ERROR,
            "FATAL" => FATAL,
            _ => UNSPECIFIED,
        }
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogPayload {
    #[prost(string, tag = "1")]
    pub message: ::prost::alloc::string::String,
    /// LogLevel enum as i32 (varint). Matches dodo.proto.v1.LogLevel field 2.
    #[prost(int32, tag = "2")]
    pub level: i32,
    #[prost(string, tag = "3")]
    pub source: ::prost::alloc::string::String,
    #[prost(map = "string, string", tag = "4")]
    pub fields: HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub trace_id: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub span_id: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InventoryPayload {
    #[prost(string, tag = "1")]
    pub hostname: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub os_name: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub kernel_version: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub architecture: ::prost::alloc::string::String,
    #[prost(uint64, tag = "13")]
    pub cpu_cores: u64,
    #[prost(uint64, tag = "14")]
    pub total_memory_bytes: u64,
}

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

    let mt = match metric_type {
        "gauge" => MetricType::Gauge,
        "counter" => MetricType::Counter,
        "histogram" => MetricType::Histogram,
        "summary" => MetricType::Summary,
        _ => MetricType::Gauge,
    };

    let payload = MetricPayload {
        name: name.to_string(),
        value,
        labels: label_map,
        timestamp_unix_ns: ts,
        metric_type: mt as i32,
        unit: String::new(),
    };

    Envelope {
        signal_type: SignalType::Metric,
        payload: payload.encode_to_vec(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Log envelope
// ---------------------------------------------------------------------------

/// Create a log envelope from raw log data.
pub fn log_envelope(
    message: &str,
    severity: &str,
    source: &str,
    attributes: &[(&str, &str)],
    trace_id: Option<&str>,
    span_id: Option<&str>,
) -> Envelope {
    let ts = now_unix_ns();
    let fields: HashMap<String, String> = attributes
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let payload = LogPayload {
        message: message.to_string(),
        level: log_level::from_str(severity),
        source: source.to_string(),
        fields,
        trace_id: trace_id.unwrap_or("").to_string(),
        span_id: span_id.unwrap_or("").to_string(),
    };

    Envelope {
        signal_type: SignalType::Log,
        payload: payload.encode_to_vec(),
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

/// Create an inventory envelope.
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

    let payload = HeartbeatPayload {
        agent_version: data["agent_version"].as_str().unwrap_or("").to_string(),
        uptime_seconds: data["uptime_seconds"].as_u64().unwrap_or(0),
        config_hash: data["config_hash"].as_str().unwrap_or("").to_string(),
        collectors_active: data["active_collectors"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        buffer_used_mb: data["buffer_used_bytes"].as_f64().unwrap_or(0.0) / 1_048_576.0,
        send_errors_total: data["send_errors_total"].as_u64().unwrap_or(0),
        redactions_total: data["redactions_total"].as_u64().unwrap_or(0),
        envelopes_sent_total: data["envelopes_sent"].as_u64().unwrap_or(0),
        cpu_usage_percent: 0.0,
        memory_usage_mb: 0.0,
    };

    Envelope {
        signal_type: SignalType::Heartbeat,
        payload: payload.encode_to_vec(),
        timestamp_unix_ns: ts,
        buffered: false,
        retry_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Trace envelope (kept as JSON for now — otel worker handles raw OTLP)
// ---------------------------------------------------------------------------

/// Create a trace envelope from span data.
#[allow(clippy::too_many_arguments)]
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_envelope_serializes_as_protobuf() {
        let env = metric_envelope("cpu.usage.percent", 42.5, &[("host", "h1")], "gauge");
        assert_eq!(env.signal_type, SignalType::Metric);
        assert!(!env.payload.is_empty());

        let parsed = MetricPayload::decode(env.payload.as_slice()).unwrap();
        assert_eq!(parsed.name, "cpu.usage.percent");
        assert!((parsed.value - 42.5).abs() < f64::EPSILON);
        assert_eq!(parsed.metric_type, MetricType::Gauge as i32);
        assert_eq!(parsed.labels.get("host").unwrap(), "h1");
    }

    #[test]
    fn heartbeat_envelope_serializes_as_protobuf() {
        let env = heartbeat_envelope(serde_json::json!({
            "agent_version": "0.1.0",
            "uptime_seconds": 3600,
            "active_collectors": ["cpu", "memory"],
        }));
        assert_eq!(env.signal_type, SignalType::Heartbeat);

        let parsed = HeartbeatPayload::decode(env.payload.as_slice()).unwrap();
        assert_eq!(parsed.agent_version, "0.1.0");
        assert_eq!(parsed.uptime_seconds, 3600);
        assert_eq!(parsed.collectors_active, vec!["cpu", "memory"]);
    }

    #[test]
    fn log_envelope_serializes_as_protobuf() {
        let env = log_envelope(
            "test msg",
            "INFO",
            "/var/log/app.log",
            &[("app", "myapp")],
            Some("abc"),
            Some("def"),
        );
        assert_eq!(env.signal_type, SignalType::Log);

        let parsed = LogPayload::decode(env.payload.as_slice()).unwrap();
        assert_eq!(parsed.message, "test msg");
        assert_eq!(parsed.trace_id, "abc");
    }

    #[test]
    fn now_unix_ns_is_positive() {
        assert!(now_unix_ns() > 0);
    }
}
