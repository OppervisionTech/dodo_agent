//! OpenTelemetry passthrough collector — HU260.
//!
//! Listens on localhost:4317 (gRPC) and localhost:4318 (HTTP) for incoming
//! OTLP data. Converts received traces, metrics, and logs into Envelopes
//! and buffers them for the scheduler to drain via `collect()`.
//!
//! # SECURITY
//! - MUST bind to 127.0.0.1 only, NEVER 0.0.0.0
//! - Agent NEVER listens on external network interfaces
//! - Rate limited to prevent resource exhaustion

// Structs/functions in this file are only wired up under the `otel` feature.
// Silence dead-code and unused-import lints for variants that don't enable it.
#![cfg_attr(
    not(feature = "otel"),
    allow(dead_code, unused_imports, unused_variables)
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::helpers;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GRPC_LISTEN_ADDR: &str = "127.0.0.1:4317";
const HTTP_LISTEN_ADDR: &str = "127.0.0.1:4318";
const BUFFER_CAPACITY: usize = 10_000;
const CAPACITY_REJECTION: &str = "receiver capacity exceeded";
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_RATE_LIMIT_PER_SEC: u64 = 50_000;

// ---------------------------------------------------------------------------
// Inline OTLP proto types (minimal subset for parsing)
// ---------------------------------------------------------------------------

/// Minimal OTLP proto types defined inline with prost to avoid external dep.
/// Field tags match the official opentelemetry-proto v1 definitions.
pub(crate) mod otlp {
    // ---- Common ----

    #[derive(Clone, prost::Message)]
    pub struct KeyValue {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(message, optional, tag = "2")]
        pub value: Option<AnyValue>,
    }

    #[derive(Clone, prost::Message)]
    pub struct AnyValue {
        #[prost(oneof = "any_value::Value", tags = "1, 2, 3, 4, 7")]
        pub value: Option<any_value::Value>,
    }

    pub mod any_value {
        #[derive(Clone, prost::Oneof)]
        #[allow(clippy::enum_variant_names)]
        pub enum Value {
            #[prost(string, tag = "1")]
            StringValue(String),
            #[prost(bool, tag = "2")]
            BoolValue(bool),
            #[prost(int64, tag = "3")]
            IntValue(i64),
            #[prost(double, tag = "4")]
            DoubleValue(f64),
            #[prost(bytes, tag = "7")]
            BytesValue(Vec<u8>),
        }
    }

    #[derive(Clone, prost::Message)]
    pub struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub attributes: Vec<KeyValue>,
    }

    #[derive(Clone, prost::Message)]
    pub struct InstrumentationScope {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub version: String,
    }

    // ---- Trace ----

    #[derive(Clone, prost::Message)]
    pub struct ExportTraceServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_spans: Vec<ResourceSpans>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ExportTraceServiceResponse {
        #[prost(message, optional, tag = "1")]
        pub partial_success: Option<ExportTracePartialSuccess>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ExportTracePartialSuccess {
        #[prost(int64, tag = "1")]
        pub rejected_spans: i64,
        #[prost(string, tag = "2")]
        pub error_message: String,
    }

    #[derive(Clone, prost::Message)]
    pub struct ResourceSpans {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_spans: Vec<ScopeSpans>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ScopeSpans {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub spans: Vec<Span>,
    }

    #[derive(Clone, prost::Message)]
    pub struct Span {
        #[prost(bytes, tag = "1")]
        pub trace_id: Vec<u8>,
        #[prost(bytes, tag = "2")]
        pub span_id: Vec<u8>,
        #[prost(string, tag = "3")]
        pub trace_state: String,
        #[prost(bytes, tag = "4")]
        pub parent_span_id: Vec<u8>,
        #[prost(string, tag = "5")]
        pub name: String,
        #[prost(enumeration = "SpanKind", tag = "6")]
        pub kind: i32,
        #[prost(fixed64, tag = "7")]
        pub start_time_unix_nano: u64,
        #[prost(fixed64, tag = "8")]
        pub end_time_unix_nano: u64,
        #[prost(message, repeated, tag = "9")]
        pub attributes: Vec<KeyValue>,
        #[prost(message, optional, tag = "15")]
        pub status: Option<SpanStatus>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    pub enum SpanKind {
        Unspecified = 0,
        Internal = 1,
        Server = 2,
        Client = 3,
        Producer = 4,
        Consumer = 5,
    }

    #[derive(Clone, prost::Message)]
    pub struct SpanStatus {
        #[prost(string, tag = "2")]
        pub message: String,
        #[prost(enumeration = "StatusCode", tag = "3")]
        pub code: i32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    pub enum StatusCode {
        Unset = 0,
        Ok = 1,
        Error = 2,
    }

    // ---- Metrics ----

    #[derive(Clone, prost::Message)]
    pub struct ExportMetricsServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_metrics: Vec<ResourceMetrics>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ExportMetricsServiceResponse {
        #[prost(message, optional, tag = "1")]
        pub partial_success: Option<ExportMetricsPartialSuccess>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ExportMetricsPartialSuccess {
        #[prost(int64, tag = "1")]
        pub rejected_data_points: i64,
        #[prost(string, tag = "2")]
        pub error_message: String,
    }

    #[derive(Clone, prost::Message)]
    pub struct ResourceMetrics {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_metrics: Vec<ScopeMetrics>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ScopeMetrics {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub metrics: Vec<Metric>,
    }

    #[derive(Clone, prost::Message)]
    pub struct Metric {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub description: String,
        #[prost(string, tag = "3")]
        pub unit: String,
        #[prost(oneof = "metric::Data", tags = "5, 7, 9")]
        pub data: Option<metric::Data>,
    }

    pub mod metric {
        #[derive(Clone, prost::Oneof)]
        pub enum Data {
            #[prost(message, tag = "5")]
            Gauge(super::Gauge),
            #[prost(message, tag = "7")]
            Sum(super::Sum),
            #[prost(message, tag = "9")]
            Histogram(super::Histogram),
        }
    }

    #[derive(Clone, prost::Message)]
    pub struct Gauge {
        #[prost(message, repeated, tag = "1")]
        pub data_points: Vec<NumberDataPoint>,
    }

    #[derive(Clone, prost::Message)]
    pub struct Sum {
        #[prost(message, repeated, tag = "1")]
        pub data_points: Vec<NumberDataPoint>,
        #[prost(bool, tag = "3")]
        pub is_monotonic: bool,
    }

    #[derive(Clone, prost::Message)]
    pub struct Histogram {
        #[prost(message, repeated, tag = "1")]
        pub data_points: Vec<HistogramDataPoint>,
    }

    #[derive(Clone, prost::Message)]
    pub struct NumberDataPoint {
        #[prost(message, repeated, tag = "7")]
        pub attributes: Vec<KeyValue>,
        #[prost(fixed64, tag = "3")]
        pub time_unix_nano: u64,
        #[prost(oneof = "number_data_point::Value", tags = "4, 6")]
        pub value: Option<number_data_point::Value>,
    }

    pub mod number_data_point {
        #[derive(Clone, prost::Oneof)]
        pub enum Value {
            #[prost(double, tag = "4")]
            AsDouble(f64),
            #[prost(sfixed64, tag = "6")]
            AsInt(i64),
        }
    }

    #[derive(Clone, prost::Message)]
    pub struct HistogramDataPoint {
        #[prost(message, repeated, tag = "9")]
        pub attributes: Vec<KeyValue>,
        #[prost(fixed64, tag = "3")]
        pub time_unix_nano: u64,
        #[prost(uint64, tag = "4")]
        pub count: u64,
        #[prost(double, optional, tag = "5")]
        pub sum: Option<f64>,
        #[prost(uint64, repeated, tag = "6")]
        pub bucket_counts: Vec<u64>,
        #[prost(double, repeated, tag = "7")]
        pub explicit_bounds: Vec<f64>,
    }

    // ---- Logs ----

    #[derive(Clone, prost::Message)]
    pub struct ExportLogsServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_logs: Vec<ResourceLogs>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ExportLogsServiceResponse {
        #[prost(message, optional, tag = "1")]
        pub partial_success: Option<ExportLogsPartialSuccess>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ExportLogsPartialSuccess {
        #[prost(int64, tag = "1")]
        pub rejected_log_records: i64,
        #[prost(string, tag = "2")]
        pub error_message: String,
    }

    #[derive(Clone, prost::Message)]
    pub struct ResourceLogs {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_logs: Vec<ScopeLogs>,
    }

    #[derive(Clone, prost::Message)]
    pub struct ScopeLogs {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub log_records: Vec<LogRecord>,
    }

    #[derive(Clone, prost::Message)]
    pub struct LogRecord {
        #[prost(fixed64, tag = "1")]
        pub time_unix_nano: u64,
        #[prost(enumeration = "SeverityNumber", tag = "2")]
        pub severity_number: i32,
        #[prost(string, tag = "3")]
        pub severity_text: String,
        #[prost(message, optional, tag = "5")]
        pub body: Option<AnyValue>,
        #[prost(message, repeated, tag = "6")]
        pub attributes: Vec<KeyValue>,
        #[prost(bytes, tag = "9")]
        pub trace_id: Vec<u8>,
        #[prost(bytes, tag = "10")]
        pub span_id: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    pub enum SeverityNumber {
        Unspecified = 0,
        Trace = 1,
        Debug = 5,
        Info = 9,
        Warn = 13,
        Error = 17,
        Fatal = 21,
    }

    // ---- Helpers ----

    /// Extract a string attribute from a KeyValue list.
    pub fn get_attribute(attrs: &[KeyValue], key: &str) -> Option<String> {
        attrs.iter().find(|kv| kv.key == key).and_then(|kv| {
            kv.value.as_ref().and_then(|v| match &v.value {
                Some(any_value::Value::StringValue(s)) => Some(s.clone()),
                _ => None,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Internal metrics
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct OtelMetrics {
    requests_total: Arc<AtomicU64>,
    spans_received: Arc<AtomicU64>,
    metrics_received: Arc<AtomicU64>,
    logs_received: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    rate_counter: Arc<AtomicU64>,
}

impl OtelMetrics {
    fn new() -> Self {
        Self {
            requests_total: Arc::new(AtomicU64::new(0)),
            spans_received: Arc::new(AtomicU64::new(0)),
            metrics_received: Arc::new(AtomicU64::new(0)),
            logs_received: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            rate_counter: Arc::new(AtomicU64::new(0)),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state for gRPC/HTTP handlers
// ---------------------------------------------------------------------------

struct OtelShared {
    envelope_tx: mpsc::Sender<Envelope>,
    metrics: OtelMetrics,
    rate_limit_per_sec: u64,
}

impl OtelShared {
    // Reserve the complete batch before accepting anything. Exporters may retry
    // transient errors; accepting a subset then returning one duplicates data.
    fn try_send(&self, envelopes: Vec<Envelope>) -> usize {
        let count = envelopes.len();
        if count == 0 {
            return 0;
        }
        let permits = match self.envelope_tx.try_reserve_many(count) {
            Ok(permits) => permits,
            Err(_) => {
                self.metrics
                    .dropped
                    .fetch_add(count as u64, Ordering::Relaxed);
                return 0;
            }
        };
        if self
            .metrics
            .rate_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(count as u64)
                    .filter(|next| *next <= self.rate_limit_per_sec)
            })
            .is_err()
        {
            self.metrics
                .dropped
                .fetch_add(count as u64, Ordering::Relaxed);
            return 0;
        }
        for (permit, envelope) in permits.zip(envelopes) {
            permit.send(envelope);
        }
        count
    }

    fn submit_native(
        &self,
        req: agent_transport::proto::SubmitBatchRequest,
    ) -> agent_transport::proto::SubmitBatchResponse {
        let total = req.envelopes.len();
        if total > 1000 {
            return agent_transport::proto::SubmitBatchResponse {
                accepted: 0,
                rejected: total as u32,
                errors: vec!["batch exceeds 1000 envelopes".into()],
            };
        }
        let mut envelopes = Vec::with_capacity(total);
        let mut invalid = 0;
        for env in req.envelopes {
            // Applications cannot forge inventory, heartbeats or security events.
            // Dropping all sender identity is intentional: the transport stamps
            // the enrolled agent's identity when these Rust-native items flush.
            let signal_type = match env.signal_type {
                1 => SignalType::Metric,
                2 => SignalType::Log,
                3 => SignalType::Trace,
                4 => SignalType::Event,
                8 => SignalType::CustomEvent,
                _ => {
                    invalid += 1;
                    continue;
                }
            };
            if env.compression != agent_transport::proto::Compression::None as i32
                || env.payload.is_empty()
                || env.payload.len() > 1024 * 1024
                || env.timestamp_unix_ns <= 0
            {
                invalid += 1;
                continue;
            }
            envelopes.push(Envelope {
                signal_type,
                payload: env.payload,
                timestamp_unix_ns: env.timestamp_unix_ns,
                buffered: false,
                retry_count: 0,
            });
        }
        let accepted = self.try_send(envelopes);
        self.metrics.dropped.fetch_add(invalid, Ordering::Relaxed);
        let rejected = total - accepted;
        agent_transport::proto::SubmitBatchResponse {
            accepted: accepted as u32,
            rejected: rejected as u32,
            errors: if rejected > 0 {
                vec![if invalid == 0 {
                    CAPACITY_REJECTION.into()
                } else {
                    "unsupported or malformed native envelope".into()
                }]
            } else {
                vec![]
            },
        }
    }
}

// ---------------------------------------------------------------------------
// OTLP → Envelope conversion
// ---------------------------------------------------------------------------

fn convert_traces(req: &otlp::ExportTraceServiceRequest) -> Vec<Envelope> {
    let mut envelopes = Vec::new();
    for rs in &req.resource_spans {
        let resource_attrs = rs
            .resource
            .as_ref()
            .map(|r| &r.attributes[..])
            .unwrap_or_default();
        let service_name = otlp::get_attribute(resource_attrs, "service.name")
            .unwrap_or_else(|| "unknown".to_string());

        for ss in &rs.scope_spans {
            for span in &ss.spans {
                let trace_id = hex::encode(&span.trace_id);
                let span_id = hex::encode(&span.span_id);
                let parent_span_id = hex::encode(&span.parent_span_id);

                let kind = match otlp::SpanKind::try_from(span.kind) {
                    Ok(otlp::SpanKind::Server) => "SERVER",
                    Ok(otlp::SpanKind::Client) => "CLIENT",
                    Ok(otlp::SpanKind::Producer) => "PRODUCER",
                    Ok(otlp::SpanKind::Consumer) => "CONSUMER",
                    Ok(otlp::SpanKind::Internal) => "INTERNAL",
                    _ => "UNSPECIFIED",
                };

                let status_code = span
                    .status
                    .as_ref()
                    .map(|s| match otlp::StatusCode::try_from(s.code) {
                        Ok(otlp::StatusCode::Ok) => "OK",
                        Ok(otlp::StatusCode::Error) => "ERROR",
                        _ => "UNSET",
                    })
                    .unwrap_or("UNSET");

                let mut attrs: Vec<(&str, &str)> = Vec::new();
                let attr_strings: Vec<(String, String)> = span
                    .attributes
                    .iter()
                    .filter_map(|kv| {
                        kv.value.as_ref().and_then(|v| match &v.value {
                            Some(otlp::any_value::Value::StringValue(s)) => {
                                Some((kv.key.clone(), s.clone()))
                            }
                            Some(otlp::any_value::Value::IntValue(i)) => {
                                Some((kv.key.clone(), i.to_string()))
                            }
                            Some(otlp::any_value::Value::DoubleValue(d)) => {
                                Some((kv.key.clone(), d.to_string()))
                            }
                            Some(otlp::any_value::Value::BoolValue(b)) => {
                                Some((kv.key.clone(), b.to_string()))
                            }
                            _ => None,
                        })
                    })
                    .collect();
                for (k, v) in &attr_strings {
                    attrs.push((k.as_str(), v.as_str()));
                }

                envelopes.push(helpers::trace_envelope(
                    &trace_id,
                    &span_id,
                    &parent_span_id,
                    &span.name,
                    &service_name,
                    kind,
                    span.start_time_unix_nano as i64,
                    span.end_time_unix_nano as i64,
                    &attrs,
                    status_code,
                ));
            }
        }
    }
    envelopes
}

fn convert_metrics(req: &otlp::ExportMetricsServiceRequest) -> Vec<Envelope> {
    let mut envelopes = Vec::new();
    for rm in &req.resource_metrics {
        let resource_attrs = rm
            .resource
            .as_ref()
            .map(|r| &r.attributes[..])
            .unwrap_or_default();
        let service_name = otlp::get_attribute(resource_attrs, "service.name")
            .unwrap_or_else(|| "unknown".to_string());

        for sm in &rm.scope_metrics {
            for metric in &sm.metrics {
                let metric_name = &metric.name;

                match &metric.data {
                    Some(otlp::metric::Data::Gauge(gauge)) => {
                        for dp in &gauge.data_points {
                            let (value, labels) = extract_number_dp(dp, &service_name);
                            let label_refs: Vec<(&str, &str)> = labels
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();
                            envelopes.push(helpers::metric_envelope(
                                metric_name,
                                value,
                                &label_refs,
                                "gauge",
                            ));
                        }
                    }
                    Some(otlp::metric::Data::Sum(sum)) => {
                        let mtype = if sum.is_monotonic { "counter" } else { "gauge" };
                        for dp in &sum.data_points {
                            let (value, labels) = extract_number_dp(dp, &service_name);
                            let label_refs: Vec<(&str, &str)> = labels
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();
                            envelopes.push(helpers::metric_envelope(
                                metric_name,
                                value,
                                &label_refs,
                                mtype,
                            ));
                        }
                    }
                    Some(otlp::metric::Data::Histogram(hist)) => {
                        for dp in &hist.data_points {
                            let mut labels: Vec<(String, String)> =
                                dp.attributes.iter().filter_map(kv_to_string_pair).collect();
                            labels.push(("service.name".to_string(), service_name.clone()));
                            let label_refs: Vec<(&str, &str)> = labels
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();
                            if let Some(sum) = dp.sum {
                                envelopes.push(helpers::metric_envelope(
                                    &format!("{metric_name}.sum"),
                                    sum,
                                    &label_refs,
                                    "histogram",
                                ));
                            }
                            envelopes.push(helpers::metric_envelope(
                                &format!("{metric_name}.count"),
                                dp.count as f64,
                                &label_refs,
                                "histogram",
                            ));
                        }
                    }
                    None => {}
                }
            }
        }
    }
    envelopes
}

fn convert_logs(req: &otlp::ExportLogsServiceRequest) -> Vec<Envelope> {
    let mut envelopes = Vec::new();
    for rl in &req.resource_logs {
        let resource_attrs = rl
            .resource
            .as_ref()
            .map(|r| &r.attributes[..])
            .unwrap_or_default();
        let service_name = otlp::get_attribute(resource_attrs, "service.name")
            .unwrap_or_else(|| "unknown".to_string());

        for sl in &rl.scope_logs {
            for record in &sl.log_records {
                let severity = severity_to_str(record.severity_number);
                let body = record
                    .body
                    .as_ref()
                    .and_then(|v| match &v.value {
                        Some(otlp::any_value::Value::StringValue(s)) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();

                let trace_id = if record.trace_id.is_empty() {
                    None
                } else {
                    Some(hex::encode(&record.trace_id))
                };
                let span_id = if record.span_id.is_empty() {
                    None
                } else {
                    Some(hex::encode(&record.span_id))
                };

                let mut attrs: Vec<(String, String)> = record
                    .attributes
                    .iter()
                    .filter_map(kv_to_string_pair)
                    .collect();
                attrs.push(("service.name".to_string(), service_name.clone()));
                let attr_refs: Vec<(&str, &str)> = attrs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();

                envelopes.push(helpers::log_envelope(
                    &body,
                    severity,
                    "otel",
                    &attr_refs,
                    trace_id.as_deref(),
                    span_id.as_deref(),
                ));
            }
        }
    }
    envelopes
}

fn extract_number_dp(
    dp: &otlp::NumberDataPoint,
    service_name: &str,
) -> (f64, Vec<(String, String)>) {
    let value = match &dp.value {
        Some(otlp::number_data_point::Value::AsDouble(d)) => *d,
        Some(otlp::number_data_point::Value::AsInt(i)) => *i as f64,
        None => 0.0,
    };
    let mut labels: Vec<(String, String)> =
        dp.attributes.iter().filter_map(kv_to_string_pair).collect();
    labels.push(("service.name".to_string(), service_name.to_string()));
    (value, labels)
}

fn kv_to_string_pair(kv: &otlp::KeyValue) -> Option<(String, String)> {
    kv.value.as_ref().and_then(|v| match &v.value {
        Some(otlp::any_value::Value::StringValue(s)) => Some((kv.key.clone(), s.clone())),
        Some(otlp::any_value::Value::IntValue(i)) => Some((kv.key.clone(), i.to_string())),
        Some(otlp::any_value::Value::DoubleValue(d)) => Some((kv.key.clone(), d.to_string())),
        Some(otlp::any_value::Value::BoolValue(b)) => Some((kv.key.clone(), b.to_string())),
        _ => None,
    })
}

fn severity_to_str(severity_number: i32) -> &'static str {
    match severity_number {
        1..=4 => "TRACE",
        5..=8 => "DEBUG",
        9..=12 => "INFO",
        13..=16 => "WARN",
        17..=20 => "ERROR",
        21..=24 => "FATAL",
        _ => "INFO",
    }
}

/// Minimal hex encoding (avoids pulling in hex crate).
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}

// ---------------------------------------------------------------------------
// gRPC server (tonic)
// ---------------------------------------------------------------------------

#[cfg(feature = "otel")]
mod grpc_server {
    use super::*;
    use prost::Message;
    use std::net::SocketAddr;

    /// OTLP gRPC service handler.
    struct OtlpGrpc {
        shared: Arc<OtelShared>,
    }

    pub async fn run(
        shared: Arc<OtelShared>,
        cancel: CancellationToken,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = GRPC_LISTEN_ADDR.parse()?;

        // Validate bind address is localhost
        assert!(
            addr.ip().is_loopback(),
            "OTEL gRPC MUST bind to loopback only"
        );

        let handler = Arc::new(OtlpGrpc {
            shared: shared.clone(),
        });

        // Use raw hyper to handle gRPC (simpler than building full tonic services)
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(addr = %addr, "OTEL gRPC listener started");

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("OTEL gRPC server shutting down");
                    return Ok(());
                }
                result = listener.accept() => {
                    let (stream, _peer) = result?;
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_grpc_connection(stream, handler).await {
                            debug!(error = %e, "gRPC connection error");
                        }
                    });
                }
            }
        }
    }

    async fn handle_grpc_connection(
        stream: tokio::net::TcpStream,
        handler: Arc<OtlpGrpc>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use hyper_util::rt::TokioIo;

        let io = TokioIo::new(stream);
        let handler = handler.clone();

        let service =
            hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let handler = handler.clone();
                async move { handler.handle_request(req).await }
            });

        let builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .http2_only();
        builder.serve_connection(io, service).into_owned().await?;

        Ok(())
    }

    impl OtlpGrpc {
        async fn handle_request(
            &self,
            req: hyper::Request<hyper::body::Incoming>,
        ) -> Result<
            hyper::Response<
                http_body_util::combinators::BoxBody<hyper::body::Bytes, std::convert::Infallible>,
            >,
            std::convert::Infallible,
        > {
            use http_body_util::BodyExt;

            let path = req.uri().path().to_string();
            let body = match BodyExt::collect(http_body_util::Limited::new(
                req.into_body(),
                MAX_REQUEST_BYTES + 5,
            ))
            .await
            {
                Ok(b) => b.to_bytes(),
                Err(_) => return Ok(grpc_response(Vec::new(), 8)),
            };

            // One uncompressed unary frame, bounded before decoding/allocation.
            if body.len() < 5
                || body[0] != 0
                || u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize
                    != body.len() - 5
            {
                return Ok(grpc_response(Vec::new(), 3));
            }
            let payload = &body[5..];

            let (response_bytes, status_code) = match path.as_str() {
                "/opentelemetry.proto.collector.trace.v1.TraceService/Export" => {
                    self.shared
                        .metrics
                        .requests_total
                        .fetch_add(1, Ordering::Relaxed);
                    match otlp::ExportTraceServiceRequest::decode(payload) {
                        Ok(req) => {
                            let envelopes = convert_traces(&req);
                            let count = envelopes.len();
                            self.shared
                                .metrics
                                .spans_received
                                .fetch_add(count as u64, Ordering::Relaxed);
                            let accepted = self.shared.try_send(envelopes);
                            let resp = otlp::ExportTraceServiceResponse::default();
                            (resp.encode_to_vec(), if accepted < count { 8 } else { 0 })
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to decode trace request");
                            (Vec::new(), 3) // INVALID_ARGUMENT
                        }
                    }
                }
                "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export" => {
                    self.shared
                        .metrics
                        .requests_total
                        .fetch_add(1, Ordering::Relaxed);
                    match otlp::ExportMetricsServiceRequest::decode(payload) {
                        Ok(req) => {
                            let envelopes = convert_metrics(&req);
                            let count = envelopes.len();
                            self.shared
                                .metrics
                                .metrics_received
                                .fetch_add(count as u64, Ordering::Relaxed);
                            let accepted = self.shared.try_send(envelopes);
                            let resp = otlp::ExportMetricsServiceResponse::default();
                            (resp.encode_to_vec(), if accepted < count { 8 } else { 0 })
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to decode metrics request");
                            (Vec::new(), 3)
                        }
                    }
                }
                "/opentelemetry.proto.collector.logs.v1.LogsService/Export" => {
                    self.shared
                        .metrics
                        .requests_total
                        .fetch_add(1, Ordering::Relaxed);
                    match otlp::ExportLogsServiceRequest::decode(payload) {
                        Ok(req) => {
                            let envelopes = convert_logs(&req);
                            let count = envelopes.len();
                            self.shared
                                .metrics
                                .logs_received
                                .fetch_add(count as u64, Ordering::Relaxed);
                            let accepted = self.shared.try_send(envelopes);
                            let resp = otlp::ExportLogsServiceResponse::default();
                            (resp.encode_to_vec(), if accepted < count { 8 } else { 0 })
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to decode logs request");
                            (Vec::new(), 3)
                        }
                    }
                }
                "/dodo.proto.v1.IngestorService/SubmitBatch" => {
                    match agent_transport::proto::SubmitBatchRequest::decode(payload) {
                        Ok(req) => {
                            let response = self.shared.submit_native(req);
                            if response.accepted == 0
                                && response
                                    .errors
                                    .first()
                                    .is_some_and(|error| error == CAPACITY_REJECTION)
                            {
                                (Vec::new(), 8)
                            } else {
                                (response.encode_to_vec(), 0)
                            }
                        }
                        Err(_) => (Vec::new(), 3),
                    }
                }
                _ => (Vec::new(), 12), // UNIMPLEMENTED
            };

            Ok(grpc_response(response_bytes, status_code))
        }
    }

    fn grpc_response(
        response_bytes: Vec<u8>,
        status_code: u16,
    ) -> hyper::Response<
        http_body_util::combinators::BoxBody<hyper::body::Bytes, std::convert::Infallible>,
    > {
        // Build gRPC response with frame header
        let mut frame = Vec::with_capacity(5 + response_bytes.len());
        frame.push(0u8); // not compressed
        frame.extend_from_slice(&(response_bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&response_bytes);

        use http_body_util::BodyExt;
        // grpc-status belongs in HTTP/2 trailers after the unary message. A
        // status header plus DATA is not a trailers-only response and gRPC
        // clients report "Stream removed" instead of reading the payload.
        let mut trailers = hyper::HeaderMap::new();
        if let Ok(value) = hyper::header::HeaderValue::from_str(&status_code.to_string()) {
            trailers.insert("grpc-status", value);
        }
        let body = http_body_util::Full::new(hyper::body::Bytes::from(frame))
            .with_trailers(async move { Some(Ok(trailers)) })
            .boxed();
        let mut resp = hyper::Response::new(body);
        resp.headers_mut().insert(
            "content-type",
            hyper::header::HeaderValue::from_static("application/grpc"),
        );

        resp
    }
}

// ---------------------------------------------------------------------------
// HTTP server (axum)
// ---------------------------------------------------------------------------

#[cfg(feature = "otel")]
mod http_server {
    use super::*;
    use prost::Message;
    use std::net::SocketAddr;

    pub async fn run(
        shared: Arc<OtelShared>,
        cancel: CancellationToken,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = HTTP_LISTEN_ADDR.parse()?;

        assert!(
            addr.ip().is_loopback(),
            "OTEL HTTP MUST bind to loopback only"
        );

        let app = axum::Router::new()
            .route("/v1/batch", axum::routing::post(handle_native))
            .route("/healthz", axum::routing::get(|| async { "ok" }))
            .route("/readyz", axum::routing::get(handle_ready))
            .route("/v1/traces", axum::routing::post(handle_traces))
            .route("/v1/metrics", axum::routing::post(handle_metrics))
            .route("/v1/logs", axum::routing::post(handle_logs))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .with_state(shared);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(addr = %addr, "OTEL HTTP listener started");

        axum::serve(listener, app)
            .with_graceful_shutdown(async move { cancel.cancelled().await })
            .await?;

        info!("OTEL HTTP server stopped");
        Ok(())
    }

    async fn handle_ready(
        axum::extract::State(shared): axum::extract::State<Arc<OtelShared>>,
    ) -> axum::http::StatusCode {
        if shared.envelope_tx.is_closed() || shared.envelope_tx.capacity() == 0 {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        } else {
            axum::http::StatusCode::OK
        }
    }

    async fn handle_native(
        axum::extract::State(shared): axum::extract::State<Arc<OtelShared>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        if !is_protobuf(&headers) {
            return axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
        match agent_transport::proto::SubmitBatchRequest::decode(body) {
            Ok(req) => {
                let response = shared.submit_native(req);
                if response.accepted == 0
                    && response
                        .errors
                        .first()
                        .is_some_and(|error| error == CAPACITY_REJECTION)
                {
                    return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
                }
                (
                    [("content-type", "application/x-protobuf")],
                    response.encode_to_vec(),
                )
                    .into_response()
            }
            Err(_) => axum::http::StatusCode::BAD_REQUEST.into_response(),
        }
    }

    async fn handle_traces(
        axum::extract::State(shared): axum::extract::State<Arc<OtelShared>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        shared
            .metrics
            .requests_total
            .fetch_add(1, Ordering::Relaxed);
        let is_proto = is_protobuf(&headers);

        let req = if is_proto {
            otlp::ExportTraceServiceRequest::decode(&body[..])
        } else {
            // JSON: try to decode via serde then re-encode to proto
            // For simplicity, attempt protobuf decode of JSON content too
            // (real OTLP/JSON would need proper JSON→proto mapping)
            Err(prost::DecodeError::new(
                "json not yet supported as protobuf",
            ))
        };

        match req {
            Ok(req) => {
                let envelopes = convert_traces(&req);
                let count = envelopes.len();
                shared
                    .metrics
                    .spans_received
                    .fetch_add(count as u64, Ordering::Relaxed);

                if shared.try_send(envelopes) < count {
                    return (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        "receiver capacity exceeded",
                    )
                        .into_response();
                }
                axum::http::StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!(error = %e, "failed to decode trace request");
                (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
        }
    }

    async fn handle_metrics(
        axum::extract::State(shared): axum::extract::State<Arc<OtelShared>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        shared
            .metrics
            .requests_total
            .fetch_add(1, Ordering::Relaxed);
        let is_proto = is_protobuf(&headers);

        let req = if is_proto {
            otlp::ExportMetricsServiceRequest::decode(&body[..])
        } else {
            Err(prost::DecodeError::new(
                "json not yet supported as protobuf",
            ))
        };

        match req {
            Ok(req) => {
                let envelopes = convert_metrics(&req);
                let count = envelopes.len();
                shared
                    .metrics
                    .metrics_received
                    .fetch_add(count as u64, Ordering::Relaxed);

                if shared.try_send(envelopes) < count {
                    return (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        "receiver capacity exceeded",
                    )
                        .into_response();
                }
                axum::http::StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!(error = %e, "failed to decode metrics request");
                (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
        }
    }

    async fn handle_logs(
        axum::extract::State(shared): axum::extract::State<Arc<OtelShared>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        shared
            .metrics
            .requests_total
            .fetch_add(1, Ordering::Relaxed);
        let is_proto = is_protobuf(&headers);

        let req = if is_proto {
            otlp::ExportLogsServiceRequest::decode(&body[..])
        } else {
            Err(prost::DecodeError::new(
                "json not yet supported as protobuf",
            ))
        };

        match req {
            Ok(req) => {
                let envelopes = convert_logs(&req);
                let count = envelopes.len();
                shared
                    .metrics
                    .logs_received
                    .fetch_add(count as u64, Ordering::Relaxed);

                if shared.try_send(envelopes) < count {
                    return (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        "receiver capacity exceeded",
                    )
                        .into_response();
                }
                axum::http::StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!(error = %e, "failed to decode logs request");
                (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
        }
    }

    fn is_protobuf(headers: &axum::http::HeaderMap) -> bool {
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("protobuf"))
            .unwrap_or(true) // default to protobuf
    }

    use axum::response::IntoResponse;
}

// ---------------------------------------------------------------------------
// Stub gRPC/HTTP servers (when otel feature is disabled)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "otel"))]
mod grpc_server {
    use super::*;

    pub async fn run(
        _shared: Arc<OtelShared>,
        _cancel: CancellationToken,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[cfg(not(feature = "otel"))]
mod http_server {
    use super::*;

    pub async fn run(
        _shared: Arc<OtelShared>,
        _cancel: CancellationToken,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Rate limit reset task
// ---------------------------------------------------------------------------

async fn rate_limit_reset_loop(metrics: OtelMetrics, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                metrics.rate_counter.store(0, Ordering::Relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OtelCollector
// ---------------------------------------------------------------------------

/// OpenTelemetry passthrough collector.
///
/// Runs gRPC (localhost:4317) and HTTP (localhost:4318) listeners that accept
/// OTLP data, convert it into Envelopes, and buffer them. The scheduler
/// drains the buffer via `collect()` every second.
pub struct OtelCollector {
    buffer_rx: Mutex<mpsc::Receiver<Envelope>>,
    cancel: CancellationToken,
    metrics: OtelMetrics,
    #[cfg(feature = "otel")]
    #[allow(dead_code)]
    enabled: bool,
}

impl OtelCollector {
    pub fn new(rate_limit: Option<u64>) -> Self {
        let (tx, rx) = mpsc::channel(BUFFER_CAPACITY);
        let cancel = CancellationToken::new();
        let metrics = OtelMetrics::new();
        let rate_limit = rate_limit.unwrap_or(DEFAULT_RATE_LIMIT_PER_SEC);

        let shared = Arc::new(OtelShared {
            envelope_tx: tx,
            metrics: metrics.clone(),
            rate_limit_per_sec: rate_limit,
        });

        #[cfg(feature = "otel")]
        let enabled = {
            // Spawn rate limit reset task
            let rl_metrics = metrics.clone();
            let rl_cancel = cancel.clone();
            tokio::spawn(rate_limit_reset_loop(rl_metrics, rl_cancel));

            // Spawn gRPC server
            let grpc_shared = shared.clone();
            let grpc_cancel = cancel.clone();
            tokio::spawn(async move {
                if let Err(e) = grpc_server::run(grpc_shared, grpc_cancel).await {
                    warn!(error = %e, "OTEL gRPC server failed");
                }
            });

            // Spawn HTTP server
            let http_shared = shared;
            let http_cancel = cancel.clone();
            tokio::spawn(async move {
                if let Err(e) = http_server::run(http_shared, http_cancel).await {
                    warn!(error = %e, "OTEL HTTP server failed");
                }
            });

            info!(
                grpc_addr = GRPC_LISTEN_ADDR,
                http_addr = HTTP_LISTEN_ADDR,
                rate_limit = rate_limit,
                buffer_capacity = BUFFER_CAPACITY,
                "OTEL passthrough collector started"
            );
            true
        };

        #[cfg(not(feature = "otel"))]
        {
            info!("OTEL collector disabled (feature not enabled)");
        }

        Self {
            buffer_rx: Mutex::new(rx),
            cancel,
            metrics,
            #[cfg(feature = "otel")]
            enabled,
        }
    }
}

impl Collector for OtelCollector {
    fn name(&self) -> &str {
        "otel"
    }

    fn signal_type(&self) -> SignalType {
        // OTEL produces traces, metrics, and logs. Report Trace as primary;
        // individual envelopes carry their own SignalType.
        SignalType::Trace
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn collect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>> {
        Box::pin(async move {
            let mut rx = self.buffer_rx.lock().await;
            let mut envelopes = Vec::new();

            // Drain all available envelopes from the buffer
            while let Ok(env) = rx.try_recv() {
                envelopes.push(env);
            }

            // Emit internal OTEL metrics
            let requests = self.metrics.requests_total.load(Ordering::Relaxed);
            let spans = self.metrics.spans_received.load(Ordering::Relaxed);
            let metrics_count = self.metrics.metrics_received.load(Ordering::Relaxed);
            let logs_count = self.metrics.logs_received.load(Ordering::Relaxed);
            let dropped = self.metrics.dropped.load(Ordering::Relaxed);

            if requests > 0 || !envelopes.is_empty() {
                envelopes.push(helpers::metric_envelope(
                    "otel.requests_total",
                    requests as f64,
                    &[],
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "otel.spans_received",
                    spans as f64,
                    &[],
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "otel.metrics_received",
                    metrics_count as f64,
                    &[],
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "otel.logs_received",
                    logs_count as f64,
                    &[],
                    "counter",
                ));
                envelopes.push(helpers::metric_envelope(
                    "otel.dropped",
                    dropped as f64,
                    &[],
                    "counter",
                ));
            }

            Ok(envelopes)
        })
    }
}

impl Drop for OtelCollector {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{log_level, LogPayload, MetricPayload, MetricType};
    use prost::Message;

    fn shared(capacity: usize, rate: u64) -> (OtelShared, mpsc::Receiver<Envelope>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            OtelShared {
                envelope_tx: tx,
                metrics: OtelMetrics::new(),
                rate_limit_per_sec: rate,
            },
            rx,
        )
    }
    fn sdk_envelope(signal: i32) -> agent_transport::proto::AgentEnvelope {
        agent_transport::proto::AgentEnvelope {
            agent_id: "forged-agent".into(),
            hostname: "forged-host".into(),
            signal_type: signal,
            compression: agent_transport::proto::Compression::None as i32,
            timestamp_unix_ns: 100,
            payload: vec![1, 2],
            buffered: true,
            retry_count: 99,
            ..Default::default()
        }
    }
    #[test]
    fn native_receiver_strips_identity_and_rejects_privileged_signals() {
        let (shared, mut rx) = shared(10, 10);
        let result = shared.submit_native(agent_transport::proto::SubmitBatchRequest {
            envelopes: vec![sdk_envelope(1), sdk_envelope(6)],
        });
        assert_eq!((result.accepted, result.rejected), (1, 1));
        let envelope = rx.try_recv().expect("accepted envelope");
        assert_eq!(envelope.signal_type, SignalType::Metric);
        assert!(!envelope.buffered);
        assert_eq!(envelope.retry_count, 0);
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn admission_rejects_entire_batch_without_partial_duplicates() {
        let (shared, mut rx) = shared(1, 10);
        let result = shared.submit_native(agent_transport::proto::SubmitBatchRequest {
            envelopes: vec![sdk_envelope(1), sdk_envelope(1)],
        });
        assert_eq!((result.accepted, result.rejected), (0, 2));
        assert!(rx.try_recv().is_err());
        assert_eq!(shared.metrics.dropped.load(Ordering::Relaxed), 2);
        let (shared, mut rx) = self::shared(10, 1);
        let result = shared.submit_native(agent_transport::proto::SubmitBatchRequest {
            envelopes: vec![sdk_envelope(1), sdk_envelope(1)],
        });
        assert_eq!((result.accepted, result.rejected), (0, 2));
        assert!(rx.try_recv().is_err());
        assert_eq!(shared.metrics.dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn listen_addresses_are_localhost() {
        assert!(GRPC_LISTEN_ADDR.starts_with("127.0.0.1"));
        assert!(HTTP_LISTEN_ADDR.starts_with("127.0.0.1"));
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex::encode(&[0xab, 0xcd, 0x12, 0x34]), "abcd1234");
        assert_eq!(hex::encode(&[]), "");
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(severity_to_str(1), "TRACE");
        assert_eq!(severity_to_str(5), "DEBUG");
        assert_eq!(severity_to_str(9), "INFO");
        assert_eq!(severity_to_str(13), "WARN");
        assert_eq!(severity_to_str(17), "ERROR");
        assert_eq!(severity_to_str(21), "FATAL");
        assert_eq!(severity_to_str(0), "INFO"); // default
    }

    #[test]
    fn convert_traces_basic() {
        let req = otlp::ExportTraceServiceRequest {
            resource_spans: vec![otlp::ResourceSpans {
                resource: Some(otlp::Resource {
                    attributes: vec![otlp::KeyValue {
                        key: "service.name".to_string(),
                        value: Some(otlp::AnyValue {
                            value: Some(otlp::any_value::Value::StringValue(
                                "test-svc".to_string(),
                            )),
                        }),
                    }],
                }),
                scope_spans: vec![otlp::ScopeSpans {
                    scope: None,
                    spans: vec![otlp::Span {
                        trace_id: vec![0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        span_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0],
                        parent_span_id: vec![],
                        name: "GET /api".to_string(),
                        kind: 2, // SERVER
                        start_time_unix_nano: 1000000,
                        end_time_unix_nano: 2000000,
                        attributes: vec![],
                        status: Some(otlp::SpanStatus {
                            message: String::new(),
                            code: 1, // OK
                        }),
                        trace_state: String::new(),
                    }],
                }],
            }],
        };

        let envelopes = convert_traces(&req);
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].signal_type, SignalType::Trace);

        let payload: serde_json::Value = serde_json::from_slice(&envelopes[0].payload).unwrap();
        assert_eq!(payload["service_name"], "test-svc");
        assert_eq!(payload["operation_name"], "GET /api");
        assert_eq!(payload["kind"], "SERVER");
        assert_eq!(payload["status_code"], "OK");
        assert_eq!(payload["source"], "otel");
    }

    #[test]
    fn convert_metrics_gauge() {
        let req = otlp::ExportMetricsServiceRequest {
            resource_metrics: vec![otlp::ResourceMetrics {
                resource: Some(otlp::Resource {
                    attributes: vec![otlp::KeyValue {
                        key: "service.name".to_string(),
                        value: Some(otlp::AnyValue {
                            value: Some(otlp::any_value::Value::StringValue("my-app".to_string())),
                        }),
                    }],
                }),
                scope_metrics: vec![otlp::ScopeMetrics {
                    scope: None,
                    metrics: vec![otlp::Metric {
                        name: "http.request.duration".to_string(),
                        description: String::new(),
                        unit: "ms".to_string(),
                        data: Some(otlp::metric::Data::Gauge(otlp::Gauge {
                            data_points: vec![otlp::NumberDataPoint {
                                attributes: vec![],
                                time_unix_nano: 100,
                                value: Some(otlp::number_data_point::Value::AsDouble(42.5)),
                            }],
                        })),
                    }],
                }],
            }],
        };

        let envelopes = convert_metrics(&req);
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].signal_type, SignalType::Metric);

        let payload = MetricPayload::decode(envelopes[0].payload.as_slice()).unwrap();
        assert_eq!(payload.name, "http.request.duration");
        assert!((payload.value - 42.5).abs() < f64::EPSILON);
        assert_eq!(payload.metric_type, MetricType::Gauge as i32);
    }

    #[test]
    fn convert_logs_with_trace_context() {
        let req = otlp::ExportLogsServiceRequest {
            resource_logs: vec![otlp::ResourceLogs {
                resource: Some(otlp::Resource {
                    attributes: vec![otlp::KeyValue {
                        key: "service.name".to_string(),
                        value: Some(otlp::AnyValue {
                            value: Some(otlp::any_value::Value::StringValue("log-svc".to_string())),
                        }),
                    }],
                }),
                scope_logs: vec![otlp::ScopeLogs {
                    scope: None,
                    log_records: vec![otlp::LogRecord {
                        time_unix_nano: 100,
                        severity_number: 17, // ERROR
                        severity_text: "ERROR".to_string(),
                        body: Some(otlp::AnyValue {
                            value: Some(otlp::any_value::Value::StringValue(
                                "connection refused".to_string(),
                            )),
                        }),
                        attributes: vec![],
                        trace_id: vec![0xab, 0xcd],
                        span_id: vec![0x12, 0x34],
                    }],
                }],
            }],
        };

        let envelopes = convert_logs(&req);
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].signal_type, SignalType::Log);

        let payload = LogPayload::decode(envelopes[0].payload.as_slice()).unwrap();
        assert_eq!(payload.message, "connection refused");
        assert_eq!(payload.level, log_level::ERROR);
        assert_eq!(payload.trace_id, "abcd");
        assert_eq!(payload.source, "otel");
    }

    #[test]
    fn buffer_capacity_constant() {
        assert_eq!(BUFFER_CAPACITY, 10_000);
    }

    #[tokio::test]
    async fn shared_try_send_respects_buffer() {
        let (tx, mut rx) = mpsc::channel(2);
        let shared = OtelShared {
            envelope_tx: tx,
            metrics: OtelMetrics::new(),
            rate_limit_per_sec: 100,
        };

        let env = Envelope {
            signal_type: SignalType::Trace,
            payload: vec![],
            timestamp_unix_ns: 0,
            buffered: false,
            retry_count: 0,
        };

        // Fill buffer
        assert_eq!(shared.try_send(vec![env.clone(), env.clone()]), 2);
        // Buffer full → dropped
        assert_eq!(shared.try_send(vec![env.clone()]), 0);
        assert_eq!(shared.metrics.dropped.load(Ordering::Relaxed), 1);

        // Drain
        rx.recv().await;
        rx.recv().await;
    }
}
