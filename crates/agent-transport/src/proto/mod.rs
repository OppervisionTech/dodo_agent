/// Manually defined proto types matching dodo.proto.v1 schema.
/// Uses prost for serialization, tonic for gRPC transport.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AgentEnvelope {
    #[prost(string, tag = "1")]
    pub agent_id: String,
    #[prost(string, tag = "2")]
    pub agent_version: String,
    #[prost(string, tag = "3")]
    pub agent_variant: String,
    #[prost(string, tag = "4")]
    pub host_id: String,
    #[prost(string, tag = "5")]
    pub hostname: String,
    #[prost(string, tag = "6")]
    pub os_family: String,
    #[prost(string, tag = "7")]
    pub cluster_id: String,
    #[prost(int64, tag = "8")]
    pub timestamp_unix_ns: i64,
    #[prost(uint64, tag = "9")]
    pub sequence_id: u64,
    #[prost(enumeration = "SignalType", tag = "10")]
    pub signal_type: i32,
    #[prost(bytes = "vec", tag = "11")]
    pub payload: Vec<u8>,
    #[prost(enumeration = "Compression", tag = "12")]
    pub compression: i32,
    #[prost(bool, tag = "13")]
    pub buffered: bool,
    #[prost(uint32, tag = "14")]
    pub retry_count: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitBatchRequest {
    #[prost(message, repeated, tag = "1")]
    pub envelopes: Vec<AgentEnvelope>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitBatchResponse {
    #[prost(uint32, tag = "1")]
    pub accepted: u32,
    #[prost(uint32, tag = "2")]
    pub rejected: u32,
    #[prost(string, repeated, tag = "3")]
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SignalType {
    Unspecified = 0,
    Metric = 1,
    Log = 2,
    Trace = 3,
    Event = 4,
    Inventory = 5,
    Heartbeat = 6,
    SecurityEvent = 7,
    CustomEvent = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Compression {
    None = 0,
    Zstd = 1,
    Lz4 = 2,
}

/// Minimal tonic gRPC client for IngestorService.
pub mod ingestor_service_client {
    use super::{SubmitBatchRequest, SubmitBatchResponse};

    #[derive(Clone)]
    pub struct IngestorServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl IngestorServiceClient<tonic::transport::Channel> {
        pub fn new(channel: tonic::transport::Channel) -> Self {
            let inner = tonic::client::Grpc::new(channel);
            Self { inner }
        }
    }

    impl<T> IngestorServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
        <T::ResponseBody as tonic::codegen::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub async fn submit_batch(
            &mut self,
            request: impl tonic::IntoRequest<SubmitBatchRequest>,
        ) -> Result<tonic::Response<SubmitBatchResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|_| {
                tonic::Status::new(tonic::Code::Unknown, "service not ready")
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/dodo.proto.v1.IngestorService/SubmitBatch",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub use ingestor_service_client::IngestorServiceClient;
