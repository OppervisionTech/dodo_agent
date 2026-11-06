// gRPC client methods return tonic::Status, whose size is fixed by tonic;
// boxing it would diverge from the generated-client API.
#![allow(clippy::result_large_err)]
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
    Unspecified = 0,
    None = 1,
    Zstd = 2,
    Lz4 = 3,
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
            self.inner
                .ready()
                .await
                .map_err(|_| tonic::Status::new(tonic::Code::Unknown, "service not ready"))?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/dodo.proto.v1.IngestorService/SubmitBatch");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub use ingestor_service_client::IngestorServiceClient;

// ---------------------------------------------------------------------------
// AgentCommand / AgentCommandResult — bidirectional command channel
// ---------------------------------------------------------------------------

/// Command payload variants that the platform can send to an agent.
#[derive(Clone, PartialEq, ::prost::Oneof)]
pub enum AgentCommandPayload {
    #[prost(message, tag = "10")]
    RestartPod(RestartPodCmd),
    #[prost(message, tag = "11")]
    ScaleDeployment(ScaleDeploymentCmd),
    #[prost(message, tag = "12")]
    ExecInContainer(ExecInContainerCmd),
    #[prost(message, tag = "13")]
    GetPodLogs(GetPodLogsCmd),
    #[prost(message, tag = "14")]
    ApplyManifest(ApplyManifestCmd),
    #[prost(message, tag = "15")]
    Rollback(RollbackDeploymentCmd),
    #[prost(message, tag = "16")]
    DescribeResource(DescribeResourceCmd),
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AgentCommand {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub agent_id: String,
    #[prost(string, tag = "3")]
    pub issued_by: String,
    #[prost(int32, tag = "4")]
    pub timeout_s: i32,
    #[prost(oneof = "AgentCommandPayload", tags = "10, 11, 12, 13, 14, 15, 16")]
    pub payload: Option<AgentCommandPayload>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestartPodCmd {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub pod_name: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScaleDeploymentCmd {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub deployment: String,
    #[prost(int32, tag = "3")]
    pub replicas: i32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecInContainerCmd {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub pod: String,
    #[prost(string, tag = "3")]
    pub container: String,
    #[prost(string, repeated, tag = "4")]
    pub command: Vec<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPodLogsCmd {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub pod: String,
    #[prost(int32, tag = "3")]
    pub tail_lines: i32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApplyManifestCmd {
    #[prost(string, tag = "1")]
    pub manifest_yaml_b64: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RollbackDeploymentCmd {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub deployment: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DescribeResourceCmd {
    #[prost(string, tag = "1")]
    pub kind: String,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(string, tag = "3")]
    pub name: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AgentCommandResult {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub agent_id: String,
    #[prost(bool, tag = "3")]
    pub success: bool,
    #[prost(string, tag = "4")]
    pub output: String,
    #[prost(string, tag = "5")]
    pub error: String,
}

/// Minimal tonic gRPC client for CommandService.
pub mod command_service_client {
    use super::{AgentCommand, AgentCommandResult};

    #[derive(Clone)]
    pub struct CommandServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl CommandServiceClient<tonic::transport::Channel> {
        pub fn new(channel: tonic::transport::Channel) -> Self {
            let inner = tonic::client::Grpc::new(channel);
            Self { inner }
        }
    }

    impl<T> CommandServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
        <T::ResponseBody as tonic::codegen::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        /// Open a bidirectional stream for agent command dispatch.
        /// The agent sends AgentCommandResult; the server sends AgentCommand.
        pub async fn command_stream(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = AgentCommandResult>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<AgentCommand>>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|_| tonic::Status::new(tonic::Code::Unknown, "service not ready"))?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/dodo.proto.v1.CommandService/CommandStream");
            self.inner
                .streaming(request.into_streaming_request(), path, codec)
                .await
        }
    }
}

pub use command_service_client::CommandServiceClient;

#[cfg(test)]
mod canonical_wire_tests {
    use super::Compression;
    #[test]
    fn compression_values_match_canonical_proto() {
        assert_eq!(Compression::Unspecified as i32, 0);
        assert_eq!(Compression::None as i32, 1);
        assert_eq!(Compression::Zstd as i32, 2);
        assert_eq!(Compression::Lz4 as i32, 3);
    }
}
