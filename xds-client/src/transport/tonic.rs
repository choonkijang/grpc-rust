//! `tonic` based transport implementation.
//!
//! This transport uses tonic's low-level `Grpc` client with a `BytesCodec`
//! to send and receive raw bytes, allowing the xDS client layer to handle
//! serialization/deserialization independently.

use crate::client::config::ServerConfig;
use crate::error::{Error, Result};
use crate::transport::{Transport, TransportBuilder, TransportStream};
use bytes::{Buf, BufMut, Bytes};
// BID-2147: GCP ADC auth for `google_default` xDS-server creds (Traffic Director).
use google_cloud_auth::credentials::{AccessTokenCredentials, Builder as GcpCredBuilder};
use http::uri::PathAndQuery;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Channel, Endpoint};
use tonic::{Status, Streaming};

/// The gRPC path for the ADS StreamAggregatedResources RPC.
const ADS_PATH: &str =
    "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources";

const ADS_CHANNEL_BUFFER_SIZE: usize = 16;

/// A codec that passes bytes through without serialization.
///
/// This allows us to handle serialization in the xDS client layer
/// rather than in the transport layer.
#[derive(Debug, Clone, Copy)]
struct BytesCodec;

impl Codec for BytesCodec {
    type Encode = Bytes;
    type Decode = Bytes;
    type Encoder = BytesEncoder;
    type Decoder = BytesDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        BytesEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        BytesDecoder
    }
}

#[derive(Debug)]
struct BytesEncoder;

impl Encoder for BytesEncoder {
    type Item = Bytes;
    type Error = Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut EncodeBuf<'_>,
    ) -> std::result::Result<(), Self::Error> {
        dst.put_slice(&item);
        Ok(())
    }
}

#[derive(Debug)]
struct BytesDecoder;

impl Decoder for BytesDecoder {
    type Item = Bytes;
    type Error = Status;

    fn decode(
        &mut self,
        src: &mut DecodeBuf<'_>,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        Ok(Some(src.copy_to_bytes(src.remaining())))
    }
}

/// Factory for creating ADS streams using tonic.
#[derive(Clone)]
pub struct TonicTransport {
    channel: Channel,
    /// BID-2147: GCP ADC credentials for `google_default` xDS-server auth. When
    /// present, `new_stream` attaches `authorization: Bearer <token>` to the ADS
    /// stream (required to talk to Traffic Director).
    creds: Option<Arc<AccessTokenCredentials>>,
}

impl std::fmt::Debug for TonicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TonicTransport")
            .field("channel", &self.channel)
            .field("google_default_creds", &self.creds.is_some())
            .finish()
    }
}

impl TonicTransport {
    /// Create a transport from an existing tonic [`Channel`].
    ///
    /// Use this when you need custom channel configuration (e.g., TLS, timeouts).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tonic::transport::{Certificate, Channel, ClientTlsConfig};
    ///
    /// let tls = ClientTlsConfig::new()
    ///     .ca_certificate(Certificate::from_pem(ca_cert))
    ///     .domain_name("xds.example.com");
    ///
    /// let channel = Channel::from_static("https://xds.example.com:443")
    ///     .tls_config(tls)?
    ///     .connect()
    ///     .await?;
    ///
    /// let transport = TonicTransport::from_channel(channel);
    /// ```
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            channel,
            creds: None,
        }
    }

    /// Connect to an xDS server with default settings.
    ///
    /// For custom configuration (TLS, timeouts, etc.), use [`from_channel`](Self::from_channel).
    pub async fn connect(uri: impl Into<String>) -> Result<Self> {
        let server = ServerConfig::new(uri.into());
        TonicTransportBuilder::new().build(&server).await
    }
}

/// Builder for creating [`TonicTransport`] instances.
///
/// This implements [`TransportBuilder`] and can be used with
/// [`XdsClientBuilder`](crate::XdsClientBuilder) to enable server fallback support.
///
/// # Example
///
/// ```ignore
/// use xds_client::{ClientConfig, Node, TonicTransportBuilder, XdsClient};
///
/// let transport_builder = TonicTransportBuilder::new();
/// let config = ClientConfig::new(node, "http://xds.example.com:18000");
/// let client = XdsClient::builder(config, transport_builder, codec, runtime).build();
/// ```
///
/// # TLS
///
/// Enable the `tls-ring` or `tls-aws-lc` feature and call [`with_tls_config`](Self::with_tls_config):
///
/// ```ignore
/// use tonic::transport::ClientTlsConfig;
/// use xds_client::TonicTransportBuilder;
///
/// let builder = TonicTransportBuilder::new()
///     .with_tls_config(ClientTlsConfig::new().with_enabled_roots());
/// ```
#[derive(Debug, Clone, Default)]
pub struct TonicTransportBuilder {
    // Future extensions:
    // - Connection timeout settings
    // - Keep-alive configuration
    // - Connection pooling settings
    // - Per-server credential overrides (via ServerConfig.extensions)
    #[cfg(any(feature = "tonic-tls-ring", feature = "tonic-tls-aws-lc"))]
    tls_config: Option<tonic::transport::ClientTlsConfig>,
    /// BID-2147: use GCP `google_default` credentials for the xDS-server
    /// connection (Traffic Director): forces TLS (system roots) + attaches a
    /// per-stream ADC bearer token. Set from the bootstrap `channel_creds`.
    google_default: bool,
}

impl TonicTransportBuilder {
    /// Create a new transport builder with default (plaintext) settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the TLS configuration for connections to the xDS server.
    ///
    /// When set, all connections created by this builder will use TLS
    /// with the provided configuration.
    #[cfg(any(feature = "tonic-tls-ring", feature = "tonic-tls-aws-lc"))]
    pub fn with_tls_config(mut self, tls_config: tonic::transport::ClientTlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// BID-2147: enable GCP `google_default` xDS-server credentials (TLS + ADC
    /// bearer token), as required to reach Traffic Director
    /// (`trafficdirector.googleapis.com:443`). Mirrors `common::xds::client`.
    pub fn with_google_default(mut self, enabled: bool) -> Self {
        self.google_default = enabled;
        self
    }

    /// Build a TLS channel to the xDS server with a GCP ADC token source
    /// (`google_default`). Forces an `https://` scheme + system roots.
    #[cfg(any(feature = "tonic-tls-ring", feature = "tonic-tls-aws-lc"))]
    async fn build_google_default(&self, server: &ServerConfig) -> Result<TonicTransport> {
        let raw = server.uri();
        let host = raw.rsplit_once(':').map(|(h, _)| h).unwrap_or(raw).to_string();
        let uri = if raw.contains("://") {
            raw.to_string()
        } else {
            format!("https://{raw}")
        };
        let tls = tonic::transport::ClientTlsConfig::new()
            .domain_name(host)
            .with_enabled_roots();
        let channel = Endpoint::from_shared(uri)
            .map_err(|e| Error::Connection(e.to_string()))?
            .tls_config(tls)
            .map_err(|e| Error::Connection(e.to_string()))?
            .connect()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;
        let creds = GcpCredBuilder::default()
            .with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
            .build_access_token_credentials()
            .map_err(|e| Error::Connection(format!("google_default credentials: {e}")))?;
        Ok(TonicTransport {
            channel,
            creds: Some(Arc::new(creds)),
        })
    }

    #[cfg(not(any(feature = "tonic-tls-ring", feature = "tonic-tls-aws-lc")))]
    async fn build_google_default(&self, _server: &ServerConfig) -> Result<TonicTransport> {
        Err(Error::Connection(
            "google_default xDS creds require a TLS feature (tonic-tls-ring / tonic-tls-aws-lc)"
                .into(),
        ))
    }
}

impl TransportBuilder for TonicTransportBuilder {
    type Transport = TonicTransport;

    async fn build(&self, server: &ServerConfig) -> Result<Self::Transport> {
        // BID-2147: `google_default` (Traffic Director) needs TLS + an ADC bearer
        // token — handled separately so the plaintext path stays unchanged.
        if self.google_default {
            return self.build_google_default(server).await;
        }

        // `Endpoint::from_shared` routes `unix://` URIs to tonic's UDS connector.
        // Required for control planes like Istio's grpc-agent that ship `unix:///etc/istio/proxy/XDS`.
        let endpoint = Endpoint::from_shared(server.uri().to_string())
            .map_err(|e| Error::Connection(e.to_string()))?;

        #[cfg(any(feature = "tonic-tls-ring", feature = "tonic-tls-aws-lc"))]
        let endpoint = match &self.tls_config {
            Some(tls) => endpoint
                .tls_config(tls.clone())
                .map_err(|e| Error::Connection(e.to_string()))?,
            None => endpoint,
        };

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        Ok(TonicTransport::from_channel(channel))
    }
}

impl Transport for TonicTransport {
    type Stream = TonicAdsStream;

    async fn new_stream(&self, initial_requests: Vec<Bytes>) -> Result<Self::Stream> {
        let mut grpc = Grpc::new(self.channel.clone());

        grpc.ready()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        let (tx, rx) = mpsc::channel::<Bytes>(ADS_CHANNEL_BUFFER_SIZE);

        // Create a stream that first yields initial requests, then reads from the channel.
        // This ensures data is available immediately when the stream is polled,
        // preventing deadlock with servers that don't send response headers
        // until they receive the first request message.
        let initial_stream = tokio_stream::iter(initial_requests);
        let channel_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let request_stream = initial_stream.chain(channel_stream);

        let path = PathAndQuery::from_static(ADS_PATH);

        // BID-2147: for `google_default`, attach the GCP ADC bearer token to the
        // ADS stream (Traffic Director rejects unauthenticated streams).
        let mut request = tonic::Request::new(request_stream);
        if let Some(creds) = &self.creds {
            let token = creds
                .access_token()
                .await
                .map_err(|e| Error::Connection(format!("google_default token fetch: {e}")))?;
            let value =
                tonic::metadata::MetadataValue::try_from(format!("Bearer {}", token.token))
                    .map_err(|e| Error::Connection(format!("google_default token metadata: {e}")))?;
            request.metadata_mut().insert("authorization", value);
        }

        let response = grpc
            .streaming(request, path, BytesCodec)
            .await
            .map_err(Error::Stream)?;

        Ok(TonicAdsStream {
            sender: tx,
            receiver: response.into_inner(),
        })
    }
}

/// A bidirectional ADS stream backed by tonic.
#[derive(Debug)]
pub struct TonicAdsStream {
    sender: mpsc::Sender<Bytes>,
    receiver: Streaming<Bytes>,
}

impl TransportStream for TonicAdsStream {
    async fn send(&mut self, request: Bytes) -> Result<()> {
        self.sender
            .send(request)
            .await
            .map_err(|_| Error::StreamClosed)?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Bytes>> {
        match self.receiver.message().await {
            Ok(msg) => Ok(msg),
            Err(status) => Err(Error::Stream(status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::service::discovery::v3::{
        DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
        aggregated_discovery_service_server::{
            AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
        },
    };
    use prost::Message;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use tokio::net::TcpListener;
    use tokio_stream::Stream;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    /// Mock ADS server that echoes back a response for each request.
    struct MockAdsServer;

    #[tonic::async_trait]
    impl AggregatedDiscoveryService for MockAdsServer {
        type StreamAggregatedResourcesStream =
            Pin<Box<dyn Stream<Item = std::result::Result<DiscoveryResponse, Status>> + Send>>;

        async fn stream_aggregated_resources(
            &self,
            request: Request<tonic::Streaming<DiscoveryRequest>>,
        ) -> std::result::Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
            let mut inbound = request.into_inner();

            let outbound = async_stream::try_stream! {
                while let Some(req) = inbound.next().await {
                    let req = req?;
                    let response = DiscoveryResponse {
                        version_info: "1".to_string(),
                        type_url: req.type_url.clone(),
                        nonce: "nonce-1".to_string(),
                        resources: vec![],
                        ..Default::default()
                    };
                    yield response;
                }
            };

            Ok(Response::new(Box::pin(outbound)))
        }

        type DeltaAggregatedResourcesStream =
            Pin<Box<dyn Stream<Item = std::result::Result<DeltaDiscoveryResponse, Status>> + Send>>;

        async fn delta_aggregated_resources(
            &self,
            _request: Request<tonic::Streaming<DeltaDiscoveryRequest>>,
        ) -> std::result::Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
            Err(Status::unimplemented("delta not supported in mock"))
        }
    }

    async fn start_mock_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(MockAdsServer))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        addr
    }

    #[tokio::test]
    async fn test_tonic_transport_connect_and_stream() {
        let addr = start_mock_server().await;
        let uri = format!("http://{addr}");

        let transport = TonicTransport::connect(&uri).await.unwrap();

        let request = DiscoveryRequest {
            type_url: "type.googleapis.com/envoy.config.listener.v3.Listener".to_string(),
            resource_names: vec!["listener-1".to_string()],
            ..Default::default()
        };
        let request_bytes: Bytes = request.encode_to_vec().into();

        let mut stream = transport.new_stream(vec![request_bytes]).await.unwrap();

        let response_bytes = stream.recv().await.unwrap().unwrap();
        let response = DiscoveryResponse::decode(response_bytes).unwrap();

        assert_eq!(response.version_info, "1");
        assert_eq!(
            response.type_url,
            "type.googleapis.com/envoy.config.listener.v3.Listener"
        );
        assert_eq!(response.nonce, "nonce-1");
    }
}
