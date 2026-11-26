use crate::config::ClientConfig;
use crate::config::DnsResolver;
use crate::config::ServerConfig;
use crate::connection::Connection;
use crate::driver::streams::session::StreamSession;
use crate::driver::streams::ProtoReadError;
use crate::driver::streams::ProtoWriteError;
use crate::driver::utils::varint_w2q;
use crate::driver::Driver;
use crate::error::ConnectingError;
use crate::error::ConnectionError;
use crate::VarInt;
use quinn::TokioRuntime;
use std::collections::HashMap;
use std::future::Future;
use std::future::IntoFuture;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use tracing::debug;
use url::Host;
use url::Url;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::headers::Headers;
use wtransport_proto::session::ReservedHeader;
use wtransport_proto::session::SessionRequest as SessionRequestProto;
use wtransport_proto::session::SessionResponse as SessionResponseProto;

/// Helper structure for Endpoint types.
pub mod endpoint_side {
    use super::*;

    /// Type of endpoint accepting multiple WebTransport connections.
    ///
    /// Use [`Endpoint::server`] to create and server-endpoint.
    pub struct Server {
        pub(super) _marker: PhantomData<()>,
    }

    /// Type of endpoint opening a WebTransport connection.
    ///
    /// Use [`Endpoint::client`] to create and client-endpoint.
    pub struct Client {
        pub(super) dns_resolver: Arc<dyn DnsResolver + Send + Sync>,
    }
}

/// Entrypoint for creating client or server connections.
///
/// A single endpoint can be used to accept or connect multiple connections.
/// Each endpoint internally binds an UDP socket.
///
/// # Server
/// Use [`Endpoint::server`] for creating a server-side endpoint.
/// Afterwards use the method [`Endpoint::accept`] for awaiting on incoming session request.
///
/// ```no_run
/// # use anyhow::Result;
/// # use wtransport::ServerConfig;
/// # use wtransport::Identity;
/// use wtransport::Endpoint;
///
/// # async fn run() -> Result<()> {
/// # let config = ServerConfig::builder()
/// #       .with_bind_default(4433)
/// #       .with_identity(Identity::self_signed(["doc"]).unwrap())
/// #       .build();
/// let server = Endpoint::server(config)?;
/// loop {
///     let incoming_session = server.accept().await;
///     // Spawn task that handles client incoming session...
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Client
/// Use [`Endpoint::client`] for creating a client-side endpoint and use [`Endpoint::connect`]
/// to connect to a server specifying the URL.
///
/// ```no_run
/// # use anyhow::Result;
/// use wtransport::ClientConfig;
/// use wtransport::Endpoint;
///
/// # async fn run() -> Result<()> {
/// let connection = Endpoint::client(ClientConfig::default())?
///     .connect("https://localhost:4433")
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Endpoint<Side> {
    endpoint: quinn::Endpoint,
    side: Side,
}

impl<Side> Endpoint<Side> {
    /// Closes all of this endpoint's connections immediately and cease accepting new connections.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.endpoint.close(varint_w2q(error_code), reason);
    }

    /// Waits for all connections on the endpoint to be cleanly shut down.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// Gets the local [`SocketAddr`] the underlying socket is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Get the number of connections that are currently open.
    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }
}

impl Endpoint<endpoint_side::Server> {
    /// Constructs a *server* endpoint.
    pub fn server(server_config: ServerConfig) -> std::io::Result<Self> {
        let endpoint_config = server_config.endpoint_config;
        let quic_config = server_config.quic_config;
        let socket = server_config.bind_address_config.bind_socket()?;
        let runtime = Arc::new(TokioRuntime);

        let endpoint = quinn::Endpoint::new(endpoint_config, Some(quic_config), socket, runtime)?;

        Ok(Self {
            endpoint,
            side: endpoint_side::Server {
                _marker: PhantomData,
            },
        })
    }

    /// Get the next incoming connection attempt from a client.
    pub async fn accept(&self) -> IncomingSession {
        let quic_incoming = self
            .endpoint
            .accept()
            .await
            .expect("Endpoint cannot be closed");

        debug!("New incoming QUIC connection");

        IncomingSession(quic_incoming)
    }

    /// Reloads the server configuration.
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    ///
    /// # Arguments
    ///
    /// * `server_config` - The new configuration for the server.
    /// * `rebind` - A boolean indicating whether the server should rebind its socket.
    ///   If `true`, the server will bind to a new socket with the provided configuration.
    ///   If `false`, the bind address configuration will be ignored.
    pub fn reload_config(&self, server_config: ServerConfig, rebind: bool) -> std::io::Result<()> {
        if rebind {
            let socket = server_config.bind_address_config.bind_socket()?;
            self.endpoint.rebind(socket)?;
        }

        let quic_config = server_config.quic_config;
        self.endpoint.set_server_config(Some(quic_config));

        Ok(())
    }
}

impl Endpoint<endpoint_side::Client> {
    /// Constructs a *client* endpoint.
    pub fn client(client_config: ClientConfig) -> std::io::Result<Self> {
        let endpoint_config = client_config.endpoint_config;
        let quic_config = client_config.quic_config;
        let socket = client_config.bind_address_config.bind_socket()?;
        let runtime = Arc::new(TokioRuntime);

        let mut endpoint = quinn::Endpoint::new(endpoint_config, None, socket, runtime)?;

        endpoint.set_default_client_config(quic_config);

        Ok(Self {
            endpoint,
            side: endpoint_side::Client {
                dns_resolver: client_config.dns_resolver,
            },
        })
    }

    /// Establishes a WebTransport connection to a specified URL.
    ///
    /// This method initiates a WebTransport connection to the specified URL.
    /// It validates the URL, and performs necessary steps to establish a secure connection.
    ///
    /// # Arguments
    ///
    /// * `options` - Connection options specifying the URL and additional headers.
    ///   It can be simply an [URL](https://en.wikipedia.org/wiki/URL) string representing
    ///   the WebTransport endpoint to connect to. It must have an `https` scheme.
    ///   The URL can specify either an IP address or a hostname.
    ///   When specifying a hostname, the method will internally perform DNS resolution,
    ///   configured with
    ///   [`ClientConfigBuilder::dns_resolver`](crate::config::ClientConfigBuilder::dns_resolver).
    ///
    /// # Examples
    ///
    /// Connect using a URL with a hostname (DNS resolution is performed):
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use wtransport::endpoint::endpoint_side::Client;
    /// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
    /// let url = "https://example.com:4433/webtransport";
    /// let connection = endpoint.connect(url).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Connect using a URL with an IP address:
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use wtransport::endpoint::endpoint_side::Client;
    /// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
    /// let url = "https://127.0.0.1:4343/webtransport";
    /// let connection = endpoint.connect(url).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Connect adding an additional header:
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use wtransport::endpoint::endpoint_side::Client;
    /// # use wtransport::endpoint::ConnectOptions;
    /// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
    /// let options = ConnectOptions::builder("https://example.com:4433/webtransport")
    ///     .add_header("Authorization", "AuthToken")
    ///     .build();
    /// let connection = endpoint.connect(options).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect<O>(&self, options: O) -> Result<Connection, ConnectingError>
    where
        O: IntoConnectOptions,
    {
        let options = options.into_options();

        let url = Url::parse(&options.url)
            .map_err(|parse_error| ConnectingError::InvalidUrl(parse_error.to_string()))?;

        if url.scheme() != "https" {
            return Err(ConnectingError::InvalidUrl(
                "WebTransport URL scheme must be 'https'".to_string(),
            ));
        }

        let host = url.host().expect("https scheme must have an host");
        let port = url.port().unwrap_or(443);

        let (socket_address, server_name) = match host {
            Host::Domain(domain) => {
                let socket_address = self
                    .side
                    .dns_resolver
                    .resolve(&format!("{domain}:{port}"))
                    .await
                    .map_err(ConnectingError::DnsLookup)?
                    .ok_or(ConnectingError::DnsNotFound)?;

                (socket_address, domain.to_string())
            }
            Host::Ipv4(address) => {
                let socket_address = SocketAddr::V4(SocketAddrV4::new(address, port));
                (socket_address, address.to_string())
            }
            Host::Ipv6(address) => {
                let socket_address = SocketAddr::V6(SocketAddrV6::new(address, port, 0, 0));
                (socket_address, address.to_string())
            }
        };

        let quic_connection = self
            .endpoint
            .connect(socket_address, &server_name)
            .map_err(ConnectingError::with_connect_error)?
            .await
            .map_err(|connection_error| {
                ConnectingError::ConnectionError(connection_error.into())
            })?;

        let driver = Driver::init(quic_connection.clone());

        let _settings = driver.accept_settings().await.map_err(|driver_error| {
            ConnectingError::ConnectionError(ConnectionError::with_driver_error(
                driver_error,
                &quic_connection,
            ))
        })?;

        // TODO(biagio): validate settings

        let mut session_request_proto =
            SessionRequestProto::new(url.as_ref()).expect("Url has been already validate");

        for (k, v) in options.additional_headers {
            session_request_proto
                .insert(k.clone(), v)
                .map_err(|ReservedHeader| ConnectingError::ReservedHeader(k))?;
        }

        let mut stream_session = match driver.open_session(session_request_proto).await {
            Ok(stream_session) => stream_session,
            Err(driver_error) => {
                return Err(ConnectingError::ConnectionError(
                    ConnectionError::with_driver_error(driver_error, &quic_connection),
                ))
            }
        };

        let session_id = stream_session.session_id();

        match stream_session
            .write_frame(stream_session.request().headers().generate_frame())
            .await
        {
            Ok(()) => {}
            Err(ProtoWriteError::Stopped) => {
                return Err(ConnectingError::SessionRejected);
            }
            Err(ProtoWriteError::NotConnected) => {
                return Err(ConnectingError::with_no_connection(&quic_connection));
            }
        }

        let frame = loop {
            let frame = match stream_session.read_frame().await {
                Ok(frame) => frame,
                Err(ProtoReadError::H3(error_code)) => {
                    quic_connection.close(varint_w2q(error_code.to_code()), b"");
                    return Err(ConnectingError::ConnectionError(
                        ConnectionError::local_h3_error(error_code),
                    ));
                }
                Err(ProtoReadError::IO(_io_error)) => {
                    return Err(ConnectingError::with_no_connection(&quic_connection));
                }
            };

            if let FrameKind::Exercise(_) = frame.kind() {
                continue;
            }
            break frame;
        };

        if !matches!(frame.kind(), FrameKind::Headers) {
            quic_connection.close(varint_w2q(ErrorCode::FrameUnexpected.to_code()), b"");
            return Err(ConnectingError::ConnectionError(
                ConnectionError::local_h3_error(ErrorCode::FrameUnexpected),
            ));
        }

        let headers = match Headers::with_frame(&frame) {
            Ok(headers) => headers,
            Err(error_code) => {
                quic_connection.close(varint_w2q(error_code.to_code()), b"");
                return Err(ConnectingError::ConnectionError(
                    ConnectionError::local_h3_error(error_code),
                ));
            }
        };

        let Ok(session_response) = SessionResponseProto::try_from(headers) else {
            quic_connection.close(varint_w2q(ErrorCode::Message.to_code()), b"");
            return Err(ConnectingError::ConnectionError(
                ConnectionError::local_h3_error(ErrorCode::Message),
            ));
        };

        if session_response.code().is_successful() {
            match driver.register_session(stream_session).await {
                Ok(()) => {}
                Err(driver_error) => {
                    return Err(ConnectingError::ConnectionError(
                        ConnectionError::with_driver_error(driver_error, &quic_connection),
                    ))
                }
            }
        } else {
            return Err(ConnectingError::SessionRejected);
        }

        Ok(Connection::new(quic_connection, driver, session_id))
    }
}

/// Options for establishing a client WebTransport connection.
///
/// Used in [`Endpoint::connect`].
///
/// # Examples
///
/// ```no_run
/// # use anyhow::Result;
/// # use wtransport::endpoint::endpoint_side::Client;
/// # use wtransport::endpoint::ConnectOptions;
/// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
/// let options = ConnectOptions::builder("https://example.com:4433/webtransport")
///     .add_header("Authorization", "AuthToken")
///     .build();
/// let connection = endpoint.connect(options).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    url: String,
    additional_headers: HashMap<String, String>,
}

impl ConnectOptions {
    /// Creates a new `ConnectOptions` using a builder pattern.
    ///
    /// # Arguments
    ///
    /// * `url` - A [URL](https://en.wikipedia.org/wiki/URL) string representing the WebTransport
    ///   endpoint to connect to. It must have an `https` scheme.
    ///   The URL can specify either an IP address or a hostname.
    ///   When specifying a hostname, the method will internally perform DNS resolution,
    ///   configured with
    ///   [`ClientConfigBuilder::dns_resolver`](crate::config::ClientConfigBuilder::dns_resolver).
    pub fn builder<S>(url: S) -> ConnectRequestBuilder
    where
        S: ToString,
    {
        ConnectRequestBuilder {
            url: url.to_string(),
            additional_headers: Default::default(),
        }
    }

    /// Gets the URL which this will connect to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Gets the additional headers that will be passed when connecting.
    pub fn additional_headers(&self) -> &HashMap<String, String> {
        &self.additional_headers
    }
}

/// A trait for converting types into `ConnectOptions`.
pub trait IntoConnectOptions {
    /// Perform value-to-value conversion into [`ConnectOptions`].
    fn into_options(self) -> ConnectOptions;
}

/// A builder for [`ConnectOptions`].
///
/// See [`ConnectOptions::builder`].
pub struct ConnectRequestBuilder {
    url: String,
    additional_headers: HashMap<String, String>,
}

impl ConnectRequestBuilder {
    /// Adds a header to the connection options.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use wtransport::endpoint::ConnectOptions;
    ///
    /// let options = ConnectOptions::builder("https://example.com:4433/webtransport")
    ///     .add_header("Authorization", "AuthToken")
    ///     .build();
    /// ```
    pub fn add_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: ToString,
        V: ToString,
    {
        self.additional_headers
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Constructs the [`ConnectOptions`] from the builder configuration.
    pub fn build(self) -> ConnectOptions {
        ConnectOptions {
            url: self.url,
            additional_headers: self.additional_headers,
        }
    }
}

impl IntoConnectOptions for ConnectRequestBuilder {
    fn into_options(self) -> ConnectOptions {
        self.build()
    }
}

impl IntoConnectOptions for ConnectOptions {
    fn into_options(self) -> ConnectOptions {
        self
    }
}

impl<S> IntoConnectOptions for S
where
    S: ToString,
{
    fn into_options(self) -> ConnectOptions {
        ConnectOptions::builder(self).build()
    }
}

type DynFutureIncomingSession =
    dyn Future<Output = Result<SessionRequest, ConnectionError>> + Send + Sync;

/// [`IntoFuture`] for an in-progress incoming connection attempt.
///
/// Created by [`Endpoint::accept`].
pub struct IncomingSession(quinn::Incoming);

impl IncomingSession {
    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated.
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.0.remote_address_validated()
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// # Panics
    ///
    /// If `remote_address_validated()` is true.
    pub fn retry(self) {
        self.0.retry().expect("remote address already verified");
    }

    /// Reject this incoming connection attempt.
    pub fn refuse(self) {
        self.0.refuse();
    }

    /// Ignore this incoming connection attempt, not sending any packet in response.
    pub fn ignore(self) {
        self.0.ignore();
    }
}

impl IntoFuture for IncomingSession {
    type IntoFuture = IncomingSessionFuture;
    type Output = Result<SessionRequest, ConnectionError>;

    fn into_future(self) -> Self::IntoFuture {
        IncomingSessionFuture::new(self.0)
    }
}

/// [`Future`] for an in-progress incoming connection attempt.
///
/// Created by awaiting an [`IncomingSession`]
pub struct IncomingSessionFuture(Pin<Box<DynFutureIncomingSession>>);

impl IncomingSessionFuture {
    /// Creates a future from [`quinn::Incoming`].
    ///
    /// The returned future resolves to a [`SessionRequest`] once the QUIC connection
    /// is established and the WebTransport session has been accepted.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_quic_incoming(quic_incoming: quinn::Incoming) -> Self {
        Self::new(quic_incoming)
    }

    /// Creates a future from [`quinn::Connecting`].
    ///
    /// This is useful when a [`quinn::Connecting`] is already available and needs to be
    /// driven to completion to accept an incoming WebTransport session.
    ///
    /// The returned future resolves to a [`SessionRequest`] once the QUIC connection
    /// is established and the WebTransport session has been accepted.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_quic_connecting(quic_connecting: quinn::Connecting) -> Self {
        Self(Box::pin(async move {
            let quic_connection = quic_connecting.await?;
            Self::accept(quic_connection).await
        }))
    }

    fn new(quic_incoming: quinn::Incoming) -> Self {
        Self(Box::pin(async move {
            let quic_connection = quic_incoming.await?;
            Self::accept(quic_connection).await
        }))
    }

    async fn accept(quic_connection: quinn::Connection) -> Result<SessionRequest, ConnectionError> {
        let driver = Driver::init(quic_connection.clone());

        let _settings = driver.accept_settings().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        // TODO(biagio): validate settings

        let stream_session = driver.accept_session().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        Ok(SessionRequest::new(quic_connection, driver, stream_session))
    }
}

impl Future for IncomingSessionFuture {
    type Output = Result<SessionRequest, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

/// A incoming client session request.
///
/// Server should use methods [`accept`](Self::accept), [`forbidden`](Self::forbidden),
/// or [`not_found`](Self::not_found) in order to validate or reject the client request.
pub struct SessionRequest {
    quic_connection: quinn::Connection,
    driver: Driver,
    stream_session: StreamSession,
}

impl SessionRequest {
    pub(crate) fn new(
        quic_connection: quinn::Connection,
        driver: Driver,
        stream_session: StreamSession,
    ) -> Self {
        Self {
            quic_connection,
            driver,
            stream_session,
        }
    }

    /// Returns the peer's UDP address.
    ///
    /// **Note**: as QUIC supports migration, remote address may change
    /// during connection. Furthermore, when IPv6 support is enabled, IPv4
    /// addresses may be mapped to IPv6.
    #[inline(always)]
    pub fn remote_address(&self) -> SocketAddr {
        self.quic_connection.remote_address()
    }

    /// Returns the `:authority` field of the request.
    pub fn authority(&self) -> &str {
        self.stream_session.request().authority()
    }

    /// Returns the `:path` field of the request.
    pub fn path(&self) -> &str {
        self.stream_session.request().path()
    }

    /// Returns the `origin` field of the request if present.
    pub fn origin(&self) -> Option<&str> {
        self.stream_session.request().origin()
    }

    /// Returns the `user-agent` field of the request if present.
    pub fn user_agent(&self) -> Option<&str> {
        self.stream_session.request().user_agent()
    }

    /// Returns all header fields associated with the request.
    pub fn headers(&self) -> &HashMap<String, String> {
        self.stream_session.request().headers().as_ref()
    }

    /// Accepts the client request with headers.
    pub async fn accept_with_headers<I, K, V>(
        self,
        headers: I,
    ) -> Result<Connection, ConnectionError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.accept_impl(
            headers
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
        .await
    }

    /// Accepts the client request and it establishes the WebTransport session.
    pub async fn accept(self) -> Result<Connection, ConnectionError> {
        self.accept_impl(HashMap::new()).await
    }

    /// Rejects the client request by replying with `403` status code.
    pub async fn forbidden(self) {
        self.reject(SessionResponseProto::forbidden()).await;
    }

    /// Rejects the client request by replying with `404` status code.
    pub async fn not_found(self) {
        self.reject(SessionResponseProto::not_found()).await;
    }

    /// Rejects the client request by replying with `429` status code.
    pub async fn too_many_requests(self) {
        self.reject(SessionResponseProto::too_many_requests()).await;
    }

    async fn accept_impl(
        mut self,
        headers: HashMap<String, String>,
    ) -> Result<Connection, ConnectionError> {
        let mut response = SessionResponseProto::ok();

        for (key, value) in headers {
            response.add(key, value);
        }

        self.send_response(response).await?;

        let session_id = self.stream_session.session_id();

        self.driver
            .register_session(self.stream_session)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?;

        Ok(Connection::new(
            self.quic_connection,
            self.driver,
            session_id,
        ))
    }

    async fn reject(mut self, response: SessionResponseProto) {
        let _ = self.send_response(response).await;
        self.stream_session.finish().await;
    }

    async fn send_response(
        &mut self,
        response: SessionResponseProto,
    ) -> Result<(), ConnectionError> {
        let frame = response.headers().generate_frame();

        match self.stream_session.write_frame(frame).await {
            Ok(()) => Ok(()),
            Err(ProtoWriteError::NotConnected) => {
                Err(ConnectionError::no_connect(&self.quic_connection))
            }
            Err(ProtoWriteError::Stopped) => {
                self.quic_connection
                    .close(varint_w2q(ErrorCode::ClosedCriticalStream.to_code()), b"");

                Err(ConnectionError::local_h3_error(
                    ErrorCode::ClosedCriticalStream,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApplicationClose;
    use crate::Identity;
    use bytes::Bytes;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use wtransport_proto::error::ErrorCode;
    use wtransport_proto::settings::Settings;

    /// A WebTransport session between a server of this crate and a plain QUIC client, which puts on the wire what a
    /// test wants. The session's CONNECT stream is the client's first bidirectional stream, so its quarter stream ID is
    /// 0, and a datagram of the session starts with the byte 0.
    struct RawSession {
        server: Connection,
        client: quinn::Connection,
        connect: quinn::SendStream,
        _connect_receive: quinn::RecvStream,
        _control: quinn::SendStream,
        _endpoints: (Endpoint<endpoint_side::Server>, quinn::Endpoint),
    }

    async fn raw_session() -> RawSession {
        let identity = Identity::self_signed(["localhost"]).unwrap();
        let certificate_hash = identity.certificate_chain().as_slice()[0].hash();
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_identity(identity)
                .build(),
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let client_config = ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([certificate_hash])
            .build();
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();

        let mut settings = Vec::new();
        Settings::builder()
            .qpack_max_table_capacity(VarInt::from_u32(0))
            .qpack_blocked_streams(VarInt::from_u32(0))
            .enable_connect_protocol()
            .enable_webtransport()
            .enable_h3_datagrams()
            .webtransport_max_sessions(VarInt::from_u32(1))
            .build()
            .generate_frame()
            .write(&mut settings)
            .unwrap();
        let mut request = Vec::new();
        SessionRequestProto::new(format!("https://localhost:{}/", server_address.port()))
            .unwrap()
            .headers()
            .generate_frame()
            .write(&mut request)
            .unwrap();

        let (server_connection, (client_connection, control, connect, connect_receive)) = tokio::join!(
            async {
                let session_request = timeout(Duration::from_secs(5), server.accept().await)
                    .await
                    .expect("the server's handshake finishes")
                    .expect("the server reads the client's SETTINGS");
                session_request
                    .accept()
                    .await
                    .expect("the server accepts the session")
            },
            async {
                let connection = client
                    .connect_with(
                        client_config.quic_config.clone(),
                        server_address,
                        "localhost",
                    )
                    .unwrap()
                    .await
                    .unwrap();
                let mut control = connection.open_uni().await.unwrap();
                // The stream type of a control stream, then the SETTINGS frame.
                control.write_all(&[0x00]).await.unwrap();
                control.write_all(&settings).await.unwrap();
                let (mut connect, connect_receive) = connection.open_bi().await.unwrap();
                connect.write_all(&request).await.unwrap();
                (connection, control, connect, connect_receive)
            },
        );
        RawSession {
            server: server_connection,
            client: client_connection,
            connect,
            _connect_receive: connect_receive,
            _control: control,
            _endpoints: (server, client),
        }
    }

    async fn receive(
        connection: &Connection,
    ) -> Result<crate::datagram::Datagram, ConnectionError> {
        timeout(Duration::from_secs(5), connection.receive_datagram())
            .await
            .expect("the receive ends within 5 s")
    }

    /// A receive that a caller drops while it waits takes no datagram along: the next receive gets it.
    #[tokio::test]
    async fn a_dropped_receive_loses_no_datagram() {
        let session = raw_session().await;
        assert!(
            timeout(Duration::from_millis(50), session.server.receive_datagram())
                .await
                .is_err()
        );
        session
            .client
            .send_datagram(Bytes::from_static(&[0x00, 1, 2]))
            .unwrap();
        assert_eq!(
            &receive(&session.server).await.unwrap().payload()[..],
            &[1, 2]
        );
    }

    /// A datagram of another session is dropped, and the receive returns the next one of its own session.
    #[tokio::test]
    async fn a_datagram_of_another_session_is_dropped() {
        let session = raw_session().await;
        session
            .client
            .send_datagram(Bytes::from_static(&[0x01, 9]))
            .unwrap();
        session
            .client
            .send_datagram(Bytes::from_static(&[0x00, 7]))
            .unwrap();
        assert_eq!(&receive(&session.server).await.unwrap().payload()[..], &[7]);
    }

    /// A datagram without a valid quarter stream ID closes the connection with `H3_DATAGRAM_ERROR` (RFC 9297, section
    /// 2.1). Every receive reports that error, and the peer gets it as the close code.
    #[tokio::test]
    async fn a_malformed_datagram_closes_the_connection() {
        let session = raw_session().await;
        // A variable-length integer of 2^62 - 1, above every quarter stream ID.
        session
            .client
            .send_datagram(Bytes::from_static(&[0xff; 8]))
            .unwrap();
        let expected = ConnectionError::local_h3_error(ErrorCode::Datagram);
        assert_eq!(receive(&session.server).await.unwrap_err(), expected);
        assert_eq!(receive(&session.server).await.unwrap_err(), expected);
        match session.client.closed().await {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, varint_w2q(ErrorCode::Datagram.to_code()));
            }
            error => panic!("unexpected close {error:?}"),
        }
    }

    /// A client that finishes its CONNECT stream ends the session with application code 0, and the receive reports
    /// that, not the local QUIC close that follows it.
    #[tokio::test]
    async fn a_finished_connect_stream_ends_the_receive_with_code_zero() {
        let mut session = raw_session().await;
        session.connect.finish().unwrap();
        assert_eq!(
            receive(&session.server).await.unwrap_err(),
            ConnectionError::ApplicationClosed(ApplicationClose::new(
                VarInt::from_u32(0),
                Box::new([])
            ))
        );
    }

    /// A peer's QUIC close reaches the receive with its code and reason.
    #[tokio::test]
    async fn a_peer_close_reaches_the_receive_with_its_code() {
        let session = raw_session().await;
        session.client.close(quinn::VarInt::from_u32(7), b"bye");
        assert_eq!(
            receive(&session.server).await.unwrap_err(),
            ConnectionError::ApplicationClosed(ApplicationClose::new(
                VarInt::from_u32(7),
                b"bye".to_vec().into_boxed_slice()
            ))
        );
    }

    /// Once the connection has closed, a receive reports how it ended instead of the datagrams that are still
    /// buffered.
    #[tokio::test]
    async fn a_closed_connection_returns_its_error_before_buffered_datagrams() {
        let session = raw_session().await;
        for number in 0..5 {
            session
                .client
                .send_datagram(Bytes::from(vec![0x00, number]))
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.client.close(quinn::VarInt::from_u32(0), b"");
        session.server.closed().await;
        assert!(matches!(
            receive(&session.server).await,
            Err(ConnectionError::ApplicationClosed(_))
        ));
    }

    /// A task that receives a backlog of datagrams, with no other await in its loop, still lets the other tasks of a
    /// single-threaded runtime run.
    #[tokio::test]
    async fn receiving_a_backlog_yields_to_other_tasks() {
        let session = raw_session().await;
        for number in 0..400u16 {
            let [high, low] = number.to_be_bytes();
            session
                .client
                .send_datagram(Bytes::from(vec![0x00, high, low]))
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let ran = Arc::new(AtomicBool::new(false));
        tokio::spawn({
            let ran = ran.clone();
            async move { ran.store(true, Ordering::Relaxed) }
        });
        for _ in 0..300 {
            receive(&session.server).await.unwrap();
        }
        assert!(
            ran.load(Ordering::Relaxed),
            "the other task ran while the backlog was received"
        );
    }

    /// The server reads a client's SETTINGS frame whole when the frame arrives in two parts with the
    /// client's CONNECT stream in between.
    ///
    /// The CONNECT stream finishes another branch of the driver's `select!` while the SETTINGS read
    /// waits for the rest of its frame. A plain QUIC client sends the frame type, the CONNECT request
    /// and the rest of the frame in that order. Nothing tells the client when the server has read
    /// what it sent, so it waits 100ms after the frame type and after the request.
    #[tokio::test]
    async fn settings_frame_split_by_connect_stream() {
        let identity = Identity::self_signed(["localhost"]).unwrap();
        let certificate_hash = identity.certificate_chain().as_slice()[0].hash();
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_identity(identity)
                .build(),
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let client_config = ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([certificate_hash])
            .build();
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();

        let mut settings = Vec::new();
        Settings::builder()
            .qpack_max_table_capacity(VarInt::from_u32(0))
            .qpack_blocked_streams(VarInt::from_u32(0))
            .enable_connect_protocol()
            .enable_webtransport()
            .enable_h3_datagrams()
            .webtransport_max_sessions(VarInt::from_u32(1))
            .build()
            .generate_frame()
            .write(&mut settings)
            .unwrap();
        let mut request = Vec::new();
        SessionRequestProto::new(format!("https://localhost:{}/", server_address.port()))
            .unwrap()
            .headers()
            .generate_frame()
            .write(&mut request)
            .unwrap();

        let (session_request, _client) = tokio::join!(
            async {
                timeout(Duration::from_secs(5), server.accept().await)
                    .await
                    .expect("the server's handshake finishes")
                    .expect("the server reads the client's SETTINGS")
            },
            async {
                let connection = client
                    .connect_with(
                        client_config.quic_config.clone(),
                        server_address,
                        "localhost",
                    )
                    .unwrap()
                    .await
                    .unwrap();
                let mut control = connection.open_uni().await.unwrap();
                // The stream type of a control stream, then the type of the SETTINGS frame.
                control.write_all(&[0x00]).await.unwrap();
                control.write_all(&settings[..1]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                let (mut connect, connect_receive) = connection.open_bi().await.unwrap();
                connect.write_all(&request).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                control.write_all(&settings[1..]).await.unwrap();
                (connection, control, connect, connect_receive)
            },
        );
        assert_eq!(session_request.path(), "/");
    }
}
