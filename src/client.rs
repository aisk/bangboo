use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap,
    HeaderName, HeaderValue, PROXY_AUTHORIZATION, TRANSFER_ENCODING, USER_AGENT, WWW_AUTHENTICATE,
};
use http::{Method, StatusCode, Version};
use url::Url;

use crate::connect::Connector;
use crate::into_url::IntoUrl;
use crate::pool::{Pool, PoolKey};
use crate::proto::{self, BodyLength};
use crate::redirect;
use crate::request::{Request, RequestBuilder, basic_auth_value};
use crate::response::{BodyReader, Response};

/// The maximum amount of a leftover response body that will be drained to
/// keep a connection reusable when following a redirect.
const REDIRECT_DRAIN_MAX: u64 = 256 * 1024;

/// A `Client` to make Requests with.
///
/// The Client has various configuration values to tweak, but the defaults
/// are set to what is usually the most commonly desired value. To configure
/// a `Client`, use `Client::builder()`.
///
/// The `Client` holds a connection pool internally, so it is advised that
/// you create one and **reuse** it.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    headers: HeaderMap,
    redirect: redirect::Policy,
    timeout: Option<Duration>,
    connector: Connector,
    pool: Arc<Pool>,
}

/// A `ClientBuilder` can be used to create a `Client` with custom
/// configuration.
#[must_use]
pub struct ClientBuilder {
    headers: HeaderMap,
    redirect: redirect::Policy,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    tcp_nodelay: bool,
    #[cfg(feature = "tls")]
    accept_invalid_certs: bool,
    error: Option<crate::Error>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Constructs a new `ClientBuilder`.
    ///
    /// This is the same as `Client::builder()`.
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        ClientBuilder {
            headers,
            redirect: redirect::Policy::default(),
            // Same default as reqwest's blocking client.
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: None,
            pool_idle_timeout: Some(Duration::from_secs(90)),
            pool_max_idle_per_host: usize::MAX,
            tcp_nodelay: true,
            #[cfg(feature = "tls")]
            accept_invalid_certs: false,
            error: None,
        }
    }

    /// Returns a `Client` that uses this `ClientBuilder` configuration.
    pub fn build(self) -> crate::Result<Client> {
        if let Some(err) = self.error {
            return Err(err);
        }
        Ok(Client {
            inner: Arc::new(ClientInner {
                headers: self.headers,
                redirect: self.redirect,
                timeout: self.timeout,
                connector: Connector {
                    connect_timeout: self.connect_timeout,
                    nodelay: self.tcp_nodelay,
                    #[cfg(feature = "tls")]
                    tls: crate::connect::tls::build_config(self.accept_invalid_certs),
                },
                pool: Arc::new(Pool::new(
                    self.pool_idle_timeout,
                    self.pool_max_idle_per_host,
                )),
            }),
        })
    }

    /// Sets the `User-Agent` header to be used by this client.
    pub fn user_agent<V>(mut self, value: V) -> ClientBuilder
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        match HeaderValue::try_from(value) {
            Ok(value) => {
                self.headers.insert(USER_AGENT, value);
            }
            Err(e) => {
                self.error = Some(crate::error::builder(e.into()));
            }
        }
        self
    }

    /// Sets the default headers for every request.
    pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
        crate::request::replace_headers(&mut self.headers, headers);
        self
    }

    /// Set a `redirect::Policy` for this client.
    ///
    /// Default will follow redirects up to a maximum of 10.
    pub fn redirect(mut self, policy: redirect::Policy) -> ClientBuilder {
        self.redirect = policy;
        self
    }

    /// Set a timeout for connect, read and write operations of a `Client`.
    ///
    /// Default is 30 seconds.
    ///
    /// Pass `None` to disable timeout.
    pub fn timeout<T>(mut self, timeout: T) -> ClientBuilder
    where
        T: Into<Option<Duration>>,
    {
        self.timeout = timeout.into();
        self
    }

    /// Set a timeout for only the connect phase of a `Client`.
    ///
    /// Default is `None`.
    pub fn connect_timeout<T>(mut self, timeout: T) -> ClientBuilder
    where
        T: Into<Option<Duration>>,
    {
        self.connect_timeout = timeout.into();
        self
    }

    /// Set an optional timeout for idle sockets being kept-alive.
    ///
    /// Pass `None` to disable timeout.
    ///
    /// Default is 90 seconds.
    pub fn pool_idle_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.pool_idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> ClientBuilder {
        self.pool_max_idle_per_host = max;
        self
    }

    /// Set whether sockets have `TCP_NODELAY` enabled.
    ///
    /// Default is `true`.
    pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
        self.tcp_nodelay = enabled;
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid
    /// certificates are trusted, *any* certificate for *any* site will be
    /// trusted for use. This introduces significant vulnerabilities, and
    /// should only be used as a last resort.
    #[cfg(feature = "tls")]
    pub fn danger_accept_invalid_certs(mut self, accept_invalid_certs: bool) -> ClientBuilder {
        self.accept_invalid_certs = accept_invalid_certs;
        self
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("timeout", &self.timeout)
            .field("redirect", &self.redirect)
            .finish()
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Panics
    ///
    /// This method panics if the client cannot be initialized. Use
    /// `Client::builder()` if you wish to handle the failure as an `Error`
    /// instead of panicking.
    pub fn new() -> Client {
        ClientBuilder::new().build().expect("Client::new()")
    }

    /// Creates a `ClientBuilder` to configure a `Client`.
    ///
    /// This is the same as `ClientBuilder::new()`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Convenience method to make a `GET` request to a URL.
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Convenience method to make a `POST` request to a URL.
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    /// Start building a `Request` with the `Method` and `Url`.
    ///
    /// Returns a `RequestBuilder`, which will allow setting headers and
    /// request body before sending.
    pub fn request<U: IntoUrl>(&self, method: Method, url: U) -> RequestBuilder {
        let req = url.into_url().map(|url| Request::new(method, url));
        RequestBuilder::new(self.clone(), req)
    }

    /// Executes a `Request`.
    ///
    /// A `Request` can be built manually with `Request::new()` or obtained
    /// from a RequestBuilder with `RequestBuilder::build()`.
    ///
    /// You should prefer to use the `RequestBuilder` and
    /// `RequestBuilder::send()`.
    pub fn execute(&self, request: Request) -> crate::Result<Response> {
        self.execute_request(request)
    }

    fn execute_request(&self, req: Request) -> crate::Result<Response> {
        let (mut method, mut url, mut headers, mut body, timeout, version) = req.pieces();

        if version != Version::HTTP_11 && version != Version::HTTP_10 {
            return Err(crate::error::builder(format!(
                "bangboo only speaks HTTP/1.x, {version:?} was requested"
            )));
        }

        // Merge default headers; request headers take precedence.
        for name in self.inner.headers.keys() {
            if !headers.contains_key(name) {
                for value in self.inner.headers.get_all(name) {
                    headers.append(name.clone(), value.clone());
                }
            }
        }

        let deadline = timeout
            .or(self.inner.timeout)
            .map(|t| Instant::now() + t);

        // HTTP/1.0 servers don't understand chunked framing, so a streaming
        // body with unknown length must be buffered up front.
        if version == Version::HTTP_10
            && let Some(b) = body.as_mut()
            && b.len().is_none()
        {
            b.buffer()?;
        }

        let mut redirects = 0usize;

        loop {
            // Credentials embedded in the URL become an Authorization
            // header, like reqwest.
            if !url.username().is_empty() || url.password().is_some() {
                let username = percent_encoding::percent_decode_str(url.username())
                    .decode_utf8_lossy()
                    .into_owned();
                let password = url
                    .password()
                    .map(|p| percent_encoding::percent_decode_str(p).decode_utf8_lossy().into_owned());
                headers.insert(AUTHORIZATION, basic_auth_value(username, password.as_deref()));
                let _ = url.set_username("");
                let _ = url.set_password(None);
            }

            let https = match url.scheme() {
                "http" => false,
                "https" => true,
                scheme => {
                    return Err(crate::error::builder(format!(
                        "unsupported URL scheme: {scheme}"
                    )));
                }
            };
            let host = url
                .host_str()
                .ok_or_else(|| crate::error::builder("URL has no host"))?
                .to_string();
            let port = url
                .port_or_known_default()
                .ok_or_else(|| crate::error::builder("URL has no port"))?;
            let key = PoolKey {
                https,
                host: host.clone(),
                port,
            };

            // A request written on a pooled connection can hit a socket the
            // server already closed; retry once on a fresh connection, but
            // only if the body can be replayed.
            let body_replayable =
                body.is_none() || body.as_ref().is_some_and(|b| b.as_bytes().is_some());

            let (conn, head) = loop {
                let (pooled, mut conn) = match self.inner.pool.checkout(&key) {
                    Some(conn) => (true, conn),
                    None => (
                        false,
                        self.inner
                            .connector
                            .connect(https, &host, port, deadline)
                            .map_err(|e| e.with_url(url.clone()))?,
                    ),
                };

                let received_before = conn.received_bytes();
                let attempt = (|| -> io::Result<proto::Head> {
                    conn.set_deadline(deadline)?;
                    proto::write_request(
                        &mut conn,
                        &method,
                        &url,
                        version,
                        &headers,
                        body.as_mut(),
                    )?;
                    proto::read_head(&mut conn)
                })();

                match attempt {
                    Ok(head) => break (conn, head),
                    // Only retry when the server never started responding:
                    // once any response bytes arrived, the request may have
                    // been acted upon and must not be replayed.
                    Err(e)
                        if pooled
                            && body_replayable
                            && is_stale_conn_error(&e)
                            && conn.received_bytes() == received_before =>
                    {
                        continue;
                    }
                    Err(e) => return Err(crate::error::from_io(e).with_url(url.clone())),
                }
            };

            let length = proto::body_length(&method, head.status, &head.headers)
                .map_err(|e| crate::error::from_io(e).with_url(url.clone()))?;
            let reusable = proto::can_keep_alive(head.version, &head.headers)
                && length != BodyLength::CloseDelimited;
            let reuse = reusable.then(|| (self.inner.pool.clone(), key));

            // Handle redirects.
            if let Some(max_redirects) = self.inner.redirect.max_redirects()
                && let Some(next_url) = redirect_target(head.status, &head.headers, &url) {
                    redirects += 1;
                    if redirects > max_redirects {
                        return Err(crate::error::redirect("too many redirects", url));
                    }
                    let next_url = next_url?;

                    // Drain the redirect response body so the connection can
                    // be reused.
                    BodyReader::new(conn, length, reuse, deadline).drain(REDIRECT_DRAIN_MAX);

                    // Like reqwest: 301/302/303 turn every method except
                    // HEAD into a body-less GET; 307/308 keep method + body.
                    let drop_body = matches!(
                        head.status,
                        StatusCode::MOVED_PERMANENTLY
                            | StatusCode::FOUND
                            | StatusCode::SEE_OTHER
                    ) && method != Method::GET
                        && method != Method::HEAD;
                    if drop_body {
                        method = Method::GET;
                        body = None;
                        for header in &[
                            CONTENT_LENGTH,
                            CONTENT_TYPE,
                            CONTENT_ENCODING,
                            TRANSFER_ENCODING,
                        ] {
                            headers.remove(header);
                        }
                    } else if let Some(b) = body.as_ref()
                        && b.as_bytes().is_none() {
                            return Err(crate::error::redirect(
                                "cannot follow redirect with a streaming body",
                                url,
                            ));
                        }

                    // Don't leak credentials across origins.
                    let cross_origin = next_url.scheme() != url.scheme()
                        || next_url.host_str() != url.host_str()
                        || next_url.port_or_known_default() != url.port_or_known_default();
                    if cross_origin {
                        headers.remove(AUTHORIZATION);
                        headers.remove(PROXY_AUTHORIZATION);
                        headers.remove(COOKIE);
                        headers.remove(WWW_AUTHENTICATE);
                        headers.remove(HeaderName::from_static("cookie2"));
                    }

                    url = next_url;
                    continue;
                }

            let remote_addr = conn.remote_addr();
            let reader = BodyReader::new(conn, length, reuse, deadline);
            return Ok(Response::new(
                head.status,
                head.version,
                head.headers,
                url,
                remote_addr,
                reader,
            ));
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish()
    }
}

fn is_stale_conn_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// If `status` is a redirect with a usable `Location`, returns the resolved
/// target URL.
fn redirect_target(
    status: StatusCode,
    headers: &HeaderMap,
    base: &Url,
) -> Option<crate::Result<Url>> {
    match status {
        StatusCode::MOVED_PERMANENTLY
        | StatusCode::FOUND
        | StatusCode::SEE_OTHER
        | StatusCode::TEMPORARY_REDIRECT
        | StatusCode::PERMANENT_REDIRECT => {}
        _ => return None,
    }
    let location = headers.get(http::header::LOCATION)?;
    let location = match location.to_str() {
        Ok(location) => location,
        Err(e) => return Some(Err(crate::error::redirect(e, base.clone()))),
    };
    match base.join(location) {
        Ok(url) => match url.scheme() {
            "http" | "https" => Some(Ok(url)),
            _ => Some(Err(crate::error::redirect(
                format!("redirect to unsupported scheme: {url}"),
                base.clone(),
            ))),
        },
        Err(e) => Some(Err(crate::error::redirect(e, base.clone()))),
    }
}
