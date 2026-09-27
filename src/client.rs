use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE,
    HeaderMap, HeaderName, HeaderValue, PROXY_AUTHORIZATION, RANGE, REFERER, TRANSFER_ENCODING,
    USER_AGENT, WWW_AUTHENTICATE,
};
use http::{Method, StatusCode, Version};
use url::Url;

use crate::connect::{Connector, TcpConfig};
use crate::decoder::{Accepts, Decoder};
use crate::dns::{GaiResolver, Resolve, ResolverWithOverrides};
use crate::into_url::IntoUrl;
use crate::pool::{Pool, PoolKey};
use crate::proto::{self, BodyLength, Http1Opts, RequestTarget};
use crate::proxy::{Proxy, ProxyScheme};
use crate::redirect;
use crate::request::{Request, RequestBuilder, basic_auth_value};
use crate::response::{BodyReader, Response};

/// The maximum amount of a leftover response body that will be drained to
/// keep a connection reusable when following a redirect.
const REDIRECT_DRAIN_MAX: u64 = 256 * 1024;

/// The `User-Agent` sent unless the caller sets one of their own.
const DEFAULT_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

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
    referer: bool,
    https_only: bool,
    timeout: Option<Duration>,
    http1: Http1Opts,
    proxies: Vec<Proxy>,
    accepts: Accepts,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn crate::cookie::CookieStore>>,
    #[cfg(feature = "tls")]
    tls_info: bool,
    connector: Connector,
    pool: Arc<Pool>,
}

/// A `ClientBuilder` can be used to create a `Client` with custom
/// configuration.
#[must_use]
pub struct ClientBuilder {
    headers: HeaderMap,
    redirect: redirect::Policy,
    referer: bool,
    https_only: bool,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    tcp: TcpConfig,
    http1: Http1Opts,
    proxies: Vec<Proxy>,
    auto_sys_proxy: bool,
    accepts: Accepts,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn crate::cookie::CookieStore>>,
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
    #[cfg(feature = "tls")]
    tls: crate::tls::TlsSettings,
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
        headers.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        ClientBuilder {
            headers,
            redirect: redirect::Policy::default(),
            referer: true,
            https_only: false,
            // Same default as reqwest's blocking client.
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: None,
            pool_idle_timeout: Some(Duration::from_secs(90)),
            pool_max_idle_per_host: usize::MAX,
            tcp: TcpConfig {
                nodelay: true,
                ..TcpConfig::default()
            },
            http1: Http1Opts::default(),
            proxies: Vec::new(),
            auto_sys_proxy: true,
            // Decompression is on whenever the corresponding feature is
            // compiled in, matching reqwest.
            accepts: Accepts {
                gzip: cfg!(feature = "gzip"),
                deflate: cfg!(feature = "deflate"),
                brotli: cfg!(feature = "brotli"),
                zstd: cfg!(feature = "zstd"),
            },
            #[cfg(feature = "cookies")]
            cookie_store: None,
            dns_overrides: HashMap::new(),
            dns_resolver: None,
            #[cfg(feature = "tls")]
            tls: crate::tls::TlsSettings::default(),
            error: None,
        }
    }

    /// Returns a `Client` that uses this `ClientBuilder` configuration.
    pub fn build(self) -> crate::Result<Client> {
        if let Some(err) = self.error {
            return Err(err);
        }
        let mut proxies = self.proxies;
        if self.auto_sys_proxy {
            proxies.extend(crate::proxy::from_environment());
        }
        let resolver: Arc<dyn Resolve> = {
            let fallback = self.dns_resolver.unwrap_or_else(|| Arc::new(GaiResolver));
            if self.dns_overrides.is_empty() {
                fallback
            } else {
                Arc::new(ResolverWithOverrides {
                    overrides: self.dns_overrides,
                    fallback,
                })
            }
        };
        let http1 = self.http1;
        #[cfg(feature = "tls")]
        let tls_info = self.tls.tls_info;
        #[cfg(feature = "tls")]
        let tls_config = self.tls.build_config()?;
        Ok(Client {
            inner: Arc::new(ClientInner {
                headers: self.headers,
                redirect: self.redirect,
                referer: self.referer,
                https_only: self.https_only,
                timeout: self.timeout,
                http1: http1.clone(),
                proxies,
                accepts: self.accepts,
                #[cfg(feature = "cookies")]
                cookie_store: self.cookie_store,
                #[cfg(feature = "tls")]
                tls_info,
                connector: Connector {
                    connect_timeout: self.connect_timeout,
                    http1: http1.clone(),
                    tcp: self.tcp,
                    resolver,
                    #[cfg(feature = "tls")]
                    tls: tls_config,
                },
                pool: Arc::new(Pool::new(
                    self.pool_idle_timeout,
                    self.pool_max_idle_per_host,
                )),
            }),
        })
    }

    /// Sets the `User-Agent` header to be used by this client.
    ///
    /// Defaults to `bangboo/x.y.z`.
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

    /// Removes the default `User-Agent`, so no such header is sent unless a
    /// request sets one itself.
    ///
    /// A later `user_agent` call puts one back; the last call wins.
    pub fn no_user_agent(mut self) -> ClientBuilder {
        self.headers.remove(USER_AGENT);
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

    /// Enable or disable automatic setting of the `Referer` header when
    /// following redirects.
    ///
    /// Default is `true`.
    pub fn referer(mut self, enable: bool) -> ClientBuilder {
        self.referer = enable;
        self
    }

    /// Restrict the Client to be used with HTTPS only requests.
    ///
    /// Defaults to `false`.
    pub fn https_only(mut self, enabled: bool) -> ClientBuilder {
        self.https_only = enabled;
        self
    }

    /// Send request header names as title case instead of lowercase.
    pub fn http1_title_case_headers(mut self) -> ClientBuilder {
        self.http1.title_case_headers = true;
        self
    }

    /// Sets the maximum number of headers accepted in a response.
    ///
    /// Default is 128.
    pub fn http1_max_headers(mut self, max: usize) -> ClientBuilder {
        self.http1.max_headers = max;
        self
    }

    /// Set whether HTTP/1 connections will accept obsolete line folding for
    /// header values (a header value continued on a following line that
    /// starts with whitespace).
    ///
    /// Default is `false`.
    pub fn http1_allow_obsolete_multiline_headers_in_responses(
        mut self,
        value: bool,
    ) -> ClientBuilder {
        self.http1.allow_obsolete_multiline_headers = value;
        self
    }

    /// Sets whether invalid header lines in responses should be silently
    /// ignored instead of failing the request.
    ///
    /// Default is `false`.
    pub fn http1_ignore_invalid_headers_in_responses(mut self, value: bool) -> ClientBuilder {
        self.http1.ignore_invalid_headers = value;
        self
    }

    /// Set whether HTTP/1 connections will accept spaces between a response
    /// header name and the colon that follows it.
    ///
    /// Default is `false`.
    pub fn http1_allow_spaces_after_header_name_in_responses(
        mut self,
        value: bool,
    ) -> ClientBuilder {
        self.http1.allow_spaces_after_header_name = value;
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

    /// Set whether connections should emit verbose logs.
    ///
    /// Enabling this option will emit [log][] messages at the `TRACE` level
    /// for read and write operations on connections.
    ///
    /// [log]: https://crates.io/crates/log
    pub fn connection_verbose(mut self, verbose: bool) -> ClientBuilder {
        self.tcp.verbose = verbose;
        self
    }

    /// Set whether sockets have `TCP_NODELAY` enabled.
    ///
    /// Default is `true`.
    pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
        self.tcp.nodelay = enabled;
        self
    }

    /// Bind to a local IP Address.
    pub fn local_address<T>(mut self, addr: T) -> ClientBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        self.tcp.local_address = addr.into();
        self
    }

    /// Bind connections only on the specified network interface.
    ///
    /// This option is only available on Android, Fuchsia and Linux
    /// (`SO_BINDTODEVICE`).
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn interface(mut self, interface: &str) -> ClientBuilder {
        self.tcp.interface = Some(interface.to_string());
        self
    }

    /// Set `SO_KEEPALIVE` with the supplied idle duration.
    ///
    /// Default is no keepalive.
    pub fn tcp_keepalive<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.tcp.keepalive = val.into();
        self
    }

    /// Set the interval between TCP keepalive probes.
    pub fn tcp_keepalive_interval<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.tcp.keepalive_interval = val.into();
        self
    }

    /// Set the number of retransmissions of TCP keepalive probes before the
    /// connection is considered dead.
    pub fn tcp_keepalive_retries<C>(mut self, retries: C) -> ClientBuilder
    where
        C: Into<Option<u32>>,
    {
        self.tcp.keepalive_retries = retries.into();
        self
    }

    /// Set `TCP_USER_TIMEOUT`: how long transmitted data may remain
    /// unacknowledged before the connection is force-closed.
    ///
    /// This option is only available on Android, Fuchsia and Linux.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn tcp_user_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.tcp.user_timeout = val.into();
        self
    }

    /// Enable a persistent cookie store for the client.
    ///
    /// Cookies received in responses will be preserved and included in
    /// additional requests.
    ///
    /// By default, no cookie store is used. Enabling the cookie store with
    /// `cookie_store(true)` will set the store to a default implementation.
    /// It is **not** necessary to call `cookie_store(true)` if
    /// [`cookie_provider`][Self::cookie_provider] is used; calling
    /// `cookie_store(false)` after `cookie_provider` will result in the
    /// provider being **not** used.
    #[cfg(feature = "cookies")]
    pub fn cookie_store(mut self, enable: bool) -> ClientBuilder {
        self.cookie_store = enable.then(|| {
            Arc::new(crate::cookie::Jar::default()) as Arc<dyn crate::cookie::CookieStore>
        });
        self
    }

    /// Set the persistent cookie store for the client.
    ///
    /// Cookies received in responses will be passed to this store, and
    /// additional requests will query this store for cookies.
    #[cfg(feature = "cookies")]
    pub fn cookie_provider<C: crate::cookie::CookieStore + 'static>(
        mut self,
        cookie_store: Arc<C>,
    ) -> ClientBuilder {
        self.cookie_store = Some(cookie_store as Arc<dyn crate::cookie::CookieStore>);
        self
    }

    /// Enable auto gzip decompression by checking the `Content-Encoding`
    /// response header.
    ///
    /// If auto gzip decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already
    ///   contain an `Accept-Encoding` **and** `Range` values, the
    ///   `Accept-Encoding` header is set to `gzip`.
    /// - When receiving a response, if its headers contain a
    ///   `Content-Encoding` value of `gzip`, both `Content-Encoding` and
    ///   `Content-Length` are removed from the headers' set. The response
    ///   body is automatically decompressed.
    ///
    /// If the `gzip` feature is turned on, the default option is enabled.
    #[cfg(feature = "gzip")]
    pub fn gzip(mut self, enable: bool) -> ClientBuilder {
        self.accepts.gzip = enable;
        self
    }

    /// Enable auto deflate decompression by checking the `Content-Encoding`
    /// response header.
    ///
    /// If the `deflate` feature is turned on, the default option is
    /// enabled.
    #[cfg(feature = "deflate")]
    pub fn deflate(mut self, enable: bool) -> ClientBuilder {
        self.accepts.deflate = enable;
        self
    }

    /// Enable auto brotli decompression by checking the `Content-Encoding`
    /// response header.
    ///
    /// If the `brotli` feature is turned on, the default option is enabled.
    #[cfg(feature = "brotli")]
    pub fn brotli(mut self, enable: bool) -> ClientBuilder {
        self.accepts.brotli = enable;
        self
    }

    /// Enable auto zstd decompression by checking the `Content-Encoding`
    /// response header.
    ///
    /// If the `zstd` feature is turned on, the default option is enabled.
    #[cfg(feature = "zstd")]
    pub fn zstd(mut self, enable: bool) -> ClientBuilder {
        self.accepts.zstd = enable;
        self
    }

    /// Disable auto response body gzip decompression.
    ///
    /// This method exists even if the optional `gzip` feature is not
    /// enabled. This can be used to ensure a `Client` doesn't use gzip
    /// decompression even if another dependency were to enable the optional
    /// `gzip` feature.
    pub fn no_gzip(mut self) -> ClientBuilder {
        self.accepts.gzip = false;
        self
    }

    /// Disable auto response body deflate decompression.
    ///
    /// This method exists even if the optional `deflate` feature is not
    /// enabled.
    pub fn no_deflate(mut self) -> ClientBuilder {
        self.accepts.deflate = false;
        self
    }

    /// Disable auto response body brotli decompression.
    ///
    /// This method exists even if the optional `brotli` feature is not
    /// enabled.
    pub fn no_brotli(mut self) -> ClientBuilder {
        self.accepts.brotli = false;
        self
    }

    /// Disable auto response body zstd decompression.
    ///
    /// This method exists even if the optional `zstd` feature is not
    /// enabled.
    pub fn no_zstd(mut self) -> ClientBuilder {
        self.accepts.zstd = false;
        self
    }

    /// Add a `Proxy` to the list of proxies the `Client` will use.
    ///
    /// # Note
    ///
    /// Adding a proxy will disable the automatic usage of the "system"
    /// proxy (the `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy`
    /// environment variables).
    pub fn proxy(mut self, proxy: Proxy) -> ClientBuilder {
        self.proxies.push(proxy);
        self.auto_sys_proxy = false;
        self
    }

    /// Clear all `Proxies`, so `Client` will use no proxy anymore.
    ///
    /// This also disables the automatic usage of the "system" proxy.
    pub fn no_proxy(mut self) -> ClientBuilder {
        self.proxies.clear();
        self.auto_sys_proxy = false;
        self
    }

    /// Override DNS resolution for specific domains to a particular IP
    /// address.
    ///
    /// Set the port to `0` to use the conventional port for the given
    /// scheme (e.g. 80 for http).
    pub fn resolve(self, domain: &str, addr: SocketAddr) -> ClientBuilder {
        self.resolve_to_addrs(domain, &[addr])
    }

    /// Override DNS resolution for specific domains to particular IP
    /// addresses.
    ///
    /// Set the port to `0` to use the conventional port for the given
    /// scheme (e.g. 80 for http).
    pub fn resolve_to_addrs(mut self, domain: &str, addrs: &[SocketAddr]) -> ClientBuilder {
        self.dns_overrides
            .insert(domain.to_ascii_lowercase(), addrs.to_vec());
        self
    }

    /// Set a custom DNS resolver, overriding the default system resolver.
    ///
    /// Per-domain overrides configured with [`resolve`][Self::resolve] and
    /// [`resolve_to_addrs`][Self::resolve_to_addrs] still take precedence.
    pub fn dns_resolver<R: Resolve + 'static>(mut self, resolver: Arc<R>) -> ClientBuilder {
        self.dns_resolver = Some(resolver);
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
        self.tls.accept_invalid_certs = accept_invalid_certs;
        self
    }

    /// Controls the use of hostname verification.
    ///
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If
    /// hostname verification is not used, any valid certificate for any
    /// site will be trusted for use from any other. This introduces a
    /// significant vulnerability to man-in-the-middle attacks.
    #[cfg(feature = "tls")]
    pub fn danger_accept_invalid_hostnames(
        mut self,
        accept_invalid_hostnames: bool,
    ) -> ClientBuilder {
        self.tls.accept_invalid_hostnames = accept_invalid_hostnames;
        self
    }

    /// Add a custom root certificate, in addition to the trusted roots the
    /// client already uses.
    ///
    /// This can be used to connect to a server that has a self-signed
    /// certificate for example.
    #[cfg(feature = "tls")]
    pub fn add_root_certificate(mut self, cert: crate::tls::Certificate) -> ClientBuilder {
        self.tls.root_certs.push(cert);
        self
    }

    /// Add several custom root certificates, in addition to the trusted
    /// roots the client already uses.
    #[cfg(feature = "tls")]
    pub fn tls_certs_merge(
        mut self,
        certs: impl IntoIterator<Item = crate::tls::Certificate>,
    ) -> ClientBuilder {
        self.tls.root_certs.extend(certs);
        self
    }

    /// Use **only** the given root certificates, disabling the built-in
    /// trust store.
    #[cfg(feature = "tls")]
    pub fn tls_certs_only(
        mut self,
        certs: impl IntoIterator<Item = crate::tls::Certificate>,
    ) -> ClientBuilder {
        self.tls.root_certs_only = Some(certs.into_iter().collect());
        self
    }

    /// Controls the use of the built-in root certificates (the bundled
    /// webpki-roots set, or the platform store with the `native-roots`
    /// feature).
    ///
    /// Defaults to `true`.
    #[cfg(feature = "tls")]
    pub fn tls_built_in_root_certs(mut self, enabled: bool) -> ClientBuilder {
        self.tls.built_in_root_certs = enabled;
        self
    }

    /// Sets the identity (client certificate and private key) to be used
    /// for mutual TLS.
    #[cfg(feature = "tls")]
    pub fn identity(mut self, identity: crate::tls::Identity) -> ClientBuilder {
        self.tls.identity = Some(identity);
        self
    }

    /// Set the certificate revocation lists to check server certificates
    /// against.
    #[cfg(feature = "tls")]
    pub fn tls_crls(
        mut self,
        crls: impl IntoIterator<Item = crate::tls::CertificateRevocationList>,
    ) -> ClientBuilder {
        self.tls.crls.extend(crls);
        self
    }

    /// Set the minimum required TLS version for connections.
    ///
    /// Note that rustls only implements TLS 1.2 and 1.3; lower minimums are
    /// accepted but have no additional effect.
    #[cfg(feature = "tls")]
    pub fn min_tls_version(mut self, version: crate::tls::Version) -> ClientBuilder {
        self.tls.min_version = Some(version);
        self
    }

    /// Set the maximum allowed TLS version for connections.
    #[cfg(feature = "tls")]
    pub fn max_tls_version(mut self, version: crate::tls::Version) -> ClientBuilder {
        self.tls.max_version = Some(version);
        self
    }

    /// Controls the use of Server Name Indication (SNI).
    ///
    /// Defaults to `true`.
    #[cfg(feature = "tls")]
    pub fn tls_sni(mut self, tls_sni: bool) -> ClientBuilder {
        self.tls.sni = tls_sni;
        self
    }

    /// Add [`crate::tls::TlsInfo`] (e.g. the peer certificate) to the
    /// response extensions.
    ///
    /// Defaults to `false`.
    #[cfg(feature = "tls")]
    pub fn tls_info(mut self, tls_info: bool) -> ClientBuilder {
        self.tls.tls_info = tls_info;
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

        // Advertise the codings this client can decode, unless the caller
        // manages encoding themselves: an explicit accept-encoding is
        // honored as-is, and a range request must not be answered with a
        // compressed (hence differently offset) body.
        if !headers.contains_key(ACCEPT_ENCODING)
            && !headers.contains_key(RANGE)
            && !self.inner.headers.contains_key(ACCEPT_ENCODING)
            && let Some(value) = self.inner.accepts.as_header()
        {
            headers.insert(ACCEPT_ENCODING, value);
        }

        // Merge default headers; request headers take precedence.
        for name in self.inner.headers.keys() {
            if !headers.contains_key(name) {
                for value in self.inner.headers.get_all(name) {
                    headers.append(name.clone(), value.clone());
                }
            }
        }

        // An overflowing deadline (e.g. `timeout(Duration::MAX)`) is treated
        // as no timeout rather than panicking.
        let deadline = timeout
            .or(self.inner.timeout)
            .and_then(|t| Instant::now().checked_add(t));

        // HTTP/1.0 servers don't understand chunked framing, so a streaming
        // body with unknown length must be buffered up front.
        if version == Version::HTTP_10
            && let Some(b) = body.as_mut()
            && b.len().is_none()
        {
            b.buffer()?;
        }

        // URLs already visited in this redirect chain, for `redirect::Attempt`.
        let mut previous: Vec<Url> = Vec::new();

        loop {
            if self.inner.https_only && url.scheme() != "https" {
                return Err(crate::error::builder(format!(
                    "URL scheme is not allowed for this client: {url}"
                ))
                .with_url(url));
            }

            // Credentials embedded in the URL become an Authorization
            // header, like reqwest.
            if !url.username().is_empty() || url.password().is_some() {
                let username = percent_encoding::percent_decode_str(url.username())
                    .decode_utf8_lossy()
                    .into_owned();
                let password = url.password().map(|p| {
                    percent_encoding::percent_decode_str(p)
                        .decode_utf8_lossy()
                        .into_owned()
                });
                headers.insert(
                    AUTHORIZATION,
                    basic_auth_value(username, password.as_deref()),
                );
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

            // The first configured proxy that intercepts this URL wins.
            let proxy_scheme = {
                let mut found: Option<ProxyScheme> = None;
                for proxy in &self.inner.proxies {
                    if let Some(scheme) = proxy.intercept(&url) {
                        found = Some(scheme.map_err(|e| e.with_url(url.clone()))?);
                        break;
                    }
                }
                found
            };
            // Plain http through an HTTP proxy is forwarded in
            // absolute-form; everything else behaves like a direct
            // connection once established.
            let forward = !https && matches!(proxy_scheme, Some(ProxyScheme::Http { .. }));

            let key = match &proxy_scheme {
                None => PoolKey {
                    https,
                    host: host.clone(),
                    port,
                    proxy: None,
                },
                Some(
                    scheme @ ProxyScheme::Http {
                        tls,
                        host: proxy_host,
                        port: proxy_port,
                        ..
                    },
                ) if forward => PoolKey {
                    // A forwarding connection can serve *any* target, so it
                    // is pooled under the proxy endpoint, not the target.
                    https: *tls,
                    host: proxy_host.clone(),
                    port: *proxy_port,
                    proxy: Some(format!("forward|{}", scheme.pool_id())),
                },
                Some(scheme) => PoolKey {
                    https,
                    host: host.clone(),
                    port,
                    proxy: Some(scheme.pool_id()),
                },
            };

            // Cookies are attached per hop: a redirect may cross origins,
            // and the store decides what applies to the new URL.
            #[cfg(feature = "cookies")]
            if let Some(store) = self.inner.cookie_store.as_deref() {
                crate::cookie::add_cookie_header(&mut headers, store, &url);
            }

            // For absolute-form forwarding the proxy's auth and extra
            // headers ride along with each request.
            let forward_headers;
            let write_headers: &HeaderMap = if forward {
                let mut merged = headers.clone();
                if let Some(ProxyScheme::Http {
                    auth,
                    headers: extra,
                    ..
                }) = &proxy_scheme
                {
                    if let Some(auth) = auth {
                        merged.insert(PROXY_AUTHORIZATION, auth.clone());
                    }
                    // Replace rather than append: a duplicated singleton
                    // header (user-agent, host, ...) is a smuggling hazard
                    // and RFC 9110 forbids generating one.
                    crate::request::replace_headers(&mut merged, extra.clone());
                }
                forward_headers = merged;
                &forward_headers
            } else {
                &headers
            };
            let target = if forward {
                RequestTarget::Absolute
            } else {
                RequestTarget::Origin
            };

            // Validate the request framing before opening a connection.
            // Conflicting Content-Length / Transfer-Encoding headers are
            // request-smuggling vectors and must be rejected without ever
            // touching the network; doing it up front also keeps the error
            // class (`is_request`) stable across platforms, so a server that
            // hangs up during the handshake can't mask it with a connect
            // error.
            proto::negotiate_framing(&method, version, write_headers, body.as_ref())
                .map_err(|e| crate::error::from_io(e).with_url(url.clone()))?;

            // A request written on a pooled connection can hit a socket the
            // server already closed; retry once on a fresh connection. A
            // non-idempotent request may have been acted upon even if no
            // response bytes arrived, so it must not be replayed.
            let retryable = is_idempotent(&method)
                && (body.is_none() || body.as_ref().is_some_and(|b| b.as_bytes().is_some()));

            let (conn, head) = loop {
                let (pooled, mut conn) = match self.inner.pool.checkout(&key) {
                    Some(conn) => (true, conn),
                    None => (
                        false,
                        self.inner
                            .connector
                            .connect(https, &host, port, proxy_scheme.as_ref(), deadline)
                            .map_err(|e| e.with_url(url.clone()))?,
                    ),
                };

                let received_before = conn.received_bytes();
                // On success the bool reports whether the request was fully
                // written; a response obtained after a broken upload is
                // still valid, but the connection must not be reused.
                let attempt = (|| -> io::Result<(proto::Head, bool)> {
                    conn.set_deadline(deadline)?;
                    match proto::write_request(
                        &mut conn,
                        &method,
                        &url,
                        version,
                        write_headers,
                        body.as_mut(),
                        target,
                        &self.inner.http1,
                    ) {
                        Ok(()) => {
                            proto::read_head(&mut conn, &self.inner.http1).map(|head| (head, true))
                        }
                        // The server may have replied before aborting our
                        // upload (e.g. 413); prefer that response over the
                        // write error.
                        Err(e) if is_stale_conn_error(&e) => {
                            match proto::read_head(&mut conn, &self.inner.http1) {
                                Ok(head) => Ok((head, false)),
                                Err(_) => Err(e),
                            }
                        }
                        Err(e) => Err(e),
                    }
                })();

                match attempt {
                    Ok(head) => break (conn, head),
                    // Only retry when the server never started responding:
                    // once any response bytes arrived, the request may have
                    // been acted upon and must not be replayed.
                    Err(e)
                        if pooled
                            && retryable
                            && is_stale_conn_error(&e)
                            && conn.received_bytes() == received_before =>
                    {
                        continue;
                    }
                    Err(e) => return Err(crate::error::from_io(e).with_url(url.clone())),
                }
            };
            let (head, request_fully_written) = head;

            #[cfg(feature = "cookies")]
            if let Some(store) = self.inner.cookie_store.as_deref() {
                crate::cookie::store_response_cookies(&head.headers, store, &url);
            }

            let length = proto::body_length(&method, head.status, head.version, &head.headers)
                .map_err(|e| crate::error::from_io(e).with_url(url.clone()))?;
            let reusable = request_fully_written
                && proto::can_keep_alive(version, write_headers)
                && proto::can_keep_alive(head.version, &head.headers)
                && length != BodyLength::CloseDelimited;
            let reuse = reusable.then(|| (self.inner.pool.clone(), key));

            // Handle redirects.
            if self.inner.redirect.follows_redirects()
                && let Some(next_url) = redirect_target(head.status, &head.headers, &url)
            {
                let next_url = next_url?;
                previous.push(url.clone());

                match self.inner.redirect.check(head.status, &next_url, &previous) {
                    redirect::ActionKind::Stop => {
                        // Fall through: the 30x response is the final result.
                    }
                    redirect::ActionKind::Error(e) => {
                        return Err(crate::error::redirect(e, url));
                    }
                    redirect::ActionKind::Follow => {
                        if self.inner.https_only && next_url.scheme() != "https" {
                            return Err(crate::error::redirect(
                                format!("redirect to insecure scheme is not allowed: {next_url}"),
                                url,
                            ));
                        }

                        // Drain the redirect response body so the connection
                        // can be reused.
                        BodyReader::new(conn, length, reuse, deadline).drain(REDIRECT_DRAIN_MAX);

                        // Like reqwest: 301/302/303 turn every method except
                        // HEAD into a body-less GET; 307/308 keep method +
                        // body.
                        let drop_body = matches!(
                            head.status,
                            StatusCode::MOVED_PERMANENTLY
                                | StatusCode::FOUND
                                | StatusCode::SEE_OTHER
                        );
                        if drop_body {
                            if method != Method::HEAD {
                                method = Method::GET;
                            }
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
                            && b.as_bytes().is_none()
                        {
                            return Err(crate::error::redirect(
                                "cannot follow redirect with a streaming body",
                                url,
                            ));
                        }

                        // The next hop gets its own cookies from the store.
                        #[cfg(feature = "cookies")]
                        if self.inner.cookie_store.is_some() {
                            headers.remove(COOKIE);
                        }

                        if self.inner.referer
                            && let Some(referer) = make_referer(&next_url, &url)
                        {
                            headers.insert(REFERER, referer);
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
                }
            }

            let remote_addr = conn.remote_addr();
            // Only for a request that actually spoke TLS to the origin: on
            // a plain-http request forwarded through an https proxy the
            // outermost session belongs to the proxy, and reporting its
            // certificate would look like end-to-end authentication.
            #[cfg(feature = "tls")]
            let tls_info = (self.inner.tls_info && https).then(|| crate::tls::TlsInfo {
                peer_certificate: conn.peer_certificate(),
            });
            let reader = BodyReader::new(conn, length, reuse, deadline);
            let mut response_headers = head.headers;
            let body = Decoder::detect(
                reader,
                &mut response_headers,
                self.inner.accepts,
                !matches!(length, BodyLength::Empty | BodyLength::Len(0)),
            );
            #[allow(unused_mut)]
            let mut response = Response::new(
                head.status,
                head.version,
                response_headers,
                url,
                remote_addr,
                body,
            );
            #[cfg(feature = "tls")]
            if let Some(tls_info) = tls_info {
                response.extensions_mut().insert(tls_info);
            }
            return Ok(response);
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish()
    }
}

/// The `Referer` header sent when following a redirect: the previous URL
/// with credentials and fragment stripped. Never sent on an https -> http
/// downgrade.
fn make_referer(next: &Url, previous: &Url) -> Option<HeaderValue> {
    if next.scheme() == "http" && previous.scheme() == "https" {
        return None;
    }
    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    referer.set_fragment(None);
    referer.as_str().parse().ok()
}

/// Idempotent methods per RFC 9110 §9.2.2; extension methods are treated as
/// non-idempotent.
fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
    )
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
        Ok(mut url) => match url.scheme() {
            "http" | "https" => {
                // RFC 9110 §10.2.2: a Location without a fragment inherits
                // the original URL's fragment.
                if url.fragment().is_none() && base.fragment().is_some() {
                    url.set_fragment(base.fragment());
                }
                Some(Ok(url))
            }
            _ => Some(Err(crate::error::redirect(
                format!("redirect to unsupported scheme: {url}"),
                base.clone(),
            ))),
        },
        Err(e) => Some(Err(crate::error::redirect(e, base.clone()))),
    }
}
