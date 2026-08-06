//! Proxy support: HTTP, HTTPS and SOCKS proxies, plus `NO_PROXY` rules.
//!
//! A [`Proxy`] is added to a client with
//! [`ClientBuilder::proxy`](crate::ClientBuilder::proxy). Without explicit
//! proxies, the standard environment variables (`http_proxy`,
//! `https_proxy`, `all_proxy`, `no_proxy` and their uppercase variants)
//! are honored.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use http::header::{HeaderMap, HeaderValue};
use url::Url;

use crate::request::basic_auth_value;

/// Configuration of a proxy that a `Client` should pass requests to.
///
/// A `Proxy` has a couple pieces to it:
///
/// - a URL of how to talk to the proxy
/// - rules on what `Client` requests should be directed to the proxy
///
/// For instance, let's look at `Proxy::http`:
///
/// ```rust
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = bangboo::Proxy::http("https://secure.example")?;
/// # Ok(())
/// # }
/// ```
///
/// This proxy will intercept all HTTP requests, and make use of the proxy.
/// Notice that the request itself can be a plain HTTP request, but the
/// connection to the proxy can use HTTPS.
#[derive(Clone)]
pub struct Proxy {
    intercept: Intercept,
    no_proxy: Option<NoProxy>,
}

#[derive(Clone)]
enum Intercept {
    All(ProxyScheme),
    Http(ProxyScheme),
    Https(ProxyScheme),
    Custom(Custom),
}

type CustomFn = dyn Fn(&Url) -> Option<crate::Result<ProxyScheme>> + Send + Sync;

#[derive(Clone)]
struct Custom {
    func: Arc<CustomFn>,
}

impl fmt::Debug for Custom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("_")
    }
}

/// How to reach the proxy itself.
#[derive(Clone, Debug)]
pub(crate) enum ProxyScheme {
    /// An HTTP proxy: plain requests are forwarded in absolute-form, https
    /// requests are tunneled with `CONNECT`.
    Http {
        /// TLS to the proxy itself (an `https://` proxy URL).
        tls: bool,
        host: String,
        port: u16,
        auth: Option<HeaderValue>,
        /// Extra headers sent to the proxy (absolute-form and CONNECT).
        headers: HeaderMap,
    },
    /// A SOCKS4 proxy. `remote_dns` selects socks4a. SOCKS4's only
    /// authentication mechanism is the USERID field.
    Socks4 {
        host: String,
        port: u16,
        remote_dns: bool,
        user_id: String,
    },
    /// A SOCKS5 proxy. `remote_dns` selects socks5h.
    Socks5 {
        host: String,
        port: u16,
        auth: Option<(String, String)>,
        remote_dns: bool,
    },
}

impl ProxyScheme {
    fn parse(url: Url) -> crate::Result<Self> {
        let host = url
            .host_str()
            .ok_or_else(|| crate::error::builder("proxy URL has no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let username = percent_encoding::percent_decode_str(url.username())
            .decode_utf8_lossy()
            .into_owned();
        let password = url
            .password()
            .map(|p| {
                percent_encoding::percent_decode_str(p)
                    .decode_utf8_lossy()
                    .into_owned()
            });
        let has_auth = !username.is_empty() || password.is_some();

        let scheme = match url.scheme() {
            "http" | "https" => {
                let tls = url.scheme() == "https";
                let port = url.port().unwrap_or(if tls { 443 } else { 80 });
                ProxyScheme::Http {
                    tls,
                    host,
                    port,
                    auth: has_auth.then(|| basic_auth_value(&username, password.as_deref())),
                    headers: HeaderMap::new(),
                }
            }
            "socks4" | "socks4a" => ProxyScheme::Socks4 {
                host,
                port: url.port().unwrap_or(1080),
                remote_dns: url.scheme() == "socks4a",
                user_id: username,
            },
            "socks5" | "socks5h" => ProxyScheme::Socks5 {
                host,
                port: url.port().unwrap_or(1080),
                auth: has_auth.then_some((username, password.unwrap_or_default())),
                remote_dns: url.scheme() == "socks5h",
            },
            other => {
                return Err(crate::error::builder(format!(
                    "unsupported proxy scheme: {other}"
                )));
            }
        };
        Ok(scheme)
    }

    fn set_basic_auth(&mut self, username: &str, password: &str) {
        match self {
            ProxyScheme::Http { auth, .. } => {
                *auth = Some(basic_auth_value(username, Some(password)));
            }
            // SOCKS4 has no password; the username becomes the USERID.
            ProxyScheme::Socks4 { user_id, .. } => {
                *user_id = username.to_string();
            }
            ProxyScheme::Socks5 { auth, .. } => {
                *auth = Some((username.to_string(), password.to_string()));
            }
        }
    }

    fn set_custom_http_auth(&mut self, value: HeaderValue) {
        if let ProxyScheme::Http { auth, .. } = self {
            *auth = Some(value);
        }
    }

    fn set_headers(&mut self, extra: HeaderMap) {
        if let ProxyScheme::Http { headers, .. } = self {
            crate::request::replace_headers(headers, extra);
        }
    }

    /// A stable identifier for connection pooling: connections established
    /// through different proxies must never be mixed.
    ///
    /// Credentials and extra headers are part of the identity. For a
    /// tunnel (CONNECT or SOCKS) they are presented once when the tunnel is
    /// built and then baked into the connection, so reusing a tunnel opened
    /// under different credentials would silently borrow the other
    /// identity's authorization.
    pub(crate) fn pool_id(&self) -> String {
        use std::hash::{DefaultHasher, Hash, Hasher};

        match self {
            ProxyScheme::Http {
                tls,
                host,
                port,
                auth,
                headers,
            } => {
                let scheme = if *tls { "https" } else { "http" };
                let mut hasher = DefaultHasher::new();
                auth.as_ref().map(|auth| auth.as_bytes()).hash(&mut hasher);
                for (name, value) in headers {
                    name.hash(&mut hasher);
                    value.hash(&mut hasher);
                }
                format!("{scheme}://{host}:{port}#{:x}", hasher.finish())
            }
            ProxyScheme::Socks4 {
                host,
                port,
                remote_dns,
                user_id,
            } => {
                let scheme = if *remote_dns { "socks4a" } else { "socks4" };
                format!("{scheme}://{host}:{port}#{user_id}")
            }
            ProxyScheme::Socks5 {
                host,
                port,
                remote_dns,
                auth,
            } => {
                let scheme = if *remote_dns { "socks5h" } else { "socks5" };
                let mut hasher = DefaultHasher::new();
                auth.hash(&mut hasher);
                format!("{scheme}://{host}:{port}#{:x}", hasher.finish())
            }
        }
    }
}

/// A trait used by the `Proxy` constructors: something that can be
/// converted into a proxy URL.
pub trait IntoProxy {
    #[doc(hidden)]
    fn into_proxy(self) -> crate::Result<Url>;
}

fn parse_proxy_str(value: &str) -> crate::Result<Url> {
    match Url::parse(value) {
        Ok(url) => Ok(url),
        // A bare `host:port` has no scheme; retry as an http proxy.
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            Url::parse(&format!("http://{value}")).map_err(crate::error::builder)
        }
        Err(e) => Err(crate::error::builder(e)),
    }
}

impl IntoProxy for &str {
    fn into_proxy(self) -> crate::Result<Url> {
        parse_proxy_str(self)
    }
}

impl IntoProxy for String {
    fn into_proxy(self) -> crate::Result<Url> {
        parse_proxy_str(&self)
    }
}

impl IntoProxy for &String {
    fn into_proxy(self) -> crate::Result<Url> {
        parse_proxy_str(self)
    }
}

impl IntoProxy for Url {
    fn into_proxy(self) -> crate::Result<Url> {
        Ok(self)
    }
}

impl Proxy {
    /// Proxy all HTTP traffic to the passed URL.
    pub fn http<U: IntoProxy>(proxy_scheme: U) -> crate::Result<Proxy> {
        Ok(Proxy::new(Intercept::Http(ProxyScheme::parse(
            proxy_scheme.into_proxy()?,
        )?)))
    }

    /// Proxy all HTTPS traffic to the passed URL.
    pub fn https<U: IntoProxy>(proxy_scheme: U) -> crate::Result<Proxy> {
        Ok(Proxy::new(Intercept::Https(ProxyScheme::parse(
            proxy_scheme.into_proxy()?,
        )?)))
    }

    /// Proxy **all** traffic to the passed URL.
    pub fn all<U: IntoProxy>(proxy_scheme: U) -> crate::Result<Proxy> {
        Ok(Proxy::new(Intercept::All(ProxyScheme::parse(
            proxy_scheme.into_proxy()?,
        )?)))
    }

    /// Provide a custom function to determine what traffic to proxy to
    /// where.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let target = bangboo::Url::parse("https://my.prox")?;
    /// let proxy = bangboo::Proxy::custom(move |url| {
    ///     if url.host_str() == Some("hyper.rs") {
    ///         Some(target.clone())
    ///     } else {
    ///         None
    ///     }
    /// });
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom<F, U: IntoProxy>(fun: F) -> Proxy
    where
        F: Fn(&Url) -> Option<U> + Send + Sync + 'static,
    {
        Proxy::new(Intercept::Custom(Custom {
            func: Arc::new(move |url| {
                fun(url).map(|into| ProxyScheme::parse(into.into_proxy()?))
            }),
        }))
    }

    fn new(intercept: Intercept) -> Proxy {
        Proxy {
            intercept,
            no_proxy: None,
        }
    }

    /// Set the `Proxy-Authorization` header using Basic auth.
    pub fn basic_auth(mut self, username: &str, password: &str) -> Proxy {
        self.intercept.set_basic_auth(username, password);
        self
    }

    /// Set the `Proxy-Authorization` header to a specified value.
    pub fn custom_http_auth(mut self, header_value: HeaderValue) -> Proxy {
        self.intercept.set_custom_http_auth(header_value);
        self
    }

    /// Adds extra headers to be sent to the proxy (HTTP proxies only).
    pub fn headers(mut self, headers: HeaderMap) -> Proxy {
        self.intercept.set_headers(headers);
        self
    }

    /// Adds a `NoProxy` exclusion to this Proxy rule. Set to `None` to
    /// never exclude anything.
    pub fn no_proxy(mut self, no_proxy: Option<NoProxy>) -> Proxy {
        self.no_proxy = no_proxy;
        self
    }

    /// Returns the proxy scheme to use for `url`, if this proxy
    /// intercepts it.
    pub(crate) fn intercept(&self, url: &Url) -> Option<crate::Result<ProxyScheme>> {
        if let Some(ref no_proxy) = self.no_proxy
            && no_proxy.contains(url.host_str().unwrap_or_default())
        {
            return None;
        }
        match self.intercept {
            Intercept::All(ref scheme) => Some(Ok(scheme.clone())),
            Intercept::Http(ref scheme) if url.scheme() == "http" => Some(Ok(scheme.clone())),
            Intercept::Https(ref scheme) if url.scheme() == "https" => Some(Ok(scheme.clone())),
            Intercept::Custom(ref custom) => (custom.func)(url),
            _ => None,
        }
    }
}

impl Intercept {
    fn set_basic_auth(&mut self, username: &str, password: &str) {
        match self {
            Intercept::All(s) | Intercept::Http(s) | Intercept::Https(s) => {
                s.set_basic_auth(username, password)
            }
            Intercept::Custom(_) => {
                panic!("Proxy::basic_auth() is not supported for custom proxies")
            }
        }
    }

    fn set_custom_http_auth(&mut self, value: HeaderValue) {
        match self {
            Intercept::All(s) | Intercept::Http(s) | Intercept::Https(s) => {
                s.set_custom_http_auth(value)
            }
            Intercept::Custom(_) => {
                panic!("Proxy::custom_http_auth() is not supported for custom proxies")
            }
        }
    }

    fn set_headers(&mut self, headers: HeaderMap) {
        match self {
            Intercept::All(s) | Intercept::Http(s) | Intercept::Https(s) => s.set_headers(headers),
            Intercept::Custom(_) => {
                panic!("Proxy::headers() is not supported for custom proxies")
            }
        }
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Proxy");
        match self.intercept {
            Intercept::All(ref s) => d.field("intercept", &format_args!("All({})", s.pool_id())),
            Intercept::Http(ref s) => d.field("intercept", &format_args!("Http({})", s.pool_id())),
            Intercept::Https(ref s) => {
                d.field("intercept", &format_args!("Https({})", s.pool_id()))
            }
            Intercept::Custom(_) => d.field("intercept", &"Custom"),
        };
        d.finish()
    }
}

/// A configuration for filtering out requests that shouldn't be proxied.
#[derive(Clone, Debug, Default)]
pub struct NoProxy {
    domains: Vec<String>,
    ips: Vec<IpAddr>,
    cidrs: Vec<(IpAddr, u8)>,
    match_all: bool,
}

impl NoProxy {
    /// Returns a new no-proxy configuration based on the `NO_PROXY` /
    /// `no_proxy` environment variables, or `None` if they are unset or
    /// empty.
    ///
    /// The rules are a comma-separated list of:
    /// - `*` to match every host
    /// - an IP address (`10.0.0.1`)
    /// - a CIDR block (`10.0.0.0/8`)
    /// - a domain, matching the domain itself and all subdomains
    ///   (`example.com` or `.example.com`)
    pub fn from_env() -> Option<NoProxy> {
        let raw = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok()?;
        Self::from_string(&raw)
    }

    /// Returns a new no-proxy configuration from a comma-separated string,
    /// or `None` if the string is empty. See [`from_env`][Self::from_env]
    /// for the rule format.
    pub fn from_string(no_proxy_list: &str) -> Option<NoProxy> {
        let mut result = NoProxy::default();
        for entry in no_proxy_list.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry == "*" {
                result.match_all = true;
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                result.ips.push(ip);
            } else if let Some((base, bits)) = entry.split_once('/')
                && let (Ok(base), Ok(bits)) = (base.parse::<IpAddr>(), bits.parse::<u8>())
            {
                result.cidrs.push((base, bits));
            } else {
                let domain = entry.trim_start_matches('.').to_ascii_lowercase();
                result.domains.push(domain);
            }
        }
        if result.match_all
            || !result.domains.is_empty()
            || !result.ips.is_empty()
            || !result.cidrs.is_empty()
        {
            Some(result)
        } else {
            None
        }
    }

    /// Whether the no-proxy rules exclude `host` from being proxied.
    pub(crate) fn contains(&self, host: &str) -> bool {
        if self.match_all {
            return true;
        }
        // Url::host_str keeps brackets on IPv6 literals.
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            if self.ips.contains(&ip) {
                return true;
            }
            return self.cidrs.iter().any(|&(base, bits)| cidr_match(ip, base, bits));
        }
        // A fully-qualified name with a trailing dot names the same host.
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|domain| {
            host == *domain
                || (host.len() > domain.len()
                    && host.ends_with(domain.as_str())
                    && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
        })
    }
}

fn cidr_match(ip: IpAddr, base: IpAddr, bits: u8) -> bool {
    fn matches(ip: u128, base: u128, width: u8, bits: u8) -> bool {
        if bits > width {
            return false;
        }
        if bits == 0 {
            return true;
        }
        let shift = width - bits;
        (ip >> shift) == (base >> shift)
    }
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => {
            matches(u32::from(ip) as u128, u32::from(base) as u128, 32, bits)
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) => {
            matches(u128::from(ip), u128::from(base), 128, bits)
        }
        _ => false,
    }
}

/// Builds the proxies configured by the standard environment variables.
pub(crate) fn from_environment() -> Vec<Proxy> {
    let no_proxy = NoProxy::from_env();
    let mut proxies = Vec::new();
    let mut push = |var_lower: &str, var_upper: &str, make: fn(String) -> crate::Result<Proxy>| {
        if let Some(value) = env_nonempty(var_lower).or_else(|| env_nonempty(var_upper))
            && let Ok(proxy) = make(value)
        {
            proxies.push(proxy.no_proxy(no_proxy.clone()));
        }
    };
    push("http_proxy", "HTTP_PROXY", Proxy::http);
    push("https_proxy", "HTTPS_PROXY", Proxy::https);
    push("all_proxy", "ALL_PROXY", Proxy::all);
    proxies
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{HeaderMap, NoProxy, Proxy, Url};

    fn pool_id(proxy: &Proxy, url: &str) -> String {
        proxy
            .intercept(&Url::parse(url).unwrap())
            .expect("proxy did not intercept")
            .expect("invalid proxy")
            .pool_id()
    }

    /// Credentials and extra headers are consumed once when a tunnel is
    /// established, so connections opened under different identities must
    /// land in different pool slots.
    #[test]
    fn pool_id_separates_proxy_identities() {
        let url = "https://target.example/";
        let alice = Proxy::all("http://alice:pw@p:8080").unwrap();
        let bob = Proxy::all("http://bob:pw@p:8080").unwrap();
        let anon = Proxy::all("http://p:8080").unwrap();
        assert_ne!(pool_id(&alice, url), pool_id(&bob, url));
        assert_ne!(pool_id(&alice, url), pool_id(&anon, url));
        // The same identity is stable, or nothing would ever be reused.
        assert_eq!(
            pool_id(&alice, url),
            pool_id(&Proxy::all("http://alice:pw@p:8080").unwrap(), url)
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", "a".parse().unwrap());
        let tenant_a = Proxy::all("http://p:8080").unwrap().headers(headers);
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", "b".parse().unwrap());
        let tenant_b = Proxy::all("http://p:8080").unwrap().headers(headers);
        assert_ne!(pool_id(&tenant_a, url), pool_id(&tenant_b, url));

        // SOCKS credentials and the SOCKS4 user id count too.
        assert_ne!(
            pool_id(&Proxy::all("socks5://u1:p@p:1080").unwrap(), url),
            pool_id(&Proxy::all("socks5://u2:p@p:1080").unwrap(), url)
        );
        assert_ne!(
            pool_id(&Proxy::all("socks4://bob@p:1080").unwrap(), url),
            pool_id(&Proxy::all("socks4://p:1080").unwrap(), url)
        );
    }

    #[test]
    fn no_proxy_matching() {
        let no_proxy =
            NoProxy::from_string("10.0.0.0/8, 192.168.1.1, example.com, .dot.com").unwrap();
        assert!(no_proxy.contains("10.1.2.3"));
        assert!(!no_proxy.contains("11.1.2.3"));
        assert!(no_proxy.contains("192.168.1.1"));
        assert!(!no_proxy.contains("192.168.1.2"));
        assert!(no_proxy.contains("example.com"));
        assert!(no_proxy.contains("sub.example.com"));
        assert!(no_proxy.contains("EXAMPLE.com"));
        assert!(!no_proxy.contains("notexample.com"));
        assert!(no_proxy.contains("dot.com"));
        assert!(no_proxy.contains("x.dot.com"));
        // A trailing-dot FQDN names the same host.
        assert!(no_proxy.contains("example.com."));
        assert!(no_proxy.contains("sub.example.com."));

        assert!(NoProxy::from_string("*").unwrap().contains("anything.at.all"));
        assert!(NoProxy::from_string("").is_none());
        assert!(NoProxy::from_string(" , ").is_none());

        // IPv6, with and without brackets.
        let v6 = NoProxy::from_string("::1, fd00::/8").unwrap();
        assert!(v6.contains("[::1]"));
        assert!(v6.contains("::1"));
        assert!(v6.contains("fd12::5"));
        assert!(!v6.contains("fe80::1"));
    }
}
