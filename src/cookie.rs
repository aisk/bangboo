//! HTTP Cookies
//!
//! Requires the `cookies` feature. A [`Jar`] (or any [`CookieStore`]
//! implementation) is attached to a client with
//! [`ClientBuilder::cookie_provider`][crate::ClientBuilder::cookie_provider],
//! or the built-in one is enabled with
//! [`ClientBuilder::cookie_store`][crate::ClientBuilder::cookie_store].

use std::fmt;
use std::sync::RwLock;
use std::time::SystemTime;

use http::HeaderValue;
use http::header::{COOKIE, HeaderMap, SET_COOKIE};
use url::Url;

/// Actions for a persistent cookie store providing session support.
pub trait CookieStore: Send + Sync {
    /// Store a set of `Set-Cookie` header values received from `url`.
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url);

    /// Get any `Cookie` header value to send for `url`.
    fn cookies(&self, url: &Url) -> Option<HeaderValue>;
}

/// A single HTTP cookie, as parsed from a `Set-Cookie` response header.
pub struct Cookie<'a>(cookie::Cookie<'a>);

impl<'a> Cookie<'a> {
    fn parse(value: &'a HeaderValue) -> crate::Result<Cookie<'a>> {
        let value = value.to_str().map_err(crate::error::decode)?;
        cookie::Cookie::parse(value)
            .map(Cookie)
            .map_err(crate::error::decode)
    }

    /// The name of the cookie.
    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// The value of the cookie.
    pub fn value(&self) -> &str {
        self.0.value()
    }

    /// Returns true if the `HttpOnly` directive is enabled.
    pub fn http_only(&self) -> bool {
        self.0.http_only().unwrap_or(false)
    }

    /// Returns true if the `Secure` directive is enabled.
    pub fn secure(&self) -> bool {
        self.0.secure().unwrap_or(false)
    }

    /// Returns true if `SameSite` is `Lax`.
    pub fn same_site_lax(&self) -> bool {
        self.0.same_site() == Some(cookie::SameSite::Lax)
    }

    /// Returns true if `SameSite` is `Strict`.
    pub fn same_site_strict(&self) -> bool {
        self.0.same_site() == Some(cookie::SameSite::Strict)
    }

    /// Returns the path directive of the cookie, if set.
    pub fn path(&self) -> Option<&str> {
        self.0.path()
    }

    /// Returns the domain directive of the cookie, if set.
    pub fn domain(&self) -> Option<&str> {
        self.0.domain()
    }

    /// Get the `Max-Age` information.
    pub fn max_age(&self) -> Option<std::time::Duration> {
        self.0.max_age().map(|d| {
            d.try_into()
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        })
    }

    /// The cookie expiration time.
    pub fn expires(&self) -> Option<SystemTime> {
        match self.0.expires() {
            Some(cookie::Expiration::DateTime(offset)) => Some(SystemTime::from(offset)),
            None | Some(cookie::Expiration::Session) => None,
        }
    }
}

impl fmt::Debug for Cookie<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Extracts the cookies from a response's `Set-Cookie` headers.
pub(crate) fn extract_response_cookies(
    headers: &HeaderMap,
) -> impl Iterator<Item = crate::Result<Cookie<'_>>> {
    headers.get_all(SET_COOKIE).iter().map(Cookie::parse)
}

/// A good default `CookieStore` implementation.
///
/// This is the implementation used when simply calling
/// [`cookie_store(true)`][crate::ClientBuilder::cookie_store]. It is also a
/// reasonable starting point for a custom implementation.
#[derive(Default)]
pub struct Jar(RwLock<cookie_store::CookieStore>);

impl Jar {
    /// Add a cookie to this jar.
    ///
    /// # Example
    ///
    /// ```
    /// use bangboo::{cookie::Jar, Url};
    ///
    /// let cookie = "foo=bar; Domain=example.com";
    /// let url = "https://example.com".parse::<Url>().unwrap();
    ///
    /// let jar = Jar::default();
    /// jar.add_cookie_str(cookie, &url);
    /// ```
    pub fn add_cookie_str(&self, cookie: &str, url: &Url) {
        let cookies = cookie::Cookie::parse(cookie)
            .ok()
            .map(|c| c.into_owned())
            .into_iter();
        self.0.write().unwrap().store_response_cookies(cookies, url);
    }
}

impl CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url) {
        let iter = cookie_headers.filter_map(|value| {
            std::str::from_utf8(value.as_bytes())
                .map_err(cookie::ParseError::from)
                .and_then(cookie::Cookie::parse)
                .map(|c| c.into_owned())
                .ok()
        });
        self.0.write().unwrap().store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let store = self.0.read().unwrap();
        let value = store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if value.is_empty() {
            return None;
        }
        HeaderValue::from_maybe_shared(bytes::Bytes::from(value)).ok()
    }
}

impl fmt::Debug for Jar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jar").finish()
    }
}

/// Merges the store's cookies for `url` into `headers`, leaving a
/// caller-supplied `Cookie` header untouched.
pub(crate) fn add_cookie_header(headers: &mut HeaderMap, store: &dyn CookieStore, url: &Url) {
    if headers.contains_key(COOKIE) {
        return;
    }
    if let Some(header) = store.cookies(url) {
        headers.insert(COOKIE, header);
    }
}

/// Feeds a response's `Set-Cookie` headers into the store.
pub(crate) fn store_response_cookies(headers: &HeaderMap, store: &dyn CookieStore, url: &Url) {
    let mut values = headers.get_all(SET_COOKIE).iter().peekable();
    if values.peek().is_some() {
        store.set_cookies(&mut values, url);
    }
}
