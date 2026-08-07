//! # bangboo
//!
//! A truly synchronous HTTP/1.1 client, with an API modeled after
//! [`reqwest::blocking`](https://docs.rs/reqwest/latest/reqwest/blocking/).
//!
//! Unlike `reqwest::blocking` (which spins up a tokio runtime on a
//! background thread), bangboo is built directly on `std::net::TcpStream`.
//! There is no async runtime anywhere: every call blocks the calling
//! thread, and it is safe to use from within an async runtime's
//! `spawn_blocking` or anywhere else.
//!
//! ## Making requests
//!
//! For a single request, use the [`get`] shortcut:
//!
//! ```rust,no_run
//! # fn run() -> Result<(), bangboo::Error> {
//! let body = bangboo::get("https://www.rust-lang.org")?.text()?;
//! println!("body = {body:?}");
//! # Ok(())
//! # }
//! ```
//!
//! If you plan to perform multiple requests, create a [`Client`] and reuse
//! it to take advantage of keep-alive connection pooling:
//!
//! ```rust,no_run
//! # fn run() -> Result<(), bangboo::Error> {
//! let client = bangboo::Client::new();
//! let res = client
//!     .post("http://httpbin.org/post")
//!     .body("the exact body that is sent")
//!     .send()?;
//! # Ok(())
//! # }
//! ```
//!
//! To send JSON, pass any [`serde::Serialize`] value to
//! [`RequestBuilder::json`]; it also sets the
//! `Content-Type: application/json` header:
//!
//! ```rust,no_run
//! # fn run() -> Result<(), bangboo::Error> {
//! # let client = bangboo::Client::new();
//! let res = client
//!     .post("http://httpbin.org/post")
//!     .json(&serde_json::json!({ "lang": "rust" }))
//!     .send()?;
//! # Ok(())
//! # }
//! ```
//!
//! To receive JSON, [`Response::json`] deserializes the response body into
//! any [`serde::Deserialize`] type:
//!
//! ```rust,no_run
//! # fn run() -> Result<(), bangboo::Error> {
//! let json: serde_json::Value = bangboo::get("http://httpbin.org/json")?.json()?;
//! println!("{}", json["slideshow"]["title"]);
//! # Ok(())
//! # }
//! ```
//!
//! [`Response`] implements `std::io::Read`, so response bodies can be
//! streamed instead of buffered:
//!
//! ```rust,no_run
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut res = bangboo::get("https://www.rust-lang.org")?;
//! let mut file = std::fs::File::create("page.html")?;
//! res.copy_to(&mut file)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! | Feature | Default | What it adds |
//! |---|---|---|
//! | `tls` | yes | HTTPS via rustls, and the [`tls`] configuration module |
//! | `charset` | yes | charset-aware [`Response::text`] and [`Response::text_with_charset`] |
//! | `native-roots` | no | validate against the OS certificate store instead of the bundled roots |
//! | `cookies` | no | the [`cookie`] store, `Set-Cookie` handling, [`Response::cookies`] |
//! | `gzip`, `deflate`, `brotli`, `zstd` | no | transparent response body decompression |
//! | `multipart` | no | [`multipart::Form`] bodies |
//!
//! Proxies (HTTP, HTTPS and SOCKS4/5, plus the `*_proxy` environment
//! variables) and DNS overrides are always available.
//!
//! With the `tls` feature, server certificates are validated against the
//! bundled Mozilla root set ([`webpki-roots`]) by default; the platform
//! store can be used instead with `native-roots`, and additional roots,
//! client certificates and version bounds are configured through the
//! [`ClientBuilder`].
//!
//! ## Scope
//!
//! bangboo intentionally implements only HTTP/1.1 (and 1.0). Features of
//! reqwest that exist only because of its async internals, or that require
//! HTTP/2+ (`http2_*`, `http3_*`, tower connector layers), are omitted.
//!
//! [`webpki-roots`]: https://docs.rs/webpki-roots

mod body;
mod client;
mod connect;
#[cfg(feature = "cookies")]
pub mod cookie;
mod decoder;
pub mod dns;
mod error;
mod into_url;
#[cfg(feature = "multipart")]
pub mod multipart;
mod pool;
mod proto;
mod proxy;
pub mod redirect;
mod request;
mod response;
mod socks;
#[cfg(feature = "tls")]
pub mod tls;

pub use self::body::Body;
pub use self::client::{Client, ClientBuilder};
pub use self::error::{Error, Result};
pub use self::into_url::IntoUrl;
pub use self::proxy::{IntoProxy, NoProxy, Proxy};
pub use self::request::{Request, RequestBuilder};
pub use self::response::Response;
#[cfg(feature = "tls")]
pub use self::tls::{Certificate, CertificateRevocationList, Identity};

// Re-exports of common types used in the API, mirroring reqwest.
pub use http::Method;
pub use http::StatusCode;
pub use http::Version;
pub use http::header;
pub use url::Url;

/// Shortcut method to quickly make a `GET` request.
///
/// **NOTE**: This function creates a new internal `Client` on each call,
/// and so should not be used if making many requests. Create a
/// [`Client`] instead.
///
/// # Examples
///
/// ```rust,no_run
/// # fn run() -> Result<(), bangboo::Error> {
/// let body = bangboo::get("https://www.rust-lang.org")?.text()?;
/// # Ok(())
/// # }
/// ```
pub fn get<T: IntoUrl>(url: T) -> Result<Response> {
    Client::builder().build()?.get(url).send()
}
