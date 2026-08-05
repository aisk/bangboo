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
//! ## Scope
//!
//! bangboo intentionally implements only HTTP/1.1 (and 1.0). Features of
//! reqwest that are tied to its async internals or to HTTP/2+ (`http2_*`,
//! `http3_*`, connector layers, etc.) are omitted. Currently not
//! implemented: proxies, cookies, automatic decompression, and multipart.

mod body;
mod client;
mod connect;
mod error;
mod into_url;
mod pool;
mod proto;
pub mod redirect;
mod request;
mod response;

pub use self::body::Body;
pub use self::client::{Client, ClientBuilder};
pub use self::error::{Error, Result};
pub use self::into_url::IntoUrl;
pub use self::request::{Request, RequestBuilder};
pub use self::response::Response;

// Re-exports of common types used in the API, mirroring reqwest.
pub use http::header;
pub use http::Method;
pub use http::StatusCode;
pub use http::Version;
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
