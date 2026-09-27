use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HeaderMap};
use http::{StatusCode, Version};
use serde::de::DeserializeOwned;
use url::Url;

use crate::connect::Conn;
use crate::decoder::Decoder;
use crate::pool::{Pool, PoolKey};
use crate::proto::{self, BodyLength};

/// A Response to a submitted `Request`.
///
/// The response body is read lazily from the connection: `Response`
/// implements `std::io::Read`, and the convenience methods
/// ([`text()`][Response::text], [`bytes()`][Response::bytes],
/// [`json()`][Response::json]) consume the response and read it fully.
pub struct Response {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    url: Url,
    remote_addr: Option<SocketAddr>,
    extensions: http::Extensions,
    body: Decoder,
}

impl Response {
    pub(crate) fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        url: Url,
        remote_addr: Option<SocketAddr>,
        body: Decoder,
    ) -> Response {
        Response {
            status,
            version,
            headers,
            url,
            remote_addr,
            extensions: http::Extensions::new(),
            body,
        }
    }

    /// Get the `StatusCode` of this `Response`.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the `Headers` of this `Response`.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a mutable reference to the `Headers` of this `Response`.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Get the HTTP `Version` of this `Response`.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get the final `Url` of this `Response`.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get the remote address used to get this `Response`.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Retrieve the cookies contained in the response.
    ///
    /// Note that invalid `Set-Cookie` headers are silently ignored.
    #[cfg(feature = "cookies")]
    pub fn cookies(&self) -> impl Iterator<Item = crate::cookie::Cookie<'_>> {
        crate::cookie::extract_response_cookies(&self.headers).filter_map(Result::ok)
    }

    /// Returns a reference to the associated extensions.
    pub fn extensions(&self) -> &http::Extensions {
        &self.extensions
    }

    /// Returns a mutable reference to the associated extensions.
    pub fn extensions_mut(&mut self) -> &mut http::Extensions {
        &mut self.extensions
    }

    /// Get the content-length of the response, if it is known.
    ///
    /// Reasons it may not be known:
    ///
    /// - The server didn't send a `content-length` header.
    /// - The response is chunked-encoded.
    /// - The body is being transparently decompressed.
    pub fn content_length(&self) -> Option<u64> {
        if self.body.is_decoding() {
            return None;
        }
        self.headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
    }

    /// Try to deserialize the response body as JSON.
    pub fn json<T: DeserializeOwned>(self) -> crate::Result<T> {
        let url = self.url.clone();
        let bytes = self.bytes()?;
        serde_json::from_slice(&bytes).map_err(|e| crate::error::decode(e).with_url(url))
    }

    /// Get the full response body as `Bytes`.
    pub fn bytes(mut self) -> crate::Result<Bytes> {
        let capacity = self
            .content_length()
            .map(|len| len.min(4 * 1024 * 1024) as usize)
            .unwrap_or(8 * 1024);
        let mut buf = Vec::with_capacity(capacity);
        let url = self.url.clone();
        self.read_to_end(&mut buf)
            .map_err(|e| crate::error::from_io(e).with_url(url))?;
        Ok(buf.into())
    }

    /// Get the response text.
    ///
    /// With the `charset` feature (on by default) the encoding is taken
    /// from the `charset` parameter of the `Content-Type` header, defaulting
    /// to UTF-8. Malformed sequences are replaced with `U+FFFD`.
    pub fn text(self) -> crate::Result<String> {
        #[cfg(feature = "charset")]
        {
            self.text_with_charset("utf-8")
        }
        #[cfg(not(feature = "charset"))]
        {
            let bytes = self.bytes()?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    /// Get the response text given a specific encoding.
    ///
    /// The encoding is taken from the `charset` parameter of the
    /// `Content-Type` header; `default_encoding` is used when the header is
    /// absent, has no charset, or names an encoding that is not known.
    /// Malformed sequences are replaced with `U+FFFD`.
    #[cfg(feature = "charset")]
    pub fn text_with_charset(self, default_encoding: &str) -> crate::Result<String> {
        let content_type = self
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<mime::Mime>().ok());
        let header_charset = content_type.as_ref().and_then(|mime| {
            mime.get_param("charset")
                .map(|charset| charset.as_str().to_owned())
        });
        // An unrecognized charset falls through to the caller's default,
        // and only then to UTF-8.
        let encoding = header_charset
            .as_deref()
            .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
            .or_else(|| encoding_rs::Encoding::for_label(default_encoding.as_bytes()))
            .unwrap_or(encoding_rs::UTF_8);

        let bytes = self.bytes()?;
        let (text, _, _) = encoding.decode(&bytes);
        Ok(text.into_owned())
    }

    /// Copy the response body into a writer.
    ///
    /// Returns the number of bytes copied.
    pub fn copy_to<W>(&mut self, w: &mut W) -> crate::Result<u64>
    where
        W: Write + ?Sized,
    {
        let url = self.url.clone();
        io::copy(self, w).map_err(|e| crate::error::from_io(e).with_url(url))
    }

    /// Turn a response into an error if the server returned an error.
    pub fn error_for_status(self) -> crate::Result<Self> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(crate::error::status_code(self.url.clone(), status))
        } else {
            Ok(self)
        }
    }

    /// Turn a reference to a response into an error if the server returned
    /// an error.
    pub fn error_for_status_ref(&self) -> crate::Result<&Self> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(crate::error::status_code(self.url.clone(), status))
        } else {
            Ok(self)
        }
    }
}

impl<T: Into<bytes::Bytes>> From<http::Response<T>> for Response {
    fn from(response: http::Response<T>) -> Response {
        let (parts, body) = response.into_parts();
        let http::response::Parts {
            status,
            version,
            headers,
            extensions,
            ..
        } = parts;
        // A synthesized response has no connection behind it; the body is
        // served straight from memory.
        let url = Url::parse("http://no.url.provided.local").expect("valid url");
        Response {
            status,
            version,
            headers,
            url,
            remote_addr: None,
            extensions,
            body: Decoder::in_memory(body.into()),
        }
    }
}

impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("url", &self.url.as_str())
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish()
    }
}

const MAX_TRAILERS: usize = 128;

enum ChunkPhase {
    Size,
    Data(u64),
    DataEnd,
    Trailers,
}

enum State {
    Len(u64),
    Chunked(ChunkPhase),
    Close,
    Done,
}

/// Streams the response body off a `Conn`, and returns the connection to the
/// pool once the body has been fully consumed (when keep-alive permits).
pub(crate) struct BodyReader {
    conn: Option<Conn>,
    state: State,
    reuse: Option<(Arc<Pool>, PoolKey)>,
    deadline: Option<Instant>,
}

impl BodyReader {
    pub(crate) fn new(
        conn: Conn,
        length: BodyLength,
        reuse: Option<(Arc<Pool>, PoolKey)>,
        deadline: Option<Instant>,
    ) -> BodyReader {
        let state = match length {
            BodyLength::Empty => State::Len(0),
            BodyLength::Len(n) => State::Len(n),
            BodyLength::Chunked => State::Chunked(ChunkPhase::Size),
            BodyLength::CloseDelimited => State::Close,
        };
        let mut reader = BodyReader {
            conn: Some(conn),
            state,
            reuse,
            deadline,
        };
        // An empty body needs no reads: return the connection to the pool
        // right away instead of waiting for a read that may never come.
        if matches!(reader.state, State::Len(0)) {
            reader.finish();
        }
        reader
    }

    /// Body fully consumed: return the connection to the pool if allowed.
    fn finish(&mut self) {
        self.state = State::Done;
        if let (Some(mut conn), Some((pool, key))) = (self.conn.take(), self.reuse.take()) {
            // Clear per-request socket timeouts before pooling.
            if conn.set_deadline(None).is_ok() {
                pool.checkin(key, conn);
            }
        }
        self.conn = None;
        self.reuse = None;
    }

    /// Read error or premature EOF: the connection is poisoned, drop it.
    fn poison(&mut self) {
        self.state = State::Done;
        self.conn = None;
        self.reuse = None;
    }

    fn apply_deadline(&mut self) -> io::Result<()> {
        if let (Some(conn), Some(deadline)) = (self.conn.as_mut(), self.deadline) {
            conn.refresh_deadline(deadline)?;
        }
        Ok(())
    }

    /// Read and discard the rest of the body, so the connection can go back
    /// to the pool. Gives up (dropping the connection) past `max` bytes.
    pub(crate) fn drain(mut self, max: u64) {
        let mut buf = [0u8; 8 * 1024];
        let mut total = 0u64;
        loop {
            match self.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    total += n as u64;
                    if total > max {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        // If the whole remaining body already sits in the connection's read
        // buffer (common for small responses whose body arrived with the
        // head), consume it so the connection can still go back to the pool.
        // No reads from the socket are performed, so Drop can never block.
        if self.reuse.is_none() {
            return;
        }
        if let (State::Len(remaining), Some(conn)) = (&self.state, self.conn.as_mut())
            && *remaining <= conn.buffered() as u64
        {
            let remaining = *remaining as usize;
            conn.consume_buffered(remaining);
            self.finish();
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            self.apply_deadline()?;
            match &mut self.state {
                State::Done => return Ok(0),
                State::Len(0) => {
                    self.finish();
                    return Ok(0);
                }
                State::Len(remaining) => {
                    let conn = self.conn.as_mut().expect("Len state without conn");
                    let max = (*remaining).min(out.len() as u64) as usize;
                    match conn.read(&mut out[..max]) {
                        Ok(0) => {
                            self.poison();
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed before body was complete",
                            ));
                        }
                        Ok(n) => {
                            *remaining -= n as u64;
                            if *remaining == 0 {
                                self.finish();
                            }
                            return Ok(n);
                        }
                        Err(e) => {
                            self.poison();
                            return Err(e);
                        }
                    }
                }
                State::Chunked(phase) => {
                    let conn = self.conn.as_mut().expect("Chunked state without conn");
                    match phase {
                        ChunkPhase::Size => {
                            let line = match conn.read_line() {
                                Ok(line) => line,
                                Err(e) => {
                                    self.poison();
                                    return Err(e);
                                }
                            };
                            match proto::parse_chunk_size(&line) {
                                Ok(0) => *phase = ChunkPhase::Trailers,
                                Ok(size) => *phase = ChunkPhase::Data(size),
                                Err(e) => {
                                    self.poison();
                                    return Err(e);
                                }
                            }
                        }
                        ChunkPhase::Data(remaining) => {
                            let max = (*remaining).min(out.len() as u64) as usize;
                            match conn.read(&mut out[..max]) {
                                Ok(0) => {
                                    self.poison();
                                    return Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed mid-chunk",
                                    ));
                                }
                                Ok(n) => {
                                    *remaining -= n as u64;
                                    if *remaining == 0 {
                                        *phase = ChunkPhase::DataEnd;
                                    }
                                    return Ok(n);
                                }
                                Err(e) => {
                                    self.poison();
                                    return Err(e);
                                }
                            }
                        }
                        ChunkPhase::DataEnd => {
                            // Consume the CRLF that terminates the chunk data.
                            match conn.read_line() {
                                Ok(line) if line.is_empty() => *phase = ChunkPhase::Size,
                                Ok(_) => {
                                    self.poison();
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "missing CRLF after chunk data",
                                    ));
                                }
                                Err(e) => {
                                    self.poison();
                                    return Err(e);
                                }
                            }
                        }
                        ChunkPhase::Trailers => {
                            let mut count = 0usize;
                            loop {
                                match conn.read_line() {
                                    Ok(line) if line.is_empty() => {
                                        self.finish();
                                        return Ok(0);
                                    }
                                    Ok(_) => {
                                        count += 1;
                                        if count > MAX_TRAILERS {
                                            self.poison();
                                            return Err(io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                "too many chunked trailers",
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        self.poison();
                                        return Err(e);
                                    }
                                }
                            }
                        }
                    }
                }
                State::Close => {
                    let conn = self.conn.as_mut().expect("Close state without conn");
                    match conn.read(out) {
                        Ok(0) => {
                            self.poison();
                            return Ok(0);
                        }
                        Ok(n) => return Ok(n),
                        Err(e) => {
                            self.poison();
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}
