//! HTTP/1.1 wire protocol: writing requests and parsing responses.

use std::io::{self, Read};

use http::header::{
    CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING,
};
use http::{Method, StatusCode, Version};
use url::Url;

use crate::body::{Body, BodyKindMut};
use crate::connect::Conn;

const MAX_HEADERS: usize = 128;
const MAX_INFORMATIONAL: usize = 10;
const CHUNK_BUF_SIZE: usize = 8 * 1024;

pub(crate) struct Head {
    pub(crate) version: Version,
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
}

pub(crate) fn write_request(
    conn: &mut Conn,
    method: &Method,
    url: &Url,
    version: Version,
    headers: &HeaderMap,
    body: Option<&mut Body>,
) -> io::Result<()> {
    enum Framing {
        NoBody,
        Len(u64),
        Chunked,
    }

    // Framing must stay consistent with any Transfer-Encoding /
    // Content-Length headers the caller set themselves: sending a framing
    // that disagrees with those headers desyncs the connection (request
    // smuggling territory), so conflicts are rejected up front.
    let user_te = transfer_encoding_tokens(headers)?;
    let user_len = content_length_value(headers)?;
    if user_te.is_some() && user_len.is_some() {
        return Err(invalid_input(
            "request has both Transfer-Encoding and Content-Length headers",
        ));
    }
    // Even identical repeats would be echoed as multiple header lines,
    // which RFC 9110 §8.6 forbids generating.
    if headers.get_all(CONTENT_LENGTH).iter().count() > 1 {
        return Err(invalid_input("request has repeated Content-Length headers"));
    }

    let framing = if let Some(tokens) = user_te {
        // Codings before the final "chunked" (e.g. `gzip, chunked`) are the
        // caller's responsibility: the body must already be encoded with
        // them; only the chunked framing is applied here.
        if tokens.last().map(String::as_str) != Some("chunked")
            || tokens.iter().filter(|t| *t == "chunked").count() != 1
        {
            return Err(invalid_input(
                "request Transfer-Encoding must end with a single chunked coding",
            ));
        }
        Framing::Chunked
    } else if let Some(user_len) = user_len {
        match body.as_deref() {
            None if user_len != 0 => {
                return Err(invalid_input(
                    "Content-Length header is set but the request has no body",
                ));
            }
            None => Framing::Len(0),
            Some(b) => match b.len() {
                Some(len) if len != user_len => {
                    return Err(invalid_input(
                        "Content-Length header does not match the body length",
                    ));
                }
                // For a streaming body of unknown length, the header's value
                // is trusted as the declared length.
                _ => Framing::Len(user_len),
            },
        }
    } else {
        match body.as_deref() {
            None => {
                // Methods that conventionally carry a body get an explicit
                // `Content-Length: 0` so servers don't respond 411.
                if matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
                    Framing::Len(0)
                } else {
                    Framing::NoBody
                }
            }
            Some(b) => match b.len() {
                Some(len) => Framing::Len(len),
                None => Framing::Chunked,
            },
        }
    };

    if version == Version::HTTP_10 && matches!(framing, Framing::Chunked) {
        return Err(invalid_input(
            "chunked Transfer-Encoding cannot be used with HTTP/1.0",
        ));
    }

    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(method.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(url.path().as_bytes());
    if let Some(query) = url.query() {
        head.push(b'?');
        head.extend_from_slice(query.as_bytes());
    }
    if version == Version::HTTP_10 {
        head.extend_from_slice(b" HTTP/1.0\r\n");
    } else {
        head.extend_from_slice(b" HTTP/1.1\r\n");
    }

    if !headers.contains_key(HOST) {
        head.extend_from_slice(b"host: ");
        head.extend_from_slice(host_header(url).as_bytes());
        head.extend_from_slice(b"\r\n");
    }

    match framing {
        Framing::NoBody => {}
        Framing::Len(len) => {
            if !headers.contains_key(CONTENT_LENGTH) {
                head.extend_from_slice(format!("content-length: {len}\r\n").as_bytes());
            }
        }
        Framing::Chunked => {
            if !headers.contains_key(TRANSFER_ENCODING) {
                head.extend_from_slice(b"transfer-encoding: chunked\r\n");
            }
        }
    }

    for (name, value) in headers.iter() {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    conn.write_all(&head)?;

    // The body is written according to the negotiated framing, not the body
    // kind: a bytes body must be chunk-encoded when the framing is chunked.
    match framing {
        Framing::NoBody => {}
        Framing::Len(len) => {
            if let Some(body) = body {
                match body.kind_mut() {
                    BodyKindMut::Bytes(bytes) => conn.write_all(bytes)?,
                    BodyKindMut::Reader(reader) => {
                        let mut taken = reader.take(len);
                        let mut buf = [0u8; CHUNK_BUF_SIZE];
                        let mut copied = 0u64;
                        loop {
                            let n = taken.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            conn.write_all(&buf[..n])?;
                            copied += n as u64;
                        }
                        if copied < len {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "request body was shorter than its declared Content-Length",
                            ));
                        }
                    }
                }
            }
        }
        Framing::Chunked => match body.map(|b| b.kind_mut()) {
            Some(BodyKindMut::Bytes(bytes)) => {
                let mut frame = Vec::with_capacity(bytes.len() + 32);
                if !bytes.is_empty() {
                    frame.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
                    frame.extend_from_slice(bytes);
                    frame.extend_from_slice(b"\r\n");
                }
                frame.extend_from_slice(b"0\r\n\r\n");
                conn.write_all(&frame)?;
            }
            Some(BodyKindMut::Reader(reader)) => {
                let mut buf = [0u8; CHUNK_BUF_SIZE];
                // Each chunk (size line + data + CRLF) is assembled into one
                // buffer so it goes out as a single write.
                let mut frame = Vec::with_capacity(CHUNK_BUF_SIZE + 32);
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    frame.clear();
                    frame.extend_from_slice(format!("{n:x}\r\n").as_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    frame.extend_from_slice(b"\r\n");
                    conn.write_all(&frame)?;
                }
                conn.write_all(b"0\r\n\r\n")?;
            }
            None => conn.write_all(b"0\r\n\r\n")?,
        },
    }

    conn.flush()
}

pub(crate) fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match (url.port(), url.scheme()) {
        (Some(port), _) => format!("{host}:{port}"),
        (None, _) => host.to_string(),
    }
}

/// Reads a response head, skipping any informational (1xx) responses.
pub(crate) fn read_head(conn: &mut Conn) -> io::Result<Head> {
    let mut informational = 0usize;
    loop {
        let line = conn.read_line()?;
        let (version, status) = parse_status_line(&line)?;

        let mut headers = HeaderMap::new();
        let mut count = 0usize;
        loop {
            let line = conn.read_line()?;
            if line.is_empty() {
                break;
            }
            count += 1;
            if count > MAX_HEADERS {
                return Err(invalid_data("too many response headers"));
            }
            let colon = line
                .iter()
                .position(|&b| b == b':')
                .ok_or_else(|| invalid_data("malformed header line"))?;
            let name = HeaderName::from_bytes(&line[..colon])
                .map_err(|_| invalid_data("invalid header name"))?;
            let mut value = &line[colon + 1..];
            while let [b' ' | b'\t', rest @ ..] = value {
                value = rest;
            }
            while let [rest @ .., b' ' | b'\t'] = value {
                value = rest;
            }
            let value = HeaderValue::from_bytes(value)
                .map_err(|_| invalid_data("invalid header value"))?;
            headers.append(name, value);
        }

        // 1xx responses (e.g. 100 Continue) are interim: keep reading.
        if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
            informational += 1;
            if informational > MAX_INFORMATIONAL {
                return Err(invalid_data("too many informational (1xx) responses"));
            }
            continue;
        }
        return Ok(Head {
            version,
            status,
            headers,
        });
    }
}

fn parse_status_line(line: &[u8]) -> io::Result<(Version, StatusCode)> {
    let s = std::str::from_utf8(line).map_err(|_| invalid_data("malformed status line"))?;
    let mut parts = s.splitn(3, ' ');
    let version = match parts.next() {
        Some("HTTP/1.1") => Version::HTTP_11,
        Some("HTTP/1.0") => Version::HTTP_10,
        _ => return Err(invalid_data("unsupported or malformed HTTP version")),
    };
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or_else(|| invalid_data("invalid status code"))?;
    Ok((version, status))
}

/// How the response body is delimited on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyLength {
    Empty,
    Len(u64),
    Chunked,
    CloseDelimited,
}

pub(crate) fn body_length(
    method: &Method,
    status: StatusCode,
    version: Version,
    headers: &HeaderMap,
) -> io::Result<BodyLength> {
    // After 101 the connection speaks another protocol; treating the body
    // as close-delimited keeps the socket out of the keep-alive pool.
    if status == StatusCode::SWITCHING_PROTOCOLS {
        return Ok(BodyLength::CloseDelimited);
    }
    if *method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Ok(BodyLength::Empty);
    }
    if let Some(tokens) = transfer_encoding_tokens(headers)? {
        // RFC 9112 §6.1: Transfer-Encoding from an HTTP/1.0 peer has no
        // defined framing; read until close and don't reuse the connection.
        if version == Version::HTTP_10 {
            return Ok(BodyLength::CloseDelimited);
        }
        return match tokens.last().map(String::as_str) {
            Some("chunked") => Ok(BodyLength::Chunked),
            // chunked anywhere but last leaves the message without a
            // determinable end; treating it as anything else risks desync.
            _ if tokens.iter().any(|t| t == "chunked") => {
                Err(invalid_data("chunked must be the final transfer coding"))
            }
            _ => Ok(BodyLength::CloseDelimited),
        };
    }
    match content_length_value(headers)? {
        Some(len) => Ok(BodyLength::Len(len)),
        None => Ok(BodyLength::CloseDelimited),
    }
}

/// Collects the transfer-coding tokens from all `Transfer-Encoding` values,
/// lowercased and in order. Returns `None` if the header is absent.
fn transfer_encoding_tokens(headers: &HeaderMap) -> io::Result<Option<Vec<String>>> {
    if !headers.contains_key(TRANSFER_ENCODING) {
        return Ok(None);
    }
    let mut tokens = Vec::new();
    for value in headers.get_all(TRANSFER_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| invalid_data("invalid Transfer-Encoding"))?;
        for part in value.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                tokens.push(part.to_ascii_lowercase());
            }
        }
    }
    Ok(Some(tokens))
}

/// Parses the `Content-Length` header(s), treating conflicting values as an
/// error (RFC 9112 §6.3, avoids request/response desync).
fn content_length_value(headers: &HeaderMap) -> io::Result<Option<u64>> {
    let mut content_length: Option<u64> = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let len = value
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .ok_or_else(|| invalid_data("invalid Content-Length"))?;
        if content_length.is_some_and(|prev| prev != len) {
            return Err(invalid_data("conflicting Content-Length headers"));
        }
        content_length = Some(len);
    }
    Ok(content_length)
}

/// Whether the connection may be reused for another request after this
/// response, based on version and `Connection` headers.
pub(crate) fn can_keep_alive(version: Version, headers: &HeaderMap) -> bool {
    let mut close = false;
    let mut keep_alive = false;
    for value in headers.get_all(CONNECTION) {
        if let Ok(value) = value.to_str() {
            for part in value.split(',') {
                let part = part.trim();
                if part.eq_ignore_ascii_case("close") {
                    close = true;
                } else if part.eq_ignore_ascii_case("keep-alive") {
                    keep_alive = true;
                }
            }
        }
    }
    match version {
        Version::HTTP_11 => !close,
        Version::HTTP_10 => keep_alive && !close,
        _ => false,
    }
}

pub(crate) fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    // chunk-size = 1*HEXDIG, optionally followed by BWS and a ";ext"
    // chunk extension. Notably no sign, radix prefix, or leading whitespace.
    let digits_end = line
        .iter()
        .position(|b| !b.is_ascii_hexdigit())
        .unwrap_or(line.len());
    if digits_end == 0 {
        return Err(invalid_data("malformed chunk size"));
    }
    let mut rest = &line[digits_end..];
    while let [b' ' | b'\t', more @ ..] = rest {
        rest = more;
    }
    if !(rest.is_empty() || rest[0] == b';') {
        return Err(invalid_data("malformed chunk size"));
    }
    let mut size = 0u64;
    for &b in &line[..digits_end] {
        let digit = (b as char).to_digit(16).expect("checked hexdigit") as u64;
        size = size
            .checked_mul(16)
            .and_then(|s| s.checked_add(digit))
            .ok_or_else(|| invalid_data("chunk size too large"))?;
    }
    Ok(size)
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
