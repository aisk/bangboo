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

    let framing = match body.as_deref() {
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
    };

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

    if let Some(body) = body {
        match body.kind_mut() {
            BodyKindMut::Bytes(bytes) => conn.write_all(bytes)?,
            BodyKindMut::Reader {
                reader,
                len: Some(len),
            } => {
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
            BodyKindMut::Reader { reader, len: None } => {
                let mut buf = [0u8; CHUNK_BUF_SIZE];
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    conn.write_all(format!("{n:x}\r\n").as_bytes())?;
                    conn.write_all(&buf[..n])?;
                    conn.write_all(b"\r\n")?;
                }
                conn.write_all(b"0\r\n\r\n")?;
            }
        }
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
    if let Some(te) = headers.get(TRANSFER_ENCODING) {
        let te = te.to_str().map_err(|_| invalid_data("invalid Transfer-Encoding"))?;
        return if te
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            Ok(BodyLength::Chunked)
        } else {
            Ok(BodyLength::CloseDelimited)
        };
    }
    let mut content_length: Option<u64> = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let len = value
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .ok_or_else(|| invalid_data("invalid Content-Length"))?;
        // RFC 9112 §6.3: conflicting Content-Length values must be treated
        // as an error to avoid request/response desync.
        if content_length.is_some_and(|prev| prev != len) {
            return Err(invalid_data("conflicting Content-Length headers"));
        }
        content_length = Some(len);
    }
    match content_length {
        Some(len) => Ok(BodyLength::Len(len)),
        None => Ok(BodyLength::CloseDelimited),
    }
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
    let s = std::str::from_utf8(line).map_err(|_| invalid_data("malformed chunk size"))?;
    let size_part = s.split(';').next().unwrap_or("").trim();
    u64::from_str_radix(size_part, 16).map_err(|_| invalid_data("malformed chunk size"))
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
