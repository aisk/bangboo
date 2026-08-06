//! Shared helpers for integration tests: a minimal single-threaded HTTP
//! test server and request parsing utilities.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

/// Spawns a server handling a single connection with `handler`.
pub fn server<F>(handler: F) -> SocketAddr
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handler(stream);
    });
    addr
}

/// Spawns a server that accepts connections in a loop, calling `handler`
/// for each.
pub fn server_loop<F>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => handler(stream),
                Err(_) => break,
            }
        }
    });
    addr
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reads a full request off the stream. Returns `(head, body)`, with the
/// body already de-chunked if it was sent with chunked encoding. Returns
/// `None` on immediate EOF (client closed the connection).
pub fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        match stream.read(&mut tmp) {
            Ok(0) => {
                if buf.is_empty() {
                    return None;
                }
                panic!("connection closed mid request head");
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return None,
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let head_lower = head.to_lowercase();
    let mut body = buf[head_end + 4..].to_vec();

    if let Some(idx) = head_lower.find("content-length:") {
        let rest = &head_lower[idx + "content-length:".len()..];
        let len: usize = rest
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .expect("bad content-length in test request");
        while body.len() < len {
            let n = stream.read(&mut tmp).unwrap();
            assert!(n > 0, "connection closed mid request body");
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(len);
    } else if head_lower.contains("transfer-encoding: chunked") {
        while find(&body, b"0\r\n\r\n").is_none() {
            let n = stream.read(&mut tmp).unwrap();
            assert!(n > 0, "connection closed mid chunked body");
            body.extend_from_slice(&tmp[..n]);
        }
        body = decode_chunked(&body);
    }
    Some((head, body))
}

fn decode_chunked(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n").expect("missing chunk size line");
        let size_str = std::str::from_utf8(&raw[..line_end]).unwrap();
        let size = usize::from_str_radix(size_str.split(';').next().unwrap().trim(), 16).unwrap();
        raw = &raw[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[..size]);
        assert_eq!(&raw[size..size + 2], b"\r\n");
        raw = &raw[size + 2..];
    }
}

/// Writes a well-formed response with a `content-length` body.
pub fn respond(stream: &mut TcpStream, status: &str, extra_headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\n{extra_headers}\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}
