//! Message framing: chunked encoding, content-length handling, and
//! rejection of ambiguous (request-smuggling-prone) framing.

mod support;

use std::io::{Cursor, Write};

use support::{read_request, respond, server, server_loop};

#[test]
fn chunked_response() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
                  5\r\nhello\r\n7\r\n, world\r\n1\r\n!\r\n0\r\n\r\n",
            )
            .unwrap();
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.content_length(), None);
    assert_eq!(res.text().unwrap(), "hello, world!");
}

#[test]
fn chunked_request_body() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head.to_lowercase().contains("transfer-encoding: chunked"));
        respond(&mut stream, "200 OK", "", &body);
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/upload"))
        .body(bangboo::Body::new(Cursor::new(b"streamed data".to_vec())))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "streamed data");
}

#[test]
fn sized_reader_body_sends_content_length() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head.to_lowercase().contains("content-length: 11"));
        assert!(!head.to_lowercase().contains("transfer-encoding"));
        respond(&mut stream, "200 OK", "", &body);
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/"))
        .body(bangboo::Body::sized(Cursor::new(b"sized bytes".to_vec()), 11))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "sized bytes");
}

#[test]
fn close_delimited_body() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nold school body")
            .unwrap();
        // Closing the socket ends the body.
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "old school body");
}

#[test]
fn large_body_roundtrip() {
    let addr = server(|mut stream| {
        let (_, body) = read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", &body);
    });

    let payload: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let client = bangboo::Client::new();
    let echoed = client
        .post(format!("http://{addr}/"))
        .body(payload.clone())
        .send()
        .unwrap()
        .bytes()
        .unwrap();
    assert_eq!(echoed.as_ref(), payload.as_slice());
}

#[test]
fn user_chunked_transfer_encoding_encodes_bytes_body() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        let head = head.to_lowercase();
        assert!(head.contains("transfer-encoding: chunked"), "head: {head}");
        assert!(!head.contains("content-length"), "head: {head}");
        respond(&mut stream, "200 OK", "", &body);
    });

    // A bytes body normally goes out with Content-Length, but an explicit
    // Transfer-Encoding header must switch the framing to chunked (and
    // actually chunk-encode the bytes) instead of desyncing the connection.
    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/"))
        .header("transfer-encoding", "chunked")
        .body("chunk me")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "chunk me");
}

#[test]
fn matching_user_content_length_is_honored() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        // Exactly one content-length header must go out.
        assert_eq!(head.to_lowercase().matches("content-length").count(), 1);
        respond(&mut stream, "200 OK", "", &body);
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/"))
        .header("content-length", "4")
        .body("four")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "four");
}

#[test]
fn ambiguous_user_framing_headers_rejected() {
    // User-set framing headers that conflict with the actual body must be
    // rejected before anything hits the wire: they are request-smuggling
    // vectors. The server never needs to respond.
    let addr = server_loop(|_stream| {});
    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");

    // Content-Length that does not match the body length.
    let err = client
        .post(&url)
        .header("content-length", "3")
        .body("longer than three")
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");

    // Transfer-Encoding combined with Content-Length.
    let err = client
        .post(&url)
        .header("transfer-encoding", "chunked")
        .header("content-length", "8")
        .body("smuggle?")
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");

    // Repeated Content-Length, even with identical values.
    let err = client
        .post(&url)
        .header("content-length", "4")
        .header("content-length", "4")
        .body("four")
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn conflicting_content_length_response_rejected() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 999\r\n\r\nhello")
            .unwrap();
    });

    let err = bangboo::get(format!("http://{addr}/")).unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn malformed_chunk_size_rejected() {
    // `+5` parses under from_str_radix but is not a valid chunk-size.
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n",
            )
            .unwrap();
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    let err = res.text().unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn chunked_not_final_coding_rejected() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked, gzip\r\n\r\nwhatever")
            .unwrap();
    });

    let err = bangboo::get(format!("http://{addr}/")).unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn http_1_0_transfer_encoding_read_to_close() {
    // RFC 9112: Transfer-Encoding from an HTTP/1.0 peer has no defined
    // framing; the body must be read raw until the connection closes.
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.0 200 OK\r\ntransfer-encoding: chunked\r\n\r\nnot chunked at all")
            .unwrap();
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "not chunked at all");
}
