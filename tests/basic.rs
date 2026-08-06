//! Basic request/response round-trips: methods, status handling, and the
//! `Read` interface of `Response`.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use support::{read_request, respond, server};

#[test]
fn get_text() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET /hello?x=1 HTTP/1.1\r\n"));
        assert!(head.to_lowercase().contains(&format!("host: {}", stream.local_addr().unwrap())));
        respond(&mut stream, "200 OK", "x-test: yes\r\n", b"hello world");
    });

    let url = format!("http://{addr}/hello?x=1");
    let res = bangboo::get(&url).unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
    assert_eq!(res.version(), bangboo::Version::HTTP_11);
    assert_eq!(res.headers()["x-test"], "yes");
    assert_eq!(res.content_length(), Some(11));
    assert_eq!(res.remote_addr(), Some(addr));
    assert_eq!(res.url().as_str(), url);
    assert_eq!(res.text().unwrap(), "hello world");
}

#[test]
fn post_body_echo() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("POST /echo HTTP/1.1\r\n"));
        assert!(head.to_lowercase().contains("content-length: 9"));
        respond(&mut stream, "200 OK", "", &body);
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/echo"))
        .body("ping pong")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "ping pong");
}

#[test]
fn head_request_has_no_body() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("HEAD / HTTP/1.1"));
        // content-length describes the body a GET would have returned.
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n")
            .unwrap();
    });

    let client = bangboo::Client::new();
    let res = client.head(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.content_length(), Some(100));
    assert_eq!(res.bytes().unwrap().len(), 0);
}

#[test]
fn response_implements_read() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"stream me");
    });

    let mut res = bangboo::get(format!("http://{addr}/")).unwrap();
    let mut out = Vec::new();
    res.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"stream me");
}

#[test]
fn error_for_status() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "500 Internal Server Error", "", b"boom");
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    let err = res.error_for_status().unwrap_err();
    assert!(err.is_status());
    assert_eq!(
        err.status(),
        Some(bangboo::StatusCode::INTERNAL_SERVER_ERROR)
    );
}

#[test]
fn no_content_204() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .unwrap();
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::NO_CONTENT);
    assert_eq!(res.bytes().unwrap().len(), 0);
}

#[test]
fn interim_100_continue_is_skipped() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .unwrap();
        respond(&mut stream, "200 OK", "", b"final answer");
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
    assert_eq!(res.text().unwrap(), "final answer");
}

#[test]
fn ipv6_literal_host() {
    // Skip silently on environments without IPv6 loopback.
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(_) => return,
    };
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"v6");
    });

    let res = bangboo::get(format!("http://[::1]:{}/", addr.port())).unwrap();
    assert_eq!(res.text().unwrap(), "v6");
}

#[cfg(feature = "charset")]
#[test]
fn text_uses_content_type_charset() {
    // "héllo" in ISO-8859-1.
    let body = b"h\xe9llo";
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        respond(
            &mut stream,
            "200 OK",
            "content-type: text/plain; charset=iso-8859-1\r\n",
            body,
        );
    });
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "héllo");
}

#[cfg(feature = "charset")]
#[test]
fn text_with_charset_default_and_override() {
    let body = b"h\xe9llo";
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "content-type: text/plain\r\n", body);
    });
    // No charset in the header, so the supplied default applies.
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text_with_charset("iso-8859-1").unwrap(), "héllo");

    // An unknown charset in the header falls through to the caller's
    // default before UTF-8.
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        respond(
            &mut stream,
            "200 OK",
            "content-type: text/plain; charset=x-bogus\r\n",
            body,
        );
    });
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text_with_charset("iso-8859-1").unwrap(), "héllo");

    // An unknown charset falls back to UTF-8 (lossy).
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        respond(
            &mut stream,
            "200 OK",
            "content-type: text/plain; charset=not-a-charset\r\n",
            body,
        );
    });
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "h\u{fffd}llo");
}
