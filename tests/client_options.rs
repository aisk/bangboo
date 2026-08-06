//! Client-level options: https_only, http1_* tweaks, extensions.

mod support;

use std::io::Write;

use support::{read_request, respond, server};

#[test]
fn https_only_rejects_http() {
    let client = bangboo::Client::builder().https_only(true).build().unwrap();
    let err = client.get("http://example.com/").send().unwrap_err();
    assert!(err.is_builder(), "unexpected error: {err:?}");
}

#[test]
fn title_case_headers() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.contains("X-Custom-Header: 1"), "head: {head}");
        assert!(head.contains("Host: "), "head: {head}");
        assert!(head.contains("Content-Length: 4"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder()
        .http1_title_case_headers()
        .build()
        .unwrap();
    let res = client
        .post(format!("http://{addr}/"))
        .header("x-custom-header", "1")
        .body("data")
        .send()
        .unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
}

#[test]
fn max_headers_limit() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        let mut head = String::from("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n");
        for i in 0..5 {
            head.push_str(&format!("x-h{i}: v\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).unwrap();
    });

    let client = bangboo::Client::builder()
        .http1_max_headers(3)
        .build()
        .unwrap();
    let err = client.get(format!("http://{addr}/")).send().unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn spaces_after_header_name() {
    let raw = "HTTP/1.1 200 OK\r\ncontent-length : 2\r\n\r\nhi";
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
    });
    let client = bangboo::Client::builder()
        .http1_allow_spaces_after_header_name_in_responses(true)
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "hi");

    // Without the option the same response is rejected.
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
    });
    let err = bangboo::Client::new()
        .get(format!("http://{addr}/"))
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn ignore_invalid_headers() {
    let raw = "HTTP/1.1 200 OK\r\nthis is not a header\r\ncontent-length: 2\r\n\r\nhi";
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
    });
    let client = bangboo::Client::builder()
        .http1_ignore_invalid_headers_in_responses(true)
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "hi");
}

#[test]
fn obsolete_multiline_headers() {
    let raw = "HTTP/1.1 200 OK\r\nx-folded: one\r\n two\r\ncontent-length: 2\r\n\r\nhi";
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
    });
    let client = bangboo::Client::builder()
        .http1_allow_obsolete_multiline_headers_in_responses(true)
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.headers()["x-folded"], "one two");
    assert_eq!(res.text().unwrap(), "hi");

    // Without the option the folded line is an error.
    let addr = server(move |mut stream| {
        read_request(&mut stream).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
    });
    let err = bangboo::Client::new()
        .get(format!("http://{addr}/"))
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn response_extensions_are_writable() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"ok");
    });
    let mut res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert!(res.extensions().get::<u32>().is_none());
    res.extensions_mut().insert(7u32);
    assert_eq!(res.extensions().get::<u32>(), Some(&7));
}

#[test]
fn local_address_and_keepalive() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder()
        .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .tcp_keepalive(Duration::from_secs(60))
        .tcp_keepalive_interval(Duration::from_secs(10))
        .tcp_keepalive_retries(3)
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}
