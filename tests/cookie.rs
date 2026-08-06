//! Cookie storage and the `Set-Cookie` / `Cookie` round trip.
#![cfg(feature = "cookies")]

mod support;

use std::sync::Arc;

use support::{read_request, respond, server};

#[test]
fn cookie_store_round_trip() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(!head.to_lowercase().contains("cookie:"), "head: {head}");
        respond(
            &mut stream,
            "200 OK",
            "set-cookie: id=42; Path=/\r\n",
            b"set",
        );

        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            head.to_lowercase().contains("cookie: id=42"),
            "head: {head}"
        );
        respond(&mut stream, "200 OK", "", b"sent");
    });

    let client = bangboo::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let url = format!("http://{addr}/");
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "set");
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "sent");
}

#[test]
fn no_cookie_store_by_default() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "set-cookie: id=42\r\n", b"one");
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(!head.to_lowercase().contains("cookie:"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"two");
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    client.get(&url).send().unwrap().text().unwrap();
    client.get(&url).send().unwrap().text().unwrap();
}

#[test]
fn response_cookies_are_readable() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(
            &mut stream,
            "200 OK",
            "set-cookie: a=1; HttpOnly; Secure; Path=/x; Max-Age=60\r\nset-cookie: b=2\r\n",
            b"ok",
        );
    });

    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    let cookies: Vec<_> = res.cookies().collect();
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0].name(), "a");
    assert_eq!(cookies[0].value(), "1");
    assert!(cookies[0].http_only());
    assert!(cookies[0].secure());
    assert_eq!(cookies[0].path(), Some("/x"));
    assert_eq!(
        cookies[0].max_age(),
        Some(std::time::Duration::from_secs(60))
    );
    assert_eq!(cookies[1].name(), "b");
    assert!(!cookies[1].http_only());
}

#[test]
fn custom_cookie_provider() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            head.to_lowercase().contains("cookie: seed=1"),
            "head: {head}"
        );
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let jar = Arc::new(bangboo::cookie::Jar::default());
    let url = format!("http://{addr}/");
    jar.add_cookie_str("seed=1", &url.parse().unwrap());

    let client = bangboo::Client::builder()
        .cookie_provider(jar)
        .build()
        .unwrap();
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "ok");
}

#[test]
fn cookies_are_recomputed_across_redirects() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET /a"), "head: {head}");
        respond(
            &mut stream,
            "302 Found",
            "location: /b\r\nset-cookie: hop=1; Path=/\r\n",
            b"",
        );
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET /b"), "head: {head}");
        // The cookie set by the 302 is sent on the very next hop.
        assert!(
            head.to_lowercase().contains("cookie: hop=1"),
            "head: {head}"
        );
        respond(&mut stream, "200 OK", "", b"done");
    });

    let client = bangboo::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/a")).send().unwrap();
    assert_eq!(res.text().unwrap(), "done");
}

#[test]
fn explicit_cookie_header_is_kept() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        let lower = head.to_lowercase();
        assert!(lower.contains("cookie: manual=1"), "head: {head}");
        assert!(!lower.contains("stored"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let jar = Arc::new(bangboo::cookie::Jar::default());
    let url = format!("http://{addr}/");
    jar.add_cookie_str("stored=1", &url.parse().unwrap());
    let client = bangboo::Client::builder()
        .cookie_provider(jar)
        .build()
        .unwrap();
    let res = client
        .get(&url)
        .header("cookie", "manual=1")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}
