//! Proxy support: HTTP forward proxies, SOCKS, and NO_PROXY rules.

mod support;

use std::io::{Read, Write};

use support::{read_request, respond, server};

#[test]
fn http_proxy_absolute_form() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            head.starts_with("GET http://example.invalid/path?q=1 HTTP/1.1"),
            "head: {head}"
        );
        assert!(head.contains("host: example.invalid"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"proxied");
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::http(format!("http://{addr}")).unwrap())
        .build()
        .unwrap();
    let res = client
        .get("http://example.invalid/path?q=1")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "proxied");
}

#[test]
fn http_proxy_sends_auth_and_headers() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        let lower = head.to_lowercase();
        assert!(
            lower.contains("proxy-authorization: basic "),
            "head: {head}"
        );
        assert!(lower.contains("x-proxy-extra: yes"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let mut extra = bangboo::header::HeaderMap::new();
    extra.insert("x-proxy-extra", "yes".parse().unwrap());
    let client = bangboo::Client::builder()
        .proxy(
            bangboo::Proxy::http(format!("http://{addr}"))
                .unwrap()
                .basic_auth("user", "pass")
                .headers(extra),
        )
        .build()
        .unwrap();
    let res = client.get("http://example.invalid/").send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
}

#[test]
fn http_proxy_connection_reused_across_hosts() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET http://one.invalid/"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"one");
        // Second request to a *different* host arrives on the same
        // forwarding connection.
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET http://two.invalid/"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"two");
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::all(format!("http://{addr}")).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .get("http://one.invalid/")
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "one"
    );
    assert_eq!(
        client
            .get("http://two.invalid/")
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "two"
    );
}

#[test]
fn proxy_refusing_connect_tunnel_errors() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            head.starts_with("CONNECT secure.invalid:443 HTTP/1.1"),
            "head: {head}"
        );
        respond(&mut stream, "407 Proxy Authentication Required", "", b"");
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::https(format!("http://{addr}")).unwrap())
        .build()
        .unwrap();
    let err = client.get("https://secure.invalid/").send().unwrap_err();
    assert!(err.is_connect(), "unexpected error: {err:?}");
}

#[test]
fn no_proxy_excludes_host() {
    // The proxy target does not exist; if the proxy were used the request
    // would fail. no_proxy sends the request directly instead.
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET / HTTP/1.1"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"direct");
    });

    let client = bangboo::Client::builder()
        .proxy(
            bangboo::Proxy::all("http://proxy.invalid:1")
                .unwrap()
                .no_proxy(bangboo::NoProxy::from_string("127.0.0.1,localhost")),
        )
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "direct");
}

#[test]
fn socks5_proxy() {
    let addr = server(|mut stream| {
        // SOCKS5 greeting: no-auth.
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..2], &[0x05, 0x01]);
        stream.write_all(&[0x05, 0x00]).unwrap();
        // CONNECT request with a domain target (socks5h).
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(&head[..4], &[0x05, 0x01, 0x00, 0x03]);
        let mut rest = vec![0u8; head[4] as usize + 2];
        stream.read_exact(&mut rest).unwrap();
        let domain = String::from_utf8_lossy(&rest[..head[4] as usize]).into_owned();
        assert_eq!(domain, "sock.invalid");
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        // Then plain HTTP over the tunnel.
        let (req, _) = read_request(&mut stream).unwrap();
        assert!(req.starts_with("GET / HTTP/1.1"), "head: {req}");
        respond(&mut stream, "200 OK", "", b"socksed");
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::all(format!("socks5h://{addr}")).unwrap())
        .build()
        .unwrap();
    let res = client.get("http://sock.invalid/").send().unwrap();
    assert_eq!(res.text().unwrap(), "socksed");
}

#[test]
fn socks5_auth() {
    let addr = server(|mut stream| {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x05, 0x02, 0x00, 0x02]);
        // Pick username/password auth.
        stream.write_all(&[0x05, 0x02]).unwrap();
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 0x01);
        let mut user = vec![0u8; head[1] as usize];
        stream.read_exact(&mut user).unwrap();
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut pass).unwrap();
        assert_eq!(user, b"u");
        assert_eq!(pass, b"p");
        stream.write_all(&[0x01, 0x00]).unwrap();
        // CONNECT.
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).unwrap();
        let mut rest = vec![0u8; head[4] as usize + 2];
        stream.read_exact(&mut rest).unwrap();
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let (req, _) = read_request(&mut stream).unwrap();
        assert!(req.starts_with("GET /"), "head: {req}");
        respond(&mut stream, "200 OK", "", b"authed");
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::all(format!("socks5h://u:p@{addr}")).unwrap())
        .build()
        .unwrap();
    let res = client.get("http://sock.invalid/").send().unwrap();
    assert_eq!(res.text().unwrap(), "authed");
}

#[test]
fn custom_proxy_selects_per_url() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            head.starts_with("GET http://picked.invalid/"),
            "head: {head}"
        );
        respond(&mut stream, "200 OK", "", b"custom");
    });

    let proxy_url = bangboo::Url::parse(&format!("http://{addr}")).unwrap();
    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::custom(move |url| {
            if url.host_str() == Some("picked.invalid") {
                Some(proxy_url.clone())
            } else {
                None
            }
        }))
        .build()
        .unwrap();
    let res = client.get("http://picked.invalid/").send().unwrap();
    assert_eq!(res.text().unwrap(), "custom");
}

#[test]
fn proxy_headers_replace_rather_than_duplicate() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        let lower = head.to_lowercase();
        assert_eq!(
            lower.matches("user-agent:").count(),
            1,
            "duplicate user-agent: {head}"
        );
        assert!(lower.contains("user-agent: proxy-agent"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let mut extra = bangboo::header::HeaderMap::new();
    extra.insert("user-agent", "proxy-agent".parse().unwrap());
    let client = bangboo::Client::builder()
        .user_agent("app/1.0")
        .proxy(
            bangboo::Proxy::all(format!("http://{addr}"))
                .unwrap()
                .headers(extra),
        )
        .build()
        .unwrap();
    let res = client.get("http://example.invalid/").send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
}

#[test]
fn socks4_sends_user_id() {
    let addr = server(|mut stream| {
        let mut head = [0u8; 8];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(&head[..2], &[0x04, 0x01]);
        // USERID, NUL-terminated.
        let mut user = Vec::new();
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).unwrap();
            if b[0] == 0 {
                break;
            }
            user.push(b[0]);
        }
        assert_eq!(user, b"bob");
        stream.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).unwrap();
        let (req, _) = read_request(&mut stream).unwrap();
        assert!(req.starts_with("GET /"), "head: {req}");
        respond(&mut stream, "200 OK", "", b"socks4");
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::all(format!("socks4://bob@{addr}")).unwrap())
        .build()
        .unwrap();
    let res = client.get("http://1.2.3.4/").send().unwrap();
    assert_eq!(res.text().unwrap(), "socks4");
}

#[test]
fn socks5_reply_codes_are_reported() {
    let addr = server(|mut stream| {
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        stream.write_all(&[0x05, 0x00]).unwrap();
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).unwrap();
        let mut rest = [0u8; 6];
        stream.read_exact(&mut rest).unwrap();
        // 0x05 = connection refused.
        stream
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
    });

    let client = bangboo::Client::builder()
        .proxy(bangboo::Proxy::all(format!("socks5://{addr}")).unwrap())
        .build()
        .unwrap();
    let err = client.get("http://1.2.3.4/").send().unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("refused"), "unexpected error: {msg}");
}
