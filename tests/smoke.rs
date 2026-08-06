use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Spawns a server handling a single connection with `handler`.
fn server<F>(handler: F) -> SocketAddr
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
fn server_loop<F>(handler: F) -> SocketAddr
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
fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
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

fn respond(stream: &mut TcpStream, status: &str, extra_headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\n{extra_headers}\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

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
fn keep_alive_reuse() {
    // The server accepts exactly one connection and serves two requests on
    // it; the second request succeeding proves the pool reused the socket.
    let addr = server(|mut stream| {
        for i in 0..2 {
            read_request(&mut stream).unwrap();
            respond(&mut stream, "200 OK", "", format!("response {i}").as_bytes());
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "response 0");
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "response 1");
}

#[test]
fn redirect_followed() {
    let addr = server(|mut stream| {
        // Both requests arrive on the same pooled connection.
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("POST /start"));
        respond(&mut stream, "302 Found", "location: /target\r\n", b"");
        let (head, _) = read_request(&mut stream).unwrap();
        // 302 on POST turns into GET.
        assert!(head.starts_with("GET /target"), "got head: {head}");
        respond(&mut stream, "200 OK", "", b"made it");
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/start"))
        .body("data")
        .send()
        .unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
    assert!(res.url().path().ends_with("/target"));
    assert_eq!(res.text().unwrap(), "made it");
}

#[test]
fn redirect_limit() {
    let addr = server_loop(|mut stream| {
        while read_request(&mut stream).is_some() {
            respond(&mut stream, "302 Found", "location: /loop\r\n", b"");
        }
    });

    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::limited(3))
        .build()
        .unwrap();
    let err = client.get(format!("http://{addr}/")).send().unwrap_err();
    assert!(err.is_redirect(), "unexpected error: {err:?}");
}

#[test]
fn redirect_none_policy() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /next\r\n", b"");
    });

    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::none())
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::FOUND);
    assert_eq!(res.headers()["location"], "/next");
}

#[test]
fn timeout_on_slow_response() {
    let addr = server(|mut stream| {
        let _ = read_request(&mut stream);
        thread::sleep(Duration::from_secs(5));
    });

    let client = bangboo::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    let err = client.get(format!("http://{addr}/")).send().unwrap_err();
    assert!(err.is_timeout(), "unexpected error: {err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Message {
    lang: String,
    stars: u32,
}

#[test]
fn json_roundtrip() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head.to_lowercase().contains("content-type: application/json"));
        respond(
            &mut stream,
            "200 OK",
            "content-type: application/json\r\n",
            &body,
        );
    });

    let sent = Message {
        lang: "rust".into(),
        stars: 100_000,
    };
    let client = bangboo::Client::new();
    let received: Message = client
        .post(format!("http://{addr}/json"))
        .json(&sent)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(received, sent);
}

#[test]
fn form_body() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head
            .to_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"));
        respond(&mut stream, "200 OK", "", &body);
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/form"))
        .form(&[("lang", "rust"), ("q", "a b")])
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "lang=rust&q=a+b");
}

#[test]
fn auth_and_default_headers() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        let head = head.to_lowercase();
        assert!(head.contains("authorization: basic dxnlcjpwyxnz"));
        assert!(head.contains("user-agent: bangboo-test/1.0"));
        assert!(head.contains("accept: */*"));
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder()
        .user_agent("bangboo-test/1.0")
        .build()
        .unwrap();
    let res = client
        .get(format!("http://{addr}/"))
        .basic_auth("user", Some("pass"))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}

#[test]
fn query_building() {
    let client = bangboo::Client::new();
    let req = client
        .get("http://example.com/search?base=1")
        .query(&[("q", "hello world"), ("page", "2")])
        .build()
        .unwrap();
    assert_eq!(
        req.url().as_str(),
        "http://example.com/search?base=1&q=hello+world&page=2"
    );
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

#[test]
fn no_retry_after_partial_response() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_server = hits.clone();
    let addr = server_loop(move |mut stream| {
        while read_request(&mut stream).is_some() {
            let n = hits_server.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                respond(&mut stream, "200 OK", "", b"first");
            } else {
                // Partial status line, then abrupt close: the request may
                // have been acted upon, so the client must NOT retry it.
                let _ = stream.write_all(b"HTTP/1.1 5");
                break;
            }
        }
    });

    let client = bangboo::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{addr}/pay");
    assert_eq!(client.post(&url).body("$$$").send().unwrap().text().unwrap(), "first");
    let err = client.post(&url).body("$$$").send().unwrap_err();
    assert!(!err.is_timeout(), "unexpected error: {err:?}");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(hits.load(Ordering::SeqCst), 2, "request was wrongly retried");
}

#[test]
fn retries_stale_pooled_connection() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let conns = Arc::new(AtomicUsize::new(0));
    let conns_server = conns.clone();
    // Each connection serves exactly one keep-alive response and then the
    // server closes it silently; the pooled socket goes stale.
    let addr = server_loop(move |mut stream| {
        conns_server.fetch_add(1, Ordering::SeqCst);
        if read_request(&mut stream).is_some() {
            respond(&mut stream, "200 OK", "", b"one-shot");
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "one-shot");
    thread::sleep(Duration::from_millis(50)); // let the FIN arrive
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "one-shot");
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

#[test]
fn redirect_301_converts_put_to_get() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("PUT /old"));
        respond(&mut stream, "301 Moved Permanently", "location: /new\r\n", b"");
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET /new"), "got head: {head}");
        assert!(
            !head.to_lowercase().contains("content-length"),
            "content headers must be stripped: {head}"
        );
        respond(&mut stream, "200 OK", "", b"moved");
    });

    let client = bangboo::Client::new();
    let res = client
        .put(format!("http://{addr}/old"))
        .body("payload")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "moved");
}

#[test]
fn userinfo_in_url_becomes_basic_auth() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        // base64("user:p@ss") == dXNlcjpwQHNz
        assert!(
            head.to_lowercase().contains("authorization: basic dxnlcjpwqhnz"),
            "got head: {head}"
        );
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let res = bangboo::get(format!("http://user:p%40ss@{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}

#[test]
fn conflicting_content_length_is_rejected() {
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
fn per_request_timeout_overrides_client_timeout() {
    let addr = server(|mut stream| {
        let _ = read_request(&mut stream);
        thread::sleep(Duration::from_secs(5));
    });

    let client = bangboo::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    let err = client
        .get(format!("http://{addr}/"))
        .timeout(Duration::from_millis(200))
        .send()
        .unwrap_err();
    assert!(err.is_timeout(), "unexpected error: {err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
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
fn http_1_0_response_not_reused() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let conns = Arc::new(AtomicUsize::new(0));
    let conns_server = conns.clone();
    let addr = server_loop(move |mut stream| {
        conns_server.fetch_add(1, Ordering::SeqCst);
        if read_request(&mut stream).is_some() {
            stream
                .write_all(b"HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .unwrap();
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    let res = client.get(&url).send().unwrap();
    assert_eq!(res.version(), bangboo::Version::HTTP_10);
    assert_eq!(res.text().unwrap(), "ok");
    // HTTP/1.0 without `Connection: keep-alive` must not be pooled.
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "ok");
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

#[test]
fn switching_protocols_connection_not_pooled() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let conns = Arc::new(AtomicUsize::new(0));
    let conns_server = conns.clone();
    let addr = server_loop(move |mut stream| {
        let n = conns_server.fetch_add(1, Ordering::SeqCst);
        if read_request(&mut stream).is_none() {
            return;
        }
        if n == 0 {
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nupgrade: raw\r\nconnection: upgrade\r\n\r\nraw-bytes",
                )
                .unwrap();
        } else {
            respond(&mut stream, "200 OK", "", b"normal");
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    let res = client
        .get(&url)
        .header("connection", "upgrade")
        .header("upgrade", "raw")
        .send()
        .unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(res.text().unwrap(), "raw-bytes");
    // The upgraded socket must not serve the next plain HTTP request.
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "normal");
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

#[test]
fn pool_max_idle_zero_disables_reuse() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let conns = Arc::new(AtomicUsize::new(0));
    let conns_server = conns.clone();
    let addr = server_loop(move |mut stream| {
        conns_server.fetch_add(1, Ordering::SeqCst);
        while read_request(&mut stream).is_some() {
            respond(&mut stream, "200 OK", "", b"ok");
        }
    });

    let client = bangboo::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let url = format!("http://{addr}/");
    client.get(&url).send().unwrap().text().unwrap();
    client.get(&url).send().unwrap().text().unwrap();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(conns.load(Ordering::SeqCst), 2);
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
fn mismatched_content_length_header_rejected() {
    let addr = server(|_stream| {});

    let client = bangboo::Client::new();
    let err = client
        .post(format!("http://{addr}/"))
        .header("content-length", "3")
        .body("longer than three")
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn transfer_encoding_and_content_length_headers_rejected() {
    let addr = server(|_stream| {});

    let client = bangboo::Client::new();
    let err = client
        .post(format!("http://{addr}/"))
        .header("transfer-encoding", "chunked")
        .header("content-length", "8")
        .body("smuggle?")
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
}

#[test]
fn repeated_content_length_headers_rejected() {
    // Even identical repeats must not go out as multiple header lines.
    let addr = server(|_stream| {});

    let client = bangboo::Client::new();
    let err = client
        .post(format!("http://{addr}/"))
        .header("content-length", "4")
        .header("content-length", "4")
        .body("four")
        .send()
        .unwrap_err();
    assert!(err.is_request(), "unexpected error: {err:?}");
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

#[test]
fn empty_body_response_pooled_without_read() {
    // One connection serving two requests: dropping the 204 response without
    // reading its (empty) body must still return the socket to the pool.
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"again");
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    let res = client.get(&url).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::NO_CONTENT);
    drop(res);
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "again");
}

#[test]
fn small_unread_body_pooled_on_drop() {
    // The body arrives in the same packet as the head, so it is fully
    // buffered client-side; dropping the response unread should consume it
    // from the buffer and reuse the connection.
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi")
            .unwrap();
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"again");
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    let res = client.get(&url).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
    drop(res);
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "again");
}

#[test]
fn redirect_inherits_fragment() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /next\r\n", b"");
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /done#other\r\n", b"");
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::new();
    let res = client
        .get(format!("http://{addr}/start#frag"))
        .send()
        .unwrap();
    // A Location without a fragment inherits the original fragment; a
    // Location with its own fragment overrides it.
    assert_eq!(res.url().fragment(), Some("other"));
    assert!(res.url().path().ends_with("/done"));
}

#[test]
fn huge_timeout_does_not_panic() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder()
        .timeout(Duration::MAX)
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}

#[test]
fn redirect_302_drops_body_even_for_get() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET /a"));
        assert_eq!(body, b"odd get body");
        respond(&mut stream, "302 Found", "location: /b\r\n", b"");
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.starts_with("GET /b"));
        assert!(
            !head.to_lowercase().contains("content-length"),
            "content headers must be stripped: {head}"
        );
        respond(&mut stream, "200 OK", "", b"done");
    });

    let client = bangboo::Client::new();
    let res = client
        .get(format!("http://{addr}/a"))
        .body("odd get body")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "done");
}
