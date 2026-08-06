//! Redirect following: policies, method rewriting, and URL resolution.

mod support;

use support::{read_request, respond, server, server_loop};

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
fn redirect_custom_policy_stop_and_error() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /blocked\r\n", b"");
    });

    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::custom(|attempt| {
            if attempt.url().path() == "/blocked" {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::FOUND);

    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /derailed\r\n", b"");
    });
    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::custom(|attempt| {
            attempt.error("no redirects for you")
        }))
        .build()
        .unwrap();
    let err = client.get(format!("http://{addr}/")).send().unwrap_err();
    assert!(err.is_redirect(), "unexpected error: {err:?}");
}

#[test]
fn redirect_custom_policy_sees_chain() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /hop1\r\n", b"");
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /hop2\r\n", b"");
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"end");
    });

    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::custom(|attempt| {
            assert!(!attempt.previous().is_empty());
            assert_eq!(attempt.status(), bangboo::StatusCode::FOUND);
            attempt.follow()
        }))
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "end");
}

#[test]
fn redirect_sets_referer() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(!head.to_lowercase().contains("referer"), "head: {head}");
        respond(&mut stream, "302 Found", "location: /next\r\n", b"");
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.to_lowercase().contains("referer: http://"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::new();
    let res = client.get(format!("http://{addr}/start")).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
}

#[test]
fn redirect_referer_disabled() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "302 Found", "location: /next\r\n", b"");
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(!head.to_lowercase().contains("referer"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder().referer(false).build().unwrap();
    let res = client.get(format!("http://{addr}/start")).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::OK);
}

#[test]
fn redirect_limit_allows_exactly_max_hops() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Three hops then a 200: allowed by limited(3).
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let addr = server_loop(move |mut stream| {
        while read_request(&mut stream).is_some() {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 3 {
                respond(&mut stream, "302 Found", "location: /next\r\n", b"");
            } else {
                respond(&mut stream, "200 OK", "", b"arrived");
            }
        }
    });

    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::limited(3))
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "arrived");
    assert_eq!(seen.load(Ordering::SeqCst), 4);

    // A fourth hop exceeds the limit.
    let addr = server_loop(|mut stream| {
        while read_request(&mut stream).is_some() {
            respond(&mut stream, "302 Found", "location: /next\r\n", b"");
        }
    });
    let client = bangboo::Client::builder()
        .redirect(bangboo::redirect::Policy::limited(3))
        .build()
        .unwrap();
    let err = client.get(format!("http://{addr}/")).send().unwrap_err();
    assert!(err.is_redirect(), "unexpected error: {err:?}");
}
