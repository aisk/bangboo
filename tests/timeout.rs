//! Timeout configuration: client-level, per-request, and edge values.

mod support;

use std::thread;
use std::time::{Duration, Instant};

use support::{read_request, respond, server};

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
    let start = Instant::now();
    let err = client.get(format!("http://{addr}/")).send().unwrap_err();
    assert!(err.is_timeout(), "unexpected error: {err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
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
    let start = Instant::now();
    let err = client
        .get(format!("http://{addr}/"))
        .timeout(Duration::from_millis(200))
        .send()
        .unwrap_err();
    assert!(err.is_timeout(), "unexpected error: {err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
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
