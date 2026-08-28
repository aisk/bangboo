//! Connection pooling: keep-alive reuse, retry semantics on stale sockets,
//! and the cases where a connection must NOT be reused.

mod support;

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use support::{read_request, respond, server, server_loop};

#[test]
fn keep_alive_reuse() {
    // The server accepts exactly one connection and serves two requests on
    // it; the second request succeeding proves the pool reused the socket.
    let addr = server(|mut stream| {
        for i in 0..2 {
            read_request(&mut stream).unwrap();
            respond(
                &mut stream,
                "200 OK",
                "",
                format!("response {i}").as_bytes(),
            );
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    assert_eq!(
        client.get(&url).send().unwrap().text().unwrap(),
        "response 0"
    );
    assert_eq!(
        client.get(&url).send().unwrap().text().unwrap(),
        "response 1"
    );
}

#[test]
fn retries_stale_pooled_connection() {
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
fn retries_idempotent_put_on_stale_connection() {
    let conns = Arc::new(AtomicUsize::new(0));
    let conns_server = conns.clone();
    // The first connection swallows its second request and closes without
    // responding, so only a retry on a fresh connection can succeed.
    let addr = server_loop(move |mut stream| {
        if conns_server.fetch_add(1, Ordering::SeqCst) == 0 {
            read_request(&mut stream).unwrap();
            respond(&mut stream, "200 OK", "", b"first");
            read_request(&mut stream);
        } else {
            read_request(&mut stream).unwrap();
            respond(&mut stream, "200 OK", "", b"retried");
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/doc");
    let put = || {
        client
            .put(&url)
            .body("data")
            .send()
            .unwrap()
            .text()
            .unwrap()
    };
    assert_eq!(put(), "first");
    assert_eq!(put(), "retried");
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

#[test]
fn no_retry_for_non_idempotent_method() {
    let conns = Arc::new(AtomicUsize::new(0));
    let conns_server = conns.clone();
    // The server fully receives the second POST, then closes without
    // responding; the POST may have been acted upon, so the client must
    // surface the error instead of replaying it.
    let addr = server_loop(move |mut stream| {
        conns_server.fetch_add(1, Ordering::SeqCst);
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"first");
        read_request(&mut stream);
    });

    let client = bangboo::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{addr}/pay");
    let post = || client.post(&url).body("$$$").send();
    assert_eq!(post().unwrap().text().unwrap(), "first");
    let err = post().unwrap_err();
    assert!(!err.is_timeout(), "unexpected error: {err:?}");
    assert_eq!(conns.load(Ordering::SeqCst), 1, "POST was wrongly retried");
}

#[test]
fn no_retry_after_partial_response() {
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
    assert_eq!(
        client
            .post(&url)
            .body("$$$")
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "first"
    );
    let err = client.post(&url).body("$$$").send().unwrap_err();
    assert!(!err.is_timeout(), "unexpected error: {err:?}");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "request was wrongly retried"
    );
}

#[test]
fn http_1_0_response_not_reused() {
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
fn empty_body_response_pooled_without_read() {
    // One connection serving two requests: dropping the 204 response without
    // reading its (empty) body must still return the socket to the pool.
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .unwrap();
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
