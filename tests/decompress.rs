//! Transparent response body decompression.
#![cfg(any(
    feature = "gzip",
    feature = "deflate",
    feature = "brotli",
    feature = "zstd"
))]

mod support;

use std::io::Write;

use support::{read_request, server};

/// Serves one request with a body encoded as `content-encoding`.
fn serve_encoded(encoding: &'static str, body: Vec<u8>) -> std::net::SocketAddr {
    server(move |mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            head.to_lowercase().contains("accept-encoding:"),
            "accept-encoding not sent: {head}"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-encoding: {encoding}\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
    })
}

#[cfg(feature = "gzip")]
fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[cfg(feature = "gzip")]
#[test]
fn gzip_response_is_decoded() {
    let addr = serve_encoded("gzip", gzip(b"hello gzip"));
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    // The headers no longer describe the encoded body.
    assert!(res.headers().get("content-encoding").is_none());
    assert!(res.headers().get("content-length").is_none());
    assert_eq!(res.content_length(), None);
    assert_eq!(res.text().unwrap(), "hello gzip");
}

#[cfg(feature = "gzip")]
#[test]
fn gzip_can_be_disabled() {
    let raw = gzip(b"still encoded");
    let addr = server(move |mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            !head.to_lowercase().contains("accept-encoding"),
            "accept-encoding must not be sent: {head}"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n",
            raw.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&raw).unwrap();
    });

    let client = bangboo::Client::builder()
        .no_gzip()
        .no_deflate()
        .no_brotli()
        .no_zstd()
        .build()
        .unwrap();
    let res = client.get(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.headers()["content-encoding"], "gzip");
    // The body comes through still compressed.
    assert_ne!(res.bytes().unwrap().as_ref(), b"still encoded");
}

#[cfg(feature = "gzip")]
#[test]
fn explicit_accept_encoding_is_not_duplicated() {
    let raw = gzip(b"manual");
    let addr = server(move |mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        let lower = head.to_lowercase();
        assert!(lower.contains("accept-encoding: gzip"), "head: {head}");
        assert_eq!(lower.matches("accept-encoding").count(), 1, "head: {head}");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n",
            raw.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&raw).unwrap();
    });

    // The caller's header is left as-is, and (like reqwest) decoding is
    // still driven by the client's configuration.
    let res = bangboo::Client::new()
        .get(format!("http://{addr}/"))
        .header("accept-encoding", "gzip")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "manual");
}

#[cfg(feature = "deflate")]
#[test]
fn deflate_response_is_decoded() {
    use flate2::write::{DeflateEncoder, ZlibEncoder};

    // zlib-wrapped, as the RFC prescribes.
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"hello zlib").unwrap();
    let addr = serve_encoded("deflate", encoder.finish().unwrap());
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "hello zlib");

    // Raw deflate, as some servers send it.
    let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"hello raw").unwrap();
    let addr = serve_encoded("deflate", encoder.finish().unwrap());
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "hello raw");
}

#[cfg(feature = "brotli")]
#[test]
fn brotli_response_is_decoded() {
    let mut encoded = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut encoded, 4096, 5, 22);
        writer.write_all(b"hello brotli").unwrap();
    }
    let addr = serve_encoded("br", encoded);
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "hello brotli");
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_response_is_decoded() {
    let encoded = zstd::encode_all(&b"hello zstd"[..], 3).unwrap();
    let addr = serve_encoded("zstd", encoded);
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "hello zstd");
}

#[cfg(all(feature = "gzip", feature = "brotli"))]
#[test]
fn chained_encodings_are_peeled_in_order() {
    // content-encoding: gzip, br means gzip was applied first, then br.
    let gzipped = gzip(b"layered");
    let mut encoded = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut encoded, 4096, 5, 22);
        writer.write_all(&gzipped).unwrap();
    }
    let addr = serve_encoded("gzip, br", encoded);
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "layered");
}

#[cfg(feature = "gzip")]
#[test]
fn unknown_outer_coding_leaves_body_encoded() {
    let addr = serve_encoded("gzip, unknown-coding", gzip(b"never decoded"));
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    // Peeling stops at the unknown outermost coding, so nothing is decoded
    // and the header is left untouched.
    assert_eq!(res.headers()["content-encoding"], "gzip, unknown-coding");
}

#[cfg(feature = "gzip")]
#[test]
fn identity_encoding_is_ignored() {
    let addr = serve_encoded("identity", b"plain body".to_vec());
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "plain body");
}

#[cfg(feature = "gzip")]
#[test]
fn range_request_skips_accept_encoding() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(
            !head.to_lowercase().contains("accept-encoding"),
            "accept-encoding must not be sent with a range request: {head}"
        );
        support::respond(&mut stream, "206 Partial Content", "", b"part");
    });

    let res = bangboo::Client::new()
        .get(format!("http://{addr}/"))
        .header("range", "bytes=0-3")
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "part");
}

#[cfg(feature = "gzip")]
#[test]
fn decoded_body_still_pools_the_connection() {
    use support::server_loop;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let conns = Arc::new(AtomicUsize::new(0));
    let counter = conns.clone();
    let addr = server_loop(move |mut stream| {
        counter.fetch_add(1, Ordering::SeqCst);
        while read_request(&mut stream).is_some() {
            let body = gzip(b"pooled");
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        }
    });

    let client = bangboo::Client::new();
    let url = format!("http://{addr}/");
    for _ in 0..3 {
        assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "pooled");
    }
    // All three requests shared one keep-alive connection.
    assert_eq!(conns.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "gzip")]
#[test]
fn empty_bodies_with_content_encoding_are_not_decoded() {
    use support::server_loop;

    // Servers routinely echo the entity's Content-Encoding on responses
    // that carry no body; feeding an empty stream to a decompressor would
    // fail instead of yielding the empty body the caller expects.
    let addr = server_loop(|mut stream| {
        while let Some((head, _)) = read_request(&mut stream) {
            let status = if head.starts_with("HEAD") {
                "200 OK"
            } else if head.contains("/304") {
                "304 Not Modified"
            } else {
                "204 No Content"
            };
            let response =
                format!("HTTP/1.1 {status}\r\ncontent-encoding: gzip\r\ncontent-length: 100\r\n\r\n");
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });

    let client = bangboo::Client::new();
    let res = client.head(format!("http://{addr}/")).send().unwrap();
    assert_eq!(res.text().unwrap(), "");

    let res = client.get(format!("http://{addr}/304")).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::NOT_MODIFIED);
    assert_eq!(res.text().unwrap(), "");

    let res = client.get(format!("http://{addr}/204")).send().unwrap();
    assert_eq!(res.status(), bangboo::StatusCode::NO_CONTENT);
    assert_eq!(res.text().unwrap(), "");
}

#[cfg(feature = "gzip")]
#[test]
fn zero_length_body_with_content_encoding_is_not_decoded() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 0\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
    });
    let res = bangboo::get(format!("http://{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "");
}
