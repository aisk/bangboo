//! TLS configuration: custom roots, hostname/cert verification toggles,
//! version bounds, and TlsInfo.
#![cfg(feature = "tls")]

mod support;

use std::net::SocketAddr;

use support::tls::TestCert;

/// A client that resolves `name` to the test server's address.
fn client_for(cert: &TestCert, addr: SocketAddr) -> bangboo::ClientBuilder {
    bangboo::Client::builder().resolve(&cert.server_name, addr)
}

fn url_for(cert: &TestCert, addr: SocketAddr) -> String {
    format!("https://{}:{}/", cert.server_name, addr.port())
}

#[test]
fn custom_root_certificate() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("secure");

    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    let client = client_for(&cert, addr)
        .add_root_certificate(ca)
        .build()
        .unwrap();
    let res = client.get(url_for(&cert, addr)).send().unwrap();
    assert_eq!(res.text().unwrap(), "secure");
}

#[test]
fn unknown_root_is_rejected() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("secure");

    let client = client_for(&cert, addr).build().unwrap();
    let err = client.get(url_for(&cert, addr)).send().unwrap_err();
    assert!(err.is_connect() || err.is_request(), "unexpected: {err:?}");
}

#[test]
fn accept_invalid_certs() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("insecure");

    let client = client_for(&cert, addr)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client.get(url_for(&cert, addr)).send().unwrap();
    assert_eq!(res.text().unwrap(), "insecure");
}

#[test]
fn accept_invalid_hostnames() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("wrong name ok");

    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    // Request a name the certificate is not valid for.
    let client = bangboo::Client::builder()
        .resolve("other.test", addr)
        .add_root_certificate(ca.clone())
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    let res = client
        .get(format!("https://other.test:{}/", addr.port()))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "wrong name ok");

    // Without the option the same request fails.
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("nope");
    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    let client = bangboo::Client::builder()
        .resolve("other.test", addr)
        .add_root_certificate(ca)
        .build()
        .unwrap();
    let err = client
        .get(format!("https://other.test:{}/", addr.port()))
        .send()
        .unwrap_err();
    assert!(err.is_connect() || err.is_request(), "unexpected: {err:?}");
}

#[test]
fn certs_only_disables_built_in_roots() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("only");

    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    let client = client_for(&cert, addr)
        .tls_certs_only([ca])
        .build()
        .unwrap();
    let res = client.get(url_for(&cert, addr)).send().unwrap();
    assert_eq!(res.text().unwrap(), "only");
}

#[test]
fn no_roots_at_all_is_a_builder_error() {
    let err = bangboo::Client::builder()
        .tls_built_in_root_certs(false)
        .build()
        .unwrap_err();
    assert!(err.is_builder(), "unexpected: {err:?}");
}

#[test]
fn tls_version_bounds() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("v13");
    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();

    let client = client_for(&cert, addr)
        .add_root_certificate(ca)
        .min_tls_version(bangboo::tls::Version::TLS_1_3)
        .build()
        .unwrap();
    let res = client.get(url_for(&cert, addr)).send().unwrap();
    assert_eq!(res.text().unwrap(), "v13");

    // An impossible range is rejected at build time.
    let err = bangboo::Client::builder()
        .min_tls_version(bangboo::tls::Version::TLS_1_3)
        .max_tls_version(bangboo::tls::Version::TLS_1_2)
        .build()
        .unwrap_err();
    assert!(err.is_builder(), "unexpected: {err:?}");
}

#[test]
fn tls_info_extension() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once("info");
    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();

    let client = client_for(&cert, addr)
        .add_root_certificate(ca)
        .tls_info(true)
        .build()
        .unwrap();
    let res = client.get(url_for(&cert, addr)).send().unwrap();
    let info = res
        .extensions()
        .get::<bangboo::tls::TlsInfo>()
        .expect("TlsInfo missing");
    assert!(!info.peer_certificate().unwrap().is_empty());
}

#[test]
fn certificate_pem_bundle_parsing() {
    let cert = TestCert::generate("bangboo.test");
    let mut bundle = cert.ca_pem.clone();
    bundle.extend_from_slice(&cert.ca_pem);
    let certs = bangboo::Certificate::from_pem_bundle(&bundle).unwrap();
    assert_eq!(certs.len(), 2);

    assert!(bangboo::Certificate::from_pem(b"not a pem").is_err());
}

#[test]
fn mutual_tls_identity() {
    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_once_mtls("mtls");
    let client_id = cert.issue_client();

    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    let identity =
        bangboo::Identity::from_pkcs8_pem(&client_id.cert_pem, &client_id.key_pem).unwrap();
    let client = client_for(&cert, addr)
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .unwrap();
    let res = client.get(url_for(&cert, addr)).send().unwrap();
    assert_eq!(res.text().unwrap(), "mtls");
}

#[test]
fn identity_from_combined_pem() {
    let cert = TestCert::generate("bangboo.test");
    let client_id = cert.issue_client();
    let mut combined = client_id.cert_pem.clone();
    combined.extend_from_slice(&client_id.key_pem);
    assert!(bangboo::Identity::from_pem(&combined).is_ok());
    assert!(bangboo::Identity::from_pem(b"garbage").is_err());
}

/// A server that appends a forged response after a complete body must not
/// get that forgery served as the *next* request's response: rustls has
/// already decrypted it, so peeking the socket cannot detect it and the
/// connection must be kept out of the pool.
#[test]
fn tls_connection_with_buffered_plaintext_is_not_pooled() {
    const FORGED: &str = "HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nFORGED";
    // Larger than the 8 KiB connection buffer so the body is read straight
    // into the caller's slice and the surplus is left inside the TLS
    // session where a socket peek cannot see it.
    let first = "x".repeat(50_000);

    let cert = TestCert::generate("bangboo.test");
    let addr = cert.serve_with_trailing(first.clone(), FORGED.to_string());
    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    let client = client_for(&cert, addr)
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let url = url_for(&cert, addr);
    assert_eq!(client.get(&url).send().unwrap().text().unwrap(), first);

    // The second request must never observe the forged body.
    // Falling back to a fresh connection may fail against this
    // single-connection test server; only the forgery must not happen.
    if let Ok(res) = client.get(&url).send() {
        assert_ne!(
            res.text().unwrap(),
            "FORGED",
            "forged response was served from the pool"
        );
    }
}

#[test]
fn tls_connections_are_pooled() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let cert = TestCert::generate("bangboo.test");
    let conns = Arc::new(AtomicUsize::new(0));
    let addr = cert.serve_keepalive(conns.clone());
    let ca = bangboo::Certificate::from_pem(&cert.ca_pem).unwrap();
    let client = client_for(&cert, addr)
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let url = url_for(&cert, addr);
    for _ in 0..3 {
        assert_eq!(client.get(&url).send().unwrap().text().unwrap(), "ok");
    }
    assert_eq!(conns.load(Ordering::SeqCst), 1, "TLS connection was not reused");
}
