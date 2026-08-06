//! DNS overrides and custom resolvers.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use support::{read_request, respond, server};

#[test]
fn resolve_override() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        assert!(head.contains("host: fake.invalid"), "head: {head}");
        respond(&mut stream, "200 OK", "", b"overridden");
    });

    let client = bangboo::Client::builder()
        .resolve("fake.invalid", addr)
        .build()
        .unwrap();
    let res = client
        .get(format!("http://fake.invalid:{}/", addr.port()))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "overridden");
}

#[test]
fn resolve_override_port_zero_uses_url_port() {
    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder()
        .resolve("fake.invalid", SocketAddr::new(addr.ip(), 0))
        .build()
        .unwrap();
    let res = client
        .get(format!("http://fake.invalid:{}/", addr.port()))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}

#[test]
fn custom_resolver() {
    struct Fixed(SocketAddr);
    impl bangboo::dns::Resolve for Fixed {
        fn resolve(&self, name: &str) -> std::io::Result<Vec<SocketAddr>> {
            assert_eq!(name, "custom.invalid");
            Ok(vec![self.0])
        }
    }

    let addr = server(|mut stream| {
        read_request(&mut stream).unwrap();
        respond(&mut stream, "200 OK", "", b"custom");
    });

    let client = bangboo::Client::builder()
        .dns_resolver(Arc::new(Fixed(addr)))
        .build()
        .unwrap();
    let res = client
        .get(format!("http://custom.invalid:{}/", addr.port()))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "custom");
}
