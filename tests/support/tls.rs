//! A minimal TLS test server backed by rustls and a freshly generated
//! self-signed certificate.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A self-signed certificate authority plus a server certificate it issued.
pub struct TestCert {
    /// PEM of the CA certificate, to be trusted by the client.
    pub ca_pem: Vec<u8>,
    /// The hostname the server certificate is valid for.
    pub server_name: String,
    ca_der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

/// A client certificate/key pair signed by a `TestCert`'s CA, for mutual
/// TLS tests.
pub struct TestIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl TestCert {
    /// Generates a certificate valid for `server_name`, signed by a fresh
    /// self-signed CA.
    pub fn generate(server_name: &str) -> TestCert {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "bangboo test ca");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let params = rcgen::CertificateParams::new(vec![server_name.to_string()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();

        TestCert {
            ca_pem: ca.pem().into_bytes(),
            server_name: server_name.to_string(),
            ca_der: ca.der().clone(),
            issuer,
            cert_chain: vec![cert.der().clone(), ca.der().clone()],
            key: PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        }
    }

    /// Issues a client certificate from this CA.
    pub fn issue_client(&self) -> TestIdentity {
        let params = rcgen::CertificateParams::new(vec!["client.test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        TestIdentity {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        }
    }

    /// Spawns a TLS server handling a single connection: reads one request
    /// head and replies with `body`.
    pub fn serve_once(&self, body: &'static str) -> SocketAddr {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain.clone(), self.key.clone_key())
            .unwrap();
        serve(Arc::new(config), body)
    }

    /// Sends a close-delimited response with or without TLS close_notify.
    pub fn serve_close_delimited(&self, close_notify: bool) -> SocketAddr {
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(self.cert_chain.clone(), self.key.clone_key())
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(config).unwrap();
            conn.complete_io(&mut sock).unwrap();
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf);
                tls.write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\npartial body")
                    .unwrap();
                tls.flush().unwrap();
            }
            if close_notify {
                conn.send_close_notify();
                conn.complete_io(&mut sock).unwrap();
            }
        });
        addr
    }

    /// Spawns a TLS server that requires a client certificate signed by
    /// this CA.
    pub fn serve_once_mtls(&self, body: &'static str) -> SocketAddr {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.cert_chain.clone(), self.key.clone_key())
            .unwrap();
        serve(Arc::new(config), body)
    }
}

impl TestCert {
    /// Spawns a TLS server that answers the first request with `first`,
    /// immediately appending `trailing` raw bytes inside the same TLS
    /// flight, then keeps serving from the same connection.
    ///
    /// Models a malicious origin trying to plant a forged response in the
    /// client's TLS receive buffer so it is read as the head of the next
    /// request's response.
    pub fn serve_with_trailing(&self, first: String, trailing: String) -> SocketAddr {
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(self.cert_chain.clone(), self.key.clone_key())
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            if conn.complete_io(&mut sock).is_err() {
                return;
            }
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf);
            // Body and forgery go out in one flight, so the client's TLS
            // session decrypts both while the socket ends up drained.
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{first}{trailing}",
                first.len()
            );
            let _ = tls.write_all(response.as_bytes());
            let _ = tls.flush();
            // Stay open so a pooled reuse would succeed if it happened.
            loop {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        let ok = "HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecond";
                        let _ = tls.write_all(ok.as_bytes());
                        let _ = tls.flush();
                    }
                }
            }
        });
        addr
    }
}

impl TestCert {
    /// Spawns a keep-alive TLS server that answers every request on the
    /// same connection, counting how many TCP connections were accepted.
    pub fn serve_keepalive(&self, counter: Arc<std::sync::atomic::AtomicUsize>) -> SocketAddr {
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(self.cert_chain.clone(), self.key.clone_key())
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { return };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let config = config.clone();
                thread::spawn(move || {
                    let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    if conn.complete_io(&mut sock).is_err() {
                        return;
                    }
                    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                    let mut buf = [0u8; 4096];
                    loop {
                        match tls.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                let r = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                                if tls.write_all(r.as_bytes()).is_err() {
                                    return;
                                }
                                let _ = tls.flush();
                            }
                        }
                    }
                });
            }
        });
        addr
    }
}

fn serve(config: Arc<rustls::ServerConfig>, body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let Ok(mut conn) = rustls::ServerConnection::new(config) else {
            return;
        };
        if conn.complete_io(&mut sock).is_err() {
            return;
        }
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let mut buf = [0u8; 4096];
        let _ = tls.read(&mut buf);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = tls.write_all(response.as_bytes());
        let _ = tls.flush();
    });
    addr
}
