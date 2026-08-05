use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const READ_BUF_SIZE: usize = 8 * 1024;
const MAX_LINE_SIZE: usize = 64 * 1024;

pub(crate) enum Stream {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Tcp(s) => s,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.get_ref(),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// An established connection with a small internal read buffer, used for
/// parsing response heads and chunked framing.
pub(crate) struct Conn {
    stream: Stream,
    buf: Box<[u8]>,
    pos: usize,
    end: usize,
    remote_addr: Option<SocketAddr>,
    received: u64,
}

impl Conn {
    fn new(stream: Stream, remote_addr: Option<SocketAddr>) -> Conn {
        Conn {
            stream,
            buf: vec![0; READ_BUF_SIZE].into_boxed_slice(),
            pos: 0,
            end: 0,
            remote_addr,
            received: 0,
        }
    }

    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Total bytes ever received on this connection. Used to detect whether
    /// a failed request attempt had already started receiving a response,
    /// in which case it must not be retried.
    pub(crate) fn received_bytes(&self) -> u64 {
        self.received
    }

    /// Applies a deadline to all following socket operations. `None` clears
    /// any previously set socket timeouts (important for pooled conns).
    pub(crate) fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        set_socket_deadline(self.stream.tcp(), deadline)
    }

    fn fill(&mut self) -> io::Result<usize> {
        self.pos = 0;
        self.end = self.stream.read(&mut self.buf)?;
        self.received += self.end as u64;
        Ok(self.end)
    }

    /// Reads a single line, returning it without the trailing CRLF.
    pub(crate) fn read_line(&mut self) -> io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if self.pos == self.end
                && self.fill()? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed while reading line",
                    ));
                }
            while self.pos < self.end {
                let b = self.buf[self.pos];
                self.pos += 1;
                if b == b'\n' {
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(line);
                }
                line.push(b);
                if line.len() > MAX_LINE_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "line exceeds maximum length",
                    ));
                }
            }
        }
    }

    pub(crate) fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    /// Checks whether an idle pooled connection is still usable: no stray
    /// buffered data and the peer has not closed or sent anything.
    pub(crate) fn is_reusable_now(&self) -> bool {
        if self.pos < self.end {
            return false;
        }
        let tcp = self.stream.tcp();
        if tcp.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let alive = match tcp.peek(&mut byte) {
            // Ok(0) means EOF; Ok(n) means unexpected data (or a pending TLS
            // close_notify) -- discard the connection in both cases.
            Ok(_) => false,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        };
        alive && tcp.set_nonblocking(false).is_ok()
    }
}

impl Read for Conn {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.end {
            let n = (self.end - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        if out.len() >= self.buf.len() {
            let n = self.stream.read(out)?;
            self.received += n as u64;
            return Ok(n);
        }
        if self.fill()? == 0 {
            return Ok(0);
        }
        let n = (self.end - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

pub(crate) fn set_socket_deadline(tcp: &TcpStream, deadline: Option<Instant>) -> io::Result<()> {
    match deadline {
        Some(deadline) => {
            let now = Instant::now();
            if deadline <= now {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline elapsed"));
            }
            let remaining = deadline - now;
            tcp.set_read_timeout(Some(remaining))?;
            tcp.set_write_timeout(Some(remaining))?;
        }
        None => {
            tcp.set_read_timeout(None)?;
            tcp.set_write_timeout(None)?;
        }
    }
    Ok(())
}

pub(crate) struct Connector {
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) nodelay: bool,
    #[cfg(feature = "tls")]
    pub(crate) tls: std::sync::Arc<rustls::ClientConfig>,
}

impl Connector {
    pub(crate) fn connect(
        &self,
        https: bool,
        host: &str,
        port: u16,
        deadline: Option<Instant>,
    ) -> crate::Result<Conn> {
        // `Url::host_str()` keeps the brackets around IPv6 literals
        // (`"[::1]"`), but the resolver and TLS want the bare address.
        let bare_host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);

        // NOTE: std's resolver offers no timeout hook, so DNS resolution is
        // not covered by connect_timeout.
        let addrs: Vec<SocketAddr> = (bare_host, port)
            .to_socket_addrs()
            .map_err(crate::error::connect)?
            .collect();

        let mut last_err: Option<io::Error> = None;
        let mut tcp: Option<TcpStream> = None;
        for addr in addrs {
            let mut budget = self.connect_timeout;
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if deadline <= now {
                    return Err(crate::error::from_io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "deadline elapsed",
                    )));
                }
                let remaining = deadline - now;
                budget = Some(budget.map_or(remaining, |b| b.min(remaining)));
            }
            let result = match budget {
                Some(timeout) => TcpStream::connect_timeout(&addr, timeout),
                None => TcpStream::connect(addr),
            };
            match result {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }

        let tcp = match tcp {
            Some(tcp) => tcp,
            None => {
                let err = last_err.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no addresses resolved")
                });
                return Err(crate::error::connect(err));
            }
        };
        let _ = tcp.set_nodelay(self.nodelay);
        let remote_addr = tcp.peer_addr().ok();

        let stream = if https {
            #[cfg(feature = "tls")]
            {
                // The handshake honors connect_timeout in addition to the
                // overall deadline, matching reqwest where connect covers
                // TCP + TLS.
                let handshake_deadline = match (deadline, self.connect_timeout) {
                    (d, Some(t)) => {
                        let by_connect = Instant::now() + t;
                        Some(d.map_or(by_connect, |d| d.min(by_connect)))
                    }
                    (d, None) => d,
                };
                set_socket_deadline(&tcp, handshake_deadline).map_err(crate::error::from_io)?;
                let name = rustls::pki_types::ServerName::try_from(bare_host.to_string())
                    .map_err(crate::error::builder)?;
                let conn = rustls::ClientConnection::new(self.tls.clone(), name)
                    .map_err(crate::error::connect)?;
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                // Drive the handshake eagerly so failures surface as connect
                // errors instead of on the first write.
                while tls.conn.is_handshaking() {
                    tls.conn.complete_io(&mut tls.sock).map_err(|e| {
                        if e.kind() == io::ErrorKind::TimedOut
                            || e.kind() == io::ErrorKind::WouldBlock
                        {
                            crate::error::from_io(e)
                        } else {
                            crate::error::connect(e)
                        }
                    })?;
                }
                Stream::Tls(Box::new(tls))
            }
            #[cfg(not(feature = "tls"))]
            {
                return Err(crate::error::builder(
                    "HTTPS requires the `tls` feature of bangboo to be enabled",
                ));
            }
        } else {
            Stream::Tcp(tcp)
        };

        Ok(Conn::new(stream, remote_addr))
    }
}

#[cfg(feature = "tls")]
pub(crate) mod tls {
    use std::sync::Arc;

    pub(crate) fn build_config(accept_invalid_certs: bool) -> Arc<rustls::ClientConfig> {
        let config = if accept_invalid_certs {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoVerify))
                .with_no_client_auth()
        } else {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        Arc::new(config)
    }

    mod danger {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};

        #[derive(Debug)]
        pub(super) struct NoVerify;

        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA1,
                    SignatureScheme::ECDSA_SHA1_Legacy,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::ED25519,
                    SignatureScheme::ED448,
                ]
            }
        }
    }
}
