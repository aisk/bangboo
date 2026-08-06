use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::dns::Resolve;
use crate::proxy::ProxyScheme;

const READ_BUF_SIZE: usize = 8 * 1024;
const MAX_LINE_SIZE: usize = 64 * 1024;

/// How stale an armed socket timeout may get before `refresh_deadline`
/// re-arms it. Bounds deadline overshoot while avoiding two `setsockopt`
/// calls on every body read.
const REARM_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) enum Stream {
    Tcp(TcpStream),
    // The inner stream is recursive so that a TLS session can run inside
    // an already-encrypted connection to an https proxy (TLS-in-TLS).
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, Stream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Tcp(s) => s,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.get_ref().tcp(),
        }
    }

    /// Whether a TLS layer is holding decrypted bytes we have not consumed,
    /// or has seen the peer's `close_notify`.
    ///
    /// Peeking the raw socket cannot see either: rustls decrypts every
    /// complete record it reads, so surplus plaintext (a pipelined or
    /// forged second response) sits inside the session while the socket
    /// looks drained. Reusing such a connection would read that plaintext
    /// as the head of the next response.
    fn has_pending_plaintext(&self) -> bool {
        match self {
            Stream::Tcp(_) => false,
            // `wants_read()` is false exactly when there is unread
            // plaintext or a close_notify has arrived; on an established
            // session nothing else can clear it.
            #[cfg(feature = "tls")]
            Stream::Tls(s) => !s.conn.wants_read() || s.get_ref().has_pending_plaintext(),
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
    /// Log every read and write at TRACE (`connection_verbose`).
    verbose: bool,
    /// The deadline currently armed on the socket, and when it was armed.
    armed: Option<(Instant, Instant)>,
}

impl Conn {
    fn new(stream: Stream, remote_addr: Option<SocketAddr>, verbose: bool) -> Conn {
        Conn {
            stream,
            buf: vec![0; READ_BUF_SIZE].into_boxed_slice(),
            pos: 0,
            end: 0,
            remote_addr,
            received: 0,
            verbose,
            armed: None,
        }
    }

    fn trace(&self, direction: &str, bytes: &[u8]) {
        if self.verbose {
            log::trace!("{direction}: {:?}", String::from_utf8_lossy(bytes));
        }
    }

    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    #[cfg(test)]
    pub(crate) fn for_test(stream: TcpStream) -> Conn {
        Conn::new(Stream::Tcp(stream), None, false)
    }

    /// The DER encoded leaf certificate presented by the peer, when this
    /// connection uses TLS. For a tunneled connection this is the
    /// certificate of the origin (the outermost TLS layer).
    #[cfg(feature = "tls")]
    pub(crate) fn peer_certificate(&self) -> Option<Vec<u8>> {
        match &self.stream {
            Stream::Tcp(_) => None,
            Stream::Tls(tls) => tls
                .conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| cert.as_ref().to_vec()),
        }
    }

    /// Total bytes ever received on this connection. Used to detect whether
    /// a failed request attempt had already started receiving a response,
    /// in which case it must not be retried.
    pub(crate) fn received_bytes(&self) -> u64 {
        self.received
    }

    /// Applies a deadline to all following socket operations. `None` clears
    /// any previously set socket timeouts (important for pooled conns).
    pub(crate) fn set_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        set_socket_deadline(self.stream.tcp(), deadline)?;
        self.armed = deadline.map(|d| (Instant::now(), d));
        Ok(())
    }

    /// Re-arms the socket timeouts for `deadline`, skipping the syscalls
    /// when the same deadline was armed within `REARM_INTERVAL` (the socket
    /// timeout is then at most that much stale).
    pub(crate) fn refresh_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        if let Some((at, armed)) = self.armed
            && armed == deadline
            && at.elapsed() < REARM_INTERVAL
        {
            return Ok(());
        }
        self.set_deadline(Some(deadline))
    }

    /// Number of bytes sitting in the internal read buffer.
    pub(crate) fn buffered(&self) -> usize {
        self.end - self.pos
    }

    /// Discards `n` bytes from the internal read buffer.
    pub(crate) fn consume_buffered(&mut self, n: usize) {
        debug_assert!(n <= self.buffered());
        self.pos += n;
    }

    fn fill(&mut self) -> io::Result<usize> {
        self.pos = 0;
        self.end = self.stream.read(&mut self.buf)?;
        self.received += self.end as u64;
        if self.verbose {
            let read = &self.buf[..self.end];
            log::trace!("read: {:?}", String::from_utf8_lossy(read));
        }
        Ok(self.end)
    }

    /// Reads a single line, returning it without the trailing CRLF.
    pub(crate) fn read_line(&mut self) -> io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if self.pos == self.end && self.fill()? == 0 {
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
        self.trace("write", data);
        self.stream.write_all(data)
    }

    /// Unwraps the connection back into its stream, e.g. to layer TLS on
    /// top after a successful `CONNECT`. Fails if response bytes beyond the
    /// head were already buffered (they would be silently lost).
    fn into_stream(self) -> io::Result<Stream> {
        // Surplus bytes may sit in our own buffer or, for an https proxy,
        // inside the proxy's TLS session.
        if self.buffered() > 0 || self.stream.has_pending_plaintext() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy sent unexpected data after the CONNECT response",
            ));
        }
        Ok(self.stream)
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    /// Checks whether an idle pooled connection is still usable: no stray
    /// buffered data and the peer has not closed or sent anything.
    pub(crate) fn is_reusable_now(&self) -> bool {
        if self.pos < self.end || self.stream.has_pending_plaintext() {
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
            self.trace("read", &out[..n]);
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

/// TCP socket configuration applied to every new connection.
#[derive(Clone, Default)]
pub(crate) struct TcpConfig {
    pub(crate) nodelay: bool,
    pub(crate) verbose: bool,
    pub(crate) local_address: Option<IpAddr>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub(crate) interface: Option<String>,
    pub(crate) keepalive: Option<Duration>,
    pub(crate) keepalive_interval: Option<Duration>,
    pub(crate) keepalive_retries: Option<u32>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub(crate) user_timeout: Option<Duration>,
}

impl TcpConfig {
    /// Opens a socket for `addr` with all configured options applied,
    /// connecting with an optional timeout.
    fn connect(&self, addr: &SocketAddr, timeout: Option<Duration>) -> io::Result<TcpStream> {
        let domain = socket2::Domain::for_address(*addr);
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref interface) = self.interface {
            socket.bind_device(Some(interface.as_bytes()))?;
        }

        if self.keepalive.is_some()
            || self.keepalive_interval.is_some()
            || self.keepalive_retries.is_some()
        {
            let mut keepalive = socket2::TcpKeepalive::new();
            if let Some(time) = self.keepalive {
                keepalive = keepalive.with_time(time);
            }
            if let Some(interval) = self.keepalive_interval {
                keepalive = keepalive.with_interval(interval);
            }
            if let Some(retries) = self.keepalive_retries {
                keepalive = keepalive.with_retries(retries);
            }
            socket.set_tcp_keepalive(&keepalive)?;
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if self.user_timeout.is_some() {
            socket.set_tcp_user_timeout(self.user_timeout)?;
        }

        // Bind to the configured local address when the family matches;
        // a mismatching family would make connect fail outright.
        if let Some(local) = self.local_address
            && local.is_ipv4() == addr.is_ipv4()
        {
            socket.bind(&SocketAddr::new(local, 0).into())?;
        }

        match timeout {
            Some(timeout) => socket.connect_timeout(&(*addr).into(), timeout)?,
            None => socket.connect(&(*addr).into())?,
        }
        let stream: TcpStream = socket.into();
        let _ = stream.set_nodelay(self.nodelay);
        Ok(stream)
    }
}

pub(crate) struct Connector {
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) http1: crate::proto::Http1Opts,
    pub(crate) tcp: TcpConfig,
    pub(crate) resolver: Arc<dyn Resolve>,
    #[cfg(feature = "tls")]
    pub(crate) tls: std::sync::Arc<rustls::ClientConfig>,
}

impl Connector {
    pub(crate) fn connect(
        &self,
        https: bool,
        host: &str,
        port: u16,
        proxy: Option<&ProxyScheme>,
        deadline: Option<Instant>,
    ) -> crate::Result<Conn> {
        // `Url::host_str()` keeps the brackets around IPv6 literals
        // (`"[::1]"`), but the resolver and TLS want the bare address.
        let bare_host = bare(host);

        // The handshake phases after the TCP connect (SOCKS, CONNECT, TLS)
        // honor connect_timeout in addition to the overall deadline,
        // matching reqwest where "connect" covers TCP + TLS.
        let handshake_deadline = match (deadline, self.connect_timeout) {
            // An overflowing connect_timeout means "no extra bound", like
            // the request deadline in `Client::execute_request`.
            (d, Some(t)) => match Instant::now().checked_add(t) {
                Some(by_connect) => Some(d.map_or(by_connect, |d| d.min(by_connect))),
                None => d,
            },
            (d, None) => d,
        };

        match proxy {
            None => {
                let tcp = self.open_tcp(bare_host, port, deadline)?;
                let remote_addr = tcp.peer_addr().ok();
                let stream = if https {
                    set_socket_deadline(&tcp, handshake_deadline).map_err(crate::error::from_io)?;
                    self.tls_wrap(Stream::Tcp(tcp), bare_host)?
                } else {
                    Stream::Tcp(tcp)
                };
                Ok(Conn::new(stream, remote_addr, self.tcp.verbose))
            }
            Some(ProxyScheme::Http {
                tls,
                host: proxy_host,
                port: proxy_port,
                auth,
                headers,
            }) => {
                let tcp = self.open_tcp(bare(proxy_host), *proxy_port, deadline)?;
                let remote_addr = tcp.peer_addr().ok();
                set_socket_deadline(&tcp, handshake_deadline).map_err(crate::error::from_io)?;
                let mut stream = Stream::Tcp(tcp);
                if *tls {
                    stream = self.tls_wrap(stream, bare(proxy_host))?;
                }
                if !https {
                    // Plain http through an HTTP proxy: no tunnel, requests
                    // are simply written in absolute-form.
                    return Ok(Conn::new(stream, remote_addr, self.tcp.verbose));
                }
                // https through an HTTP proxy: open a CONNECT tunnel, then
                // run TLS to the origin inside it.
                let mut conn = Conn::new(stream, remote_addr, self.tcp.verbose);
                self.connect_tunnel(&mut conn, host, port, auth.as_ref(), headers)?;
                let stream = self.tls_wrap(
                    conn.into_stream().map_err(crate::error::connect)?,
                    bare_host,
                )?;
                Ok(Conn::new(stream, remote_addr, self.tcp.verbose))
            }
            Some(ProxyScheme::Socks4 {
                host: proxy_host,
                port: proxy_port,
                remote_dns,
                user_id,
            }) => {
                let mut tcp = self.open_tcp(bare(proxy_host), *proxy_port, deadline)?;
                let remote_addr = tcp.peer_addr().ok();
                set_socket_deadline(&tcp, handshake_deadline).map_err(crate::error::from_io)?;
                crate::socks::socks4_handshake(
                    &mut tcp,
                    bare_host,
                    port,
                    *remote_dns,
                    user_id,
                    &*self.resolver,
                )
                .map_err(connect_io)?;
                let stream = if https {
                    self.tls_wrap(Stream::Tcp(tcp), bare_host)?
                } else {
                    Stream::Tcp(tcp)
                };
                Ok(Conn::new(stream, remote_addr, self.tcp.verbose))
            }
            Some(ProxyScheme::Socks5 {
                host: proxy_host,
                port: proxy_port,
                auth,
                remote_dns,
            }) => {
                let mut tcp = self.open_tcp(bare(proxy_host), *proxy_port, deadline)?;
                let remote_addr = tcp.peer_addr().ok();
                set_socket_deadline(&tcp, handshake_deadline).map_err(crate::error::from_io)?;
                crate::socks::socks5_handshake(
                    &mut tcp,
                    bare_host,
                    port,
                    auth.as_ref(),
                    *remote_dns,
                    &*self.resolver,
                )
                .map_err(connect_io)?;
                let stream = if https {
                    self.tls_wrap(Stream::Tcp(tcp), bare_host)?
                } else {
                    Stream::Tcp(tcp)
                };
                Ok(Conn::new(stream, remote_addr, self.tcp.verbose))
            }
        }
    }

    /// Resolves `host` and opens a TCP connection to the first address that
    /// accepts, within the deadline and `connect_timeout` budget.
    fn open_tcp(
        &self,
        bare_host: &str,
        port: u16,
        deadline: Option<Instant>,
    ) -> crate::Result<TcpStream> {
        // NOTE: resolvers offer no timeout hook, so DNS resolution is not
        // covered by connect_timeout.
        let addrs: Vec<SocketAddr> = if let Ok(ip) = bare_host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            let mut addrs = self
                .resolver
                .resolve(bare_host)
                .map_err(crate::error::connect)?;
            // Port 0 means "use the port of the URL".
            for addr in &mut addrs {
                if addr.port() == 0 {
                    addr.set_port(port);
                }
            }
            addrs
        };

        let mut last_err: Option<io::Error> = None;
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
            match self.tcp.connect(&addr, budget) {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }

        let err = last_err
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"));
        Err(crate::error::connect(err))
    }

    /// Establishes a `CONNECT` tunnel to `host:port` through an already
    /// connected HTTP proxy.
    fn connect_tunnel(
        &self,
        conn: &mut Conn,
        host: &str,
        port: u16,
        auth: Option<&http::HeaderValue>,
        extra_headers: &http::HeaderMap,
    ) -> crate::Result<()> {
        let mut req = Vec::with_capacity(128);
        req.extend_from_slice(format!("CONNECT {host}:{port} HTTP/1.1\r\n").as_bytes());
        req.extend_from_slice(format!("host: {host}:{port}\r\n").as_bytes());
        if let Some(auth) = auth {
            req.extend_from_slice(b"proxy-authorization: ");
            req.extend_from_slice(auth.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        for (name, value) in extra_headers {
            req.extend_from_slice(name.as_str().as_bytes());
            req.extend_from_slice(b": ");
            req.extend_from_slice(value.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"\r\n");
        conn.write_all(&req).map_err(connect_io)?;
        conn.flush().map_err(connect_io)?;

        let head = crate::proto::read_head(conn, &self.http1).map_err(connect_io)?;
        if !head.status.is_success() {
            return Err(crate::error::connect(format!(
                "proxy refused CONNECT tunnel: {}",
                head.status
            )));
        }
        Ok(())
    }

    /// Wraps `stream` in a TLS session for `name`, driving the handshake
    /// eagerly so failures surface as connect errors instead of on the
    /// first write.
    #[cfg(feature = "tls")]
    fn tls_wrap(&self, stream: Stream, name: &str) -> crate::Result<Stream> {
        let name = rustls::pki_types::ServerName::try_from(name.to_string())
            .map_err(crate::error::builder)?;
        let conn =
            rustls::ClientConnection::new(self.tls.clone(), name).map_err(crate::error::connect)?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(|e| {
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                    crate::error::from_io(e)
                } else {
                    crate::error::connect(e)
                }
            })?;
        }
        Ok(Stream::Tls(Box::new(tls)))
    }

    #[cfg(not(feature = "tls"))]
    fn tls_wrap(&self, _stream: Stream, _name: &str) -> crate::Result<Stream> {
        Err(crate::error::builder(
            "HTTPS requires the `tls` feature of bangboo to be enabled",
        ))
    }
}

/// Strips the brackets from an IPv6 literal host (`"[::1]"` -> `"::1"`).
fn bare(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

fn connect_io(e: io::Error) -> crate::Error {
    if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
        crate::error::from_io(e)
    } else {
        crate::error::connect(e)
    }
}
