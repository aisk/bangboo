//! Synchronous SOCKS4/4a/5/5h handshakes, performed on a freshly connected
//! TCP stream to the proxy before any HTTP (or TLS) traffic.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

use crate::dns::Resolve;

fn other(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, msg)
}

fn resolve_all(resolver: &dyn Resolve, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut addrs = resolver.resolve(host)?;
    for addr in &mut addrs {
        if addr.port() == 0 {
            addr.set_port(port);
        }
    }
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses resolved",
        ));
    }
    Ok(addrs)
}

/// SOCKS4 (and 4a with `remote_dns`) CONNECT handshake.
pub(crate) fn socks4_handshake(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    remote_dns: bool,
    user_id: &str,
    resolver: &dyn Resolve,
) -> io::Result<()> {
    let mut req = vec![0x04u8, 0x01];
    req.extend_from_slice(&port.to_be_bytes());

    let ip = host.parse::<IpAddr>().ok();
    match (ip, remote_dns) {
        // socks4a: an unresolvable placeholder IP plus the hostname.
        (None, true) => req.extend_from_slice(&[0, 0, 0, 1]),
        // SOCKS4 addresses are IPv4-only, so a dual-stack host is resolved
        // to its first IPv4 candidate rather than failing on a leading AAAA.
        (None, false) => {
            let addrs = resolve_all(resolver, host, port)?;
            let v4 = addrs
                .iter()
                .find_map(|addr| match addr {
                    SocketAddr::V4(v4) => Some(*v4.ip()),
                    SocketAddr::V6(_) => None,
                })
                .ok_or_else(|| other("SOCKS4 proxies only support IPv4 targets"))?;
            req.extend_from_slice(&v4.octets());
        }
        (Some(IpAddr::V4(v4)), _) => req.extend_from_slice(&v4.octets()),
        (Some(IpAddr::V6(_)), _) => {
            return Err(other("SOCKS4 proxies only support IPv4 targets"));
        }
    }
    if user_id.len() > 255 {
        return Err(other("SOCKS4 user id too long"));
    }
    req.extend_from_slice(user_id.as_bytes());
    req.push(0);
    if ip.is_none() && remote_dns {
        req.extend_from_slice(host.as_bytes());
        req.push(0);
    }
    stream.write_all(&req)?;

    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply)?;
    // RFC 1928 predecessor: the reply version byte is 0, not 4.
    if reply[0] != 0x00 {
        return Err(other("malformed SOCKS4 reply"));
    }
    match reply[1] {
        0x5a => Ok(()),
        0x5b => Err(other("SOCKS4 proxy rejected the request")),
        0x5c => Err(other("SOCKS4 proxy could not reach the identd service")),
        0x5d => Err(other("SOCKS4 proxy rejected the user id")),
        _ => Err(other("SOCKS4 proxy refused the connection")),
    }
}

/// SOCKS5 (and 5h with `remote_dns`) CONNECT handshake, with optional
/// username/password authentication (RFC 1928, RFC 1929).
pub(crate) fn socks5_handshake(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<&(String, String)>,
    remote_dns: bool,
    resolver: &dyn Resolve,
) -> io::Result<()> {
    // Method negotiation.
    match auth {
        Some(_) => stream.write_all(&[0x05, 0x02, 0x00, 0x02])?,
        None => stream.write_all(&[0x05, 0x01, 0x00])?,
    }
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 {
        return Err(other("not a SOCKS5 proxy"));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let (username, password) = auth.ok_or_else(|| {
                other("SOCKS5 proxy requires authentication")
            })?;
            if username.len() > 255 || password.len() > 255 {
                return Err(other("SOCKS5 credentials too long"));
            }
            let mut req = vec![0x01u8, username.len() as u8];
            req.extend_from_slice(username.as_bytes());
            req.push(password.len() as u8);
            req.extend_from_slice(password.as_bytes());
            stream.write_all(&req)?;
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply)?;
            // RFC 1929 subnegotiation carries its own version byte.
            if reply[0] != 0x01 {
                return Err(other("malformed SOCKS5 authentication reply"));
            }
            if reply[1] != 0x00 {
                return Err(other("SOCKS5 proxy rejected the credentials"));
            }
        }
        _ => return Err(other("SOCKS5 proxy accepted no supported auth method")),
    }

    // CONNECT request.
    let mut req = vec![0x05u8, 0x01, 0x00];
    let ip = host.parse::<IpAddr>().ok();
    match (ip, remote_dns) {
        (Some(IpAddr::V4(v4)), _) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        (Some(IpAddr::V6(v6)), _) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        (None, true) => {
            if host.len() > 255 {
                return Err(other("SOCKS5 target hostname too long"));
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
        (None, false) => match resolve_all(resolver, host, port)?[0] {
            SocketAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.ip().octets());
            }
        },
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(other("malformed SOCKS5 reply"));
    }
    if head[1] != 0x00 {
        return Err(other(match head[1] {
            0x01 => "SOCKS5 proxy reported a general failure",
            0x02 => "SOCKS5 proxy denied the connection by policy",
            0x03 => "SOCKS5 proxy reported the network as unreachable",
            0x04 => "SOCKS5 proxy reported the host as unreachable",
            0x05 => "SOCKS5 proxy reported the connection as refused",
            0x06 => "SOCKS5 proxy reported the TTL as expired",
            0x07 => "SOCKS5 proxy does not support the CONNECT command",
            0x08 => "SOCKS5 proxy does not support the address type",
            _ => "SOCKS5 proxy refused the connection",
        }));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize
        }
        _ => return Err(other("malformed SOCKS5 reply")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest)?;
    Ok(())
}
