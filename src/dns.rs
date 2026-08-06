//! DNS resolution
//!
//! By default hostnames are resolved with the system resolver
//! (`std::net::ToSocketAddrs`, i.e. `getaddrinfo`). A custom resolver can
//! be supplied with [`ClientBuilder::dns_resolver`], and individual domains
//! can be overridden with [`ClientBuilder::resolve`] and
//! [`ClientBuilder::resolve_to_addrs`].
//!
//! [`ClientBuilder::dns_resolver`]: crate::ClientBuilder::dns_resolver
//! [`ClientBuilder::resolve`]: crate::ClientBuilder::resolve
//! [`ClientBuilder::resolve_to_addrs`]: crate::ClientBuilder::resolve_to_addrs

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

/// A custom, synchronous DNS resolver.
pub trait Resolve: Send + Sync {
    /// Resolve a hostname to a list of socket addresses.
    ///
    /// A returned address with port `0` is connected to on the port of the
    /// URL being requested; a non-zero port overrides it.
    fn resolve(&self, name: &str) -> io::Result<Vec<SocketAddr>>;
}

/// The default resolver: the system's `getaddrinfo` via
/// `std::net::ToSocketAddrs`.
pub(crate) struct GaiResolver;

impl Resolve for GaiResolver {
    fn resolve(&self, name: &str) -> io::Result<Vec<SocketAddr>> {
        // NOTE: std's resolver offers no timeout hook, so DNS resolution is
        // not covered by connect_timeout.
        Ok((name, 0u16).to_socket_addrs()?.collect())
    }
}

/// Wraps a resolver with a fixed set of per-domain overrides
/// (`ClientBuilder::resolve` / `resolve_to_addrs`).
pub(crate) struct ResolverWithOverrides {
    pub(crate) overrides: HashMap<String, Vec<SocketAddr>>,
    pub(crate) fallback: Arc<dyn Resolve>,
}

impl Resolve for ResolverWithOverrides {
    fn resolve(&self, name: &str) -> io::Result<Vec<SocketAddr>> {
        match self.overrides.get(&name.to_ascii_lowercase()) {
            Some(addrs) => Ok(addrs.clone()),
            None => self.fallback.resolve(name),
        }
    }
}
