use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::connect::Conn;

/// Identifies which idle connections may serve a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    pub(crate) https: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The proxy the connection runs through (`ProxyScheme::pool_id`), if
    /// any: tunneled/forwarded connections must never be mixed with direct
    /// ones or with those of another proxy.
    pub(crate) proxy: Option<String>,
}

struct Idle {
    conn: Conn,
    since: Instant,
}

/// A simple keep-alive connection pool.
pub(crate) struct Pool {
    idle_timeout: Option<Duration>,
    max_idle_per_host: usize,
    inner: Mutex<HashMap<PoolKey, VecDeque<Idle>>>,
}

impl Pool {
    pub(crate) fn new(idle_timeout: Option<Duration>, max_idle_per_host: usize) -> Pool {
        Pool {
            idle_timeout,
            max_idle_per_host,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn checkout(&self, key: &PoolKey) -> Option<Conn> {
        let mut inner = self.inner.lock().unwrap();
        let list = inner.get_mut(key)?;
        let mut found = None;
        // Most-recently-used first: it is the most likely to still be alive.
        while let Some(idle) = list.pop_back() {
            if let Some(timeout) = self.idle_timeout
                && idle.since.elapsed() > timeout
            {
                continue;
            }
            if idle.conn.is_reusable_now() {
                found = Some(idle.conn);
                break;
            }
        }
        if list.is_empty() {
            inner.remove(key);
        }
        found
    }

    pub(crate) fn checkin(&self, key: PoolKey, conn: Conn) {
        if self.max_idle_per_host == 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        // Idle entries are otherwise only reaped when their own key is
        // checked out again, so a client that talks to many hosts once each
        // would hold every socket open forever.
        if let Some(timeout) = self.idle_timeout {
            inner.retain(|_, list| {
                list.retain(|idle| idle.since.elapsed() <= timeout);
                !list.is_empty()
            });
        }
        let list = inner.entry(key).or_default();
        if list.len() >= self.max_idle_per_host {
            // Evict the oldest idle connection.
            list.pop_front();
        }
        list.push_back(Idle {
            conn,
            since: Instant::now(),
        });
    }

    /// Number of idle connections currently held, across all keys.
    #[cfg(test)]
    pub(crate) fn idle_count(&self) -> usize {
        self.inner.lock().unwrap().values().map(|l| l.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host: &str) -> PoolKey {
        PoolKey {
            https: false,
            host: host.to_string(),
            port: 80,
            proxy: None,
        }
    }

    /// A client that contacts many hosts once each must not accumulate
    /// idle sockets forever: expired entries are swept on every check-in,
    /// not only when their own key is requested again.
    #[test]
    fn expired_idle_entries_are_swept_across_keys() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = Pool::new(Some(Duration::from_millis(1)), 10);

        for i in 0..5 {
            let stream = TcpStream::connect(addr).unwrap();
            let _accepted = listener.accept().unwrap();
            pool.checkin(key(&format!("host{i}")), Conn::for_test(stream));
        }
        assert!(pool.idle_count() > 0);

        std::thread::sleep(Duration::from_millis(10));
        let stream = TcpStream::connect(addr).unwrap();
        let _accepted = listener.accept().unwrap();
        pool.checkin(key("fresh"), Conn::for_test(stream));

        // Only the just-added connection survives.
        assert_eq!(pool.idle_count(), 1);
    }
}
