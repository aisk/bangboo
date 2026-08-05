use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::connect::Conn;

/// Identifies which idle connections may serve a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    pub(crate) https: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
}

struct Idle {
    conn: Conn,
    since: Instant,
}

/// A simple keep-alive connection pool.
pub(crate) struct Pool {
    idle_timeout: Option<Duration>,
    max_idle_per_host: usize,
    inner: Mutex<HashMap<PoolKey, Vec<Idle>>>,
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
        while let Some(idle) = list.pop() {
            if let Some(timeout) = self.idle_timeout
                && idle.since.elapsed() > timeout {
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
        let list = inner.entry(key).or_default();
        if list.len() >= self.max_idle_per_host {
            list.remove(0);
        }
        list.push(Idle {
            conn,
            since: Instant::now(),
        });
    }
}
