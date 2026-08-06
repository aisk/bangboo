//! Redirect Handling
//!
//! By default, a `Client` will automatically handle HTTP redirects, having a
//! maximum redirect chain of 10 hops. To customize this behavior, a
//! `redirect::Policy` can be used with a `ClientBuilder`.

use std::fmt;

use http::StatusCode;
use url::Url;

use crate::error::BoxError;

/// A type that controls the policy on how to handle the following of redirects.
pub struct Policy {
    inner: PolicyKind,
}

enum PolicyKind {
    Custom(Box<dyn Fn(Attempt) -> Action + Send + Sync + 'static>),
    Limit(usize),
    None,
}

impl Policy {
    /// Create a `Policy` with a maximum number of redirects.
    ///
    /// An `Error` will be returned if the max is reached.
    pub fn limited(max: usize) -> Self {
        Policy {
            inner: PolicyKind::Limit(max),
        }
    }

    /// Create a `Policy` that does not follow any redirect.
    pub fn none() -> Self {
        Policy {
            inner: PolicyKind::None,
        }
    }

    /// Create a custom `Policy` using the passed function.
    ///
    /// # Note
    ///
    /// The default `Policy` handles a maximum loop chain, but the custom
    /// variant does not do that for you automatically. The custom policy
    /// should have some way of handling those.
    ///
    /// Information on the next request and previous requests can be found
    /// on the [`Attempt`] argument passed to the closure.
    ///
    /// Actions can be conveniently created from methods on the
    /// [`Attempt`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bangboo::{Error, redirect};
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let custom = redirect::Policy::custom(|attempt| {
    ///     if attempt.previous().len() > 5 {
    ///         attempt.error("too many redirects")
    ///     } else if attempt.url().host_str() == Some("example.domain") {
    ///         // prevent redirects to 'example.domain'
    ///         attempt.stop()
    ///     } else {
    ///         attempt.follow()
    ///     }
    /// });
    /// let client = bangboo::Client::builder()
    ///     .redirect(custom)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom<T>(policy: T) -> Self
    where
        T: Fn(Attempt) -> Action + Send + Sync + 'static,
    {
        Policy {
            inner: PolicyKind::Custom(Box::new(policy)),
        }
    }

    /// Apply this policy to a redirect attempt.
    pub fn redirect(&self, attempt: Attempt) -> Action {
        match self.inner {
            PolicyKind::Custom(ref custom) => custom(attempt),
            PolicyKind::Limit(max) => {
                // The first URL in `previous` is the original request, so a
                // limit of 10 means at most 10 hops after it.
                if attempt.previous.len() > max {
                    attempt.error(TooManyRedirects)
                } else {
                    attempt.follow()
                }
            }
            PolicyKind::None => attempt.stop(),
        }
    }

    /// Whether this policy can ever follow a redirect. `false` only for
    /// `Policy::none()`, letting the client skip redirect handling (and its
    /// strict `Location` parsing) entirely.
    pub(crate) fn follows_redirects(&self) -> bool {
        !matches!(self.inner, PolicyKind::None)
    }

    pub(crate) fn check(&self, status: StatusCode, next: &Url, previous: &[Url]) -> ActionKind {
        self.redirect(Attempt {
            status,
            next,
            previous,
        })
        .inner
    }
}

impl Default for Policy {
    fn default() -> Policy {
        // Follow up to 10 redirects, same as reqwest.
        Policy::limited(10)
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner {
            PolicyKind::Custom(..) => f.write_str("Policy::Custom"),
            PolicyKind::Limit(max) => f.debug_tuple("Policy::Limit").field(&max).finish(),
            PolicyKind::None => f.write_str("Policy::None"),
        }
    }
}

/// A type that holds information on the next request and previous requests
/// in redirect chain.
#[derive(Debug)]
pub struct Attempt<'a> {
    status: StatusCode,
    next: &'a Url,
    previous: &'a [Url],
}

impl<'a> Attempt<'a> {
    /// Get the type of redirect.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the next URL to redirect to.
    pub fn url(&self) -> &Url {
        self.next
    }

    /// Get the list of previous URLs that have already been requested in
    /// this chain.
    pub fn previous(&self) -> &[Url] {
        self.previous
    }

    /// Returns an action meaning bangboo should follow the next URL.
    pub fn follow(self) -> Action {
        Action {
            inner: ActionKind::Follow,
        }
    }

    /// Returns an action meaning bangboo should not follow the next URL.
    ///
    /// The 30x response will be returned as the `Ok` result.
    pub fn stop(self) -> Action {
        Action {
            inner: ActionKind::Stop,
        }
    }

    /// Returns an action failing the redirect with an error.
    ///
    /// The `Error` will be returned for the result of the sent request.
    pub fn error<E: Into<BoxError>>(self, error: E) -> Action {
        Action {
            inner: ActionKind::Error(error.into()),
        }
    }
}

/// An action to perform when a redirect status code is found.
#[derive(Debug)]
pub struct Action {
    inner: ActionKind,
}

#[derive(Debug)]
pub(crate) enum ActionKind {
    Follow,
    Stop,
    Error(BoxError),
}

#[derive(Debug)]
struct TooManyRedirects;

impl fmt::Display for TooManyRedirects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("too many redirects")
    }
}

impl std::error::Error for TooManyRedirects {}
