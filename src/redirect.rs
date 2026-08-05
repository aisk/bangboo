//! Redirect Handling
//!
//! By default, a `Client` will automatically handle HTTP redirects, having a
//! maximum redirect chain of 10 hops. To customize this behavior, a
//! `redirect::Policy` can be used with a `ClientBuilder`.

/// A type that controls the policy on how to handle the following of redirects.
#[derive(Debug)]
pub struct Policy {
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Limit(usize),
    None,
}

impl Policy {
    /// Create a `Policy` with a maximum number of redirects.
    ///
    /// An error will be returned if the max is reached.
    pub fn limited(max: usize) -> Self {
        Policy {
            kind: Kind::Limit(max),
        }
    }

    /// Create a `Policy` that does not follow any redirect.
    pub fn none() -> Self {
        Policy { kind: Kind::None }
    }

    /// Returns the maximum number of redirects to follow, or `None` if
    /// redirects are not followed at all.
    pub(crate) fn max_redirects(&self) -> Option<usize> {
        match self.kind {
            Kind::Limit(max) => Some(max),
            Kind::None => None,
        }
    }
}

impl Default for Policy {
    fn default() -> Policy {
        // Follow up to 10 redirects, same as reqwest.
        Policy::limited(10)
    }
}
