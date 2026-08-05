use std::error::Error as StdError;
use std::fmt;
use std::io;

use http::StatusCode;
use url::Url;

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

/// A `Result` alias where the `Err` case is `bangboo::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// The errors that may occur when processing a `Request`.
pub struct Error {
    inner: Box<Inner>,
}

struct Inner {
    kind: Kind,
    source: Option<BoxError>,
    url: Option<Url>,
}

#[derive(Debug)]
pub(crate) enum Kind {
    Builder,
    Request,
    Connect,
    Redirect,
    Status(StatusCode),
    Body,
    Decode,
    Timeout,
}

impl Error {
    pub(crate) fn new(kind: Kind, source: Option<BoxError>) -> Error {
        Error {
            inner: Box::new(Inner {
                kind,
                source,
                url: None,
            }),
        }
    }

    /// Returns a possible URL related to this error.
    pub fn url(&self) -> Option<&Url> {
        self.inner.url.as_ref()
    }

    /// Returns a mutable reference to the URL related to this error.
    pub fn url_mut(&mut self) -> Option<&mut Url> {
        self.inner.url.as_mut()
    }

    /// Adds a url related to this error (overwriting any existing).
    pub fn with_url(mut self, url: Url) -> Self {
        self.inner.url = Some(url);
        self
    }

    /// Strips the related URL from this error (if there is one).
    pub fn without_url(mut self) -> Self {
        self.inner.url = None;
        self
    }

    /// Returns true if the error is from a type builder.
    pub fn is_builder(&self) -> bool {
        matches!(self.inner.kind, Kind::Builder)
    }

    /// Returns true if the error is from a `RedirectPolicy`.
    pub fn is_redirect(&self) -> bool {
        matches!(self.inner.kind, Kind::Redirect)
    }

    /// Returns true if the error is from `Response::error_for_status`.
    pub fn is_status(&self) -> bool {
        matches!(self.inner.kind, Kind::Status(_))
    }

    /// Returns true if the error is related to a timeout.
    pub fn is_timeout(&self) -> bool {
        if matches!(self.inner.kind, Kind::Timeout) {
            return true;
        }
        let mut source = self.source();
        while let Some(err) = source {
            if let Some(io_err) = err.downcast_ref::<io::Error>()
                && is_timeout_io(io_err) {
                    return true;
                }
            source = err.source();
        }
        false
    }

    /// Returns true if the error is related to the request.
    pub fn is_request(&self) -> bool {
        matches!(self.inner.kind, Kind::Request)
    }

    /// Returns true if the error is related to connect.
    pub fn is_connect(&self) -> bool {
        matches!(self.inner.kind, Kind::Connect)
    }

    /// Returns true if the error is related to the request or response body.
    pub fn is_body(&self) -> bool {
        matches!(self.inner.kind, Kind::Body)
    }

    /// Returns true if the error is related to decoding the response's body.
    pub fn is_decode(&self) -> bool {
        matches!(self.inner.kind, Kind::Decode)
    }

    /// Returns the status code, if the error was generated from a response.
    pub fn status(&self) -> Option<StatusCode> {
        match self.inner.kind {
            Kind::Status(code) => Some(code),
            _ => None,
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("bangboo::Error");
        builder.field("kind", &self.inner.kind);
        if let Some(ref url) = self.inner.url {
            builder.field("url", &url.as_str());
        }
        if let Some(ref source) = self.inner.source {
            builder.field("source", source);
        }
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.kind {
            Kind::Builder => f.write_str("builder error")?,
            Kind::Request => f.write_str("error sending request")?,
            Kind::Connect => f.write_str("error connecting")?,
            Kind::Redirect => f.write_str("error following redirect")?,
            Kind::Status(code) => {
                let prefix = if code.is_client_error() {
                    "HTTP status client error"
                } else {
                    "HTTP status server error"
                };
                write!(f, "{prefix} ({code})")?;
            }
            Kind::Body => f.write_str("request or response body error")?,
            Kind::Decode => f.write_str("error decoding response body")?,
            Kind::Timeout => f.write_str("operation timed out")?,
        }
        if let Some(url) = &self.inner.url {
            write!(f, " for url ({url})")?;
        }
        if let Some(source) = &self.inner.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner.source.as_ref().map(|e| &**e as _)
    }
}

fn is_timeout_io(err: &io::Error) -> bool {
    // With socket timeouts (SO_RCVTIMEO/SO_SNDTIMEO), reads and writes fail
    // with WouldBlock on unix and TimedOut on windows.
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

// constructors, used internally

pub(crate) fn builder<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Builder, Some(e.into()))
}

pub(crate) fn connect<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Connect, Some(e.into()))
}

pub(crate) fn redirect<E: Into<BoxError>>(e: E, url: Url) -> Error {
    Error::new(Kind::Redirect, Some(e.into())).with_url(url)
}

pub(crate) fn status_code(url: Url, status: StatusCode) -> Error {
    Error::new(Kind::Status(status), None).with_url(url)
}

pub(crate) fn body<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Body, Some(e.into()))
}

pub(crate) fn decode<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Decode, Some(e.into()))
}

/// Map an io error, recognizing socket timeouts.
pub(crate) fn from_io(e: io::Error) -> Error {
    if is_timeout_io(&e) {
        Error::new(Kind::Timeout, Some(e.into()))
    } else {
        Error::new(Kind::Request, Some(e.into()))
    }
}
