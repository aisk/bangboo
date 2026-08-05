use std::fmt;
use std::fs::File;
use std::io::Read;

use bytes::Bytes;

/// The body of a `Request`.
///
/// In most cases, this is created indirectly via the `From` implementations
/// (`String`, `Vec<u8>`, `&'static str`, `File`, ...), or by
/// [`RequestBuilder::body`][crate::RequestBuilder::body].
pub struct Body {
    kind: Kind,
}

enum Kind {
    Bytes(Bytes),
    Reader(Box<dyn Read + Send>, Option<u64>),
}

pub(crate) enum BodyKindMut<'a> {
    Bytes(&'a [u8]),
    Reader {
        reader: &'a mut (dyn Read + Send),
        len: Option<u64>,
    },
}

impl Body {
    /// Instantiate a `Body` from a reader.
    ///
    /// # Note
    ///
    /// While allowing for many types to be used, these bodies do not have
    /// a way to reset to the beginning and be reused. This means that when
    /// encountering a 307 or 308 status code, instead of repeating the
    /// request at the new location, the `Error` will be returned. Also, a
    /// body constructed from a reader is sent with
    /// `Transfer-Encoding: chunked`; use [`Body::sized`] if the length is
    /// known up front.
    pub fn new<R: Read + Send + 'static>(reader: R) -> Body {
        Body {
            kind: Kind::Reader(Box::new(reader), None),
        }
    }

    /// Create a `Body` from a `Read` where the size is known in advance,
    /// but the data should not be fully loaded into memory. This will
    /// set the `Content-Length` header and stream from the `Read`.
    pub fn sized<R: Read + Send + 'static>(reader: R, len: u64) -> Body {
        Body {
            kind: Kind::Reader(Box::new(reader), Some(len)),
        }
    }

    /// Returns the body as a byte slice if the body is already buffered in
    /// memory. For streamed requests this method returns `None`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self.kind {
            Kind::Bytes(ref bytes) => Some(bytes.as_ref()),
            Kind::Reader(..) => None,
        }
    }

    /// Converts streamed body to its buffered equivalent and returns the
    /// buffered value.
    ///
    /// For requests that are already buffered, this has no effect.
    pub fn buffer(&mut self) -> crate::Result<&[u8]> {
        match self.kind {
            Kind::Reader(ref mut reader, maybe_len) => {
                let mut bytes = if let Some(len) = maybe_len {
                    Vec::with_capacity(len.min(1024 * 1024) as usize)
                } else {
                    Vec::new()
                };
                reader
                    .read_to_end(&mut bytes)
                    .map_err(crate::error::body)?;
                self.kind = Kind::Bytes(bytes.into());
                self.buffer()
            }
            Kind::Bytes(ref bytes) => Ok(bytes.as_ref()),
        }
    }

    pub(crate) fn len(&self) -> Option<u64> {
        match self.kind {
            Kind::Bytes(ref bytes) => Some(bytes.len() as u64),
            Kind::Reader(_, len) => len,
        }
    }

    pub(crate) fn kind_mut(&mut self) -> BodyKindMut<'_> {
        match self.kind {
            Kind::Bytes(ref bytes) => BodyKindMut::Bytes(bytes.as_ref()),
            Kind::Reader(ref mut reader, len) => BodyKindMut::Reader {
                reader: &mut **reader,
                len,
            },
        }
    }

    /// Attempts to clone the body; only buffered bodies can be cloned.
    pub(crate) fn try_clone(&self) -> Option<Body> {
        match self.kind {
            Kind::Bytes(ref bytes) => Some(Body {
                kind: Kind::Bytes(bytes.clone()),
            }),
            Kind::Reader(..) => None,
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Body {
        Body {
            kind: Kind::Bytes(v.into()),
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        s.into_bytes().into()
    }
}

impl From<&'static [u8]> for Body {
    fn from(s: &'static [u8]) -> Body {
        Body {
            kind: Kind::Bytes(Bytes::from_static(s)),
        }
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Body {
        s.as_bytes().into()
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Body {
        Body {
            kind: Kind::Bytes(b),
        }
    }
}

impl From<File> for Body {
    fn from(f: File) -> Body {
        let len = f.metadata().map(|m| m.len()).ok();
        Body {
            kind: Kind::Reader(Box::new(f), len),
        }
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Kind::Bytes(ref bytes) => f.debug_struct("Body").field("len", &bytes.len()).finish(),
            Kind::Reader(_, ref len) => f
                .debug_struct("Body")
                .field("reader", &"..")
                .field("len", len)
                .finish(),
        }
    }
}
