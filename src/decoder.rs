//! Transparent response body decompression.
//!
//! When any of the `gzip`, `deflate`, `brotli` or `zstd` features is
//! enabled and the corresponding `ClientBuilder` option is on, an
//! `accept-encoding` header is added to requests that don't already have
//! one, and matching response bodies are decoded on the fly.

use std::io::{self, Read};

use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderMap, HeaderValue, TRANSFER_ENCODING};

use crate::response::BodyReader;

/// Which content codings the client advertises and decodes.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Accepts {
    pub(crate) gzip: bool,
    pub(crate) deflate: bool,
    pub(crate) brotli: bool,
    pub(crate) zstd: bool,
}

impl Accepts {
    pub(crate) fn is_empty(&self) -> bool {
        !self.gzip && !self.deflate && !self.brotli && !self.zstd
    }

    /// The `accept-encoding` value for these codings, or `None` if none are
    /// enabled.
    pub(crate) fn as_header(&self) -> Option<HeaderValue> {
        if self.is_empty() {
            return None;
        }
        let mut value = String::new();
        for (enabled, name) in [
            (self.gzip, "gzip"),
            (self.deflate, "deflate"),
            (self.brotli, "br"),
            (self.zstd, "zstd"),
        ] {
            if enabled {
                if !value.is_empty() {
                    value.push_str(", ");
                }
                value.push_str(name);
            }
        }
        Some(HeaderValue::from_str(&value).expect("coding names are valid header values"))
    }

    fn supports(&self, coding: &str) -> bool {
        match coding {
            #[cfg(feature = "gzip")]
            "gzip" | "x-gzip" => self.gzip,
            #[cfg(feature = "deflate")]
            "deflate" => self.deflate,
            #[cfg(feature = "brotli")]
            "br" => self.brotli,
            #[cfg(feature = "zstd")]
            "zstd" => self.zstd,
            _ => false,
        }
    }
}

/// Reads a response body, decoding the content codings the client asked
/// for.
pub(crate) struct Decoder {
    inner: Inner,
}

enum Inner {
    Plain(BodyReader),
    Decoding(Box<dyn Read + Send>),
    /// A body that never came off a connection, e.g. a `Response` built
    /// from an `http::Response`.
    Memory(io::Cursor<bytes::Bytes>),
}

impl Decoder {
    pub(crate) fn plain(body: BodyReader) -> Decoder {
        Decoder {
            inner: Inner::Plain(body),
        }
    }

    pub(crate) fn in_memory(bytes: bytes::Bytes) -> Decoder {
        Decoder {
            inner: Inner::Memory(io::Cursor::new(bytes)),
        }
    }

    /// Wraps `body` in decoders for the codings listed in the response's
    /// `content-encoding`, and rewrites the headers that no longer describe
    /// the body the caller sees.
    ///
    /// Codings that were not negotiated are left in place: peeling stops at
    /// the first one the client cannot decode, and `content-encoding` keeps
    /// the remainder.
    ///
    /// `has_body` is false for responses that carry no body at all (HEAD,
    /// 1xx, 204, 304). Those are never decoded: servers routinely echo the
    /// entity's `Content-Encoding` on them, and handing an empty stream to
    /// a decompressor fails with an unexpected-EOF error instead of
    /// yielding the empty body the caller expects.
    pub(crate) fn detect(
        body: BodyReader,
        headers: &mut HeaderMap,
        accepts: Accepts,
        has_body: bool,
    ) -> Decoder {
        if accepts.is_empty() || !has_body {
            return Decoder::plain(body);
        }
        let codings: Vec<String> = headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(|coding| coding.trim().to_ascii_lowercase())
            .filter(|coding| !coding.is_empty() && coding != "identity")
            .collect();
        if codings.is_empty() {
            return Decoder::plain(body);
        }

        // Codings are listed in the order they were applied, so the last
        // one is the outermost on the wire and must be decoded first.
        let peelable = codings
            .iter()
            .rev()
            .take_while(|coding| accepts.supports(coding))
            .count();
        if peelable == 0 {
            return Decoder::plain(body);
        }

        let mut reader: Box<dyn Read + Send> = Box::new(body);
        for coding in codings[codings.len() - peelable..].iter().rev() {
            reader = wrap(coding, reader);
        }
        strip_encoding_headers(headers, &codings[..codings.len() - peelable]);
        Decoder {
            inner: Inner::Decoding(reader),
        }
    }

    /// Whether this decoder alters the bytes, i.e. whether the response's
    /// `content-length` still describes what the caller will read.
    pub(crate) fn is_decoding(&self) -> bool {
        matches!(self.inner, Inner::Decoding(_))
    }
}

/// Wraps `reader` in the decoder for a single content coding. Only called
/// for codings `Accepts::supports` returned true for, so every arm here is
/// reachable exactly when its feature is on.
#[allow(unused_variables, unreachable_code)]
fn wrap(coding: &str, reader: Box<dyn Read + Send>) -> Box<dyn Read + Send> {
    match coding {
        #[cfg(feature = "gzip")]
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(reader)),
        #[cfg(feature = "deflate")]
        "deflate" => Box::new(DeflateReader::new(reader)),
        #[cfg(feature = "brotli")]
        "br" => Box::new(brotli::Decompressor::new(reader, 8 * 1024)),
        #[cfg(feature = "zstd")]
        "zstd" => Box::new(
            zstd::stream::read::Decoder::new(reader).expect("zstd decoder init is infallible"),
        ),
        _ => unreachable!("unsupported coding reached the decoder: {coding}"),
    }
}

/// `deflate` responses in the wild come both zlib-wrapped (as the RFC says)
/// and as raw deflate streams. The first bytes decide which decoder to use.
#[cfg(feature = "deflate")]
struct DeflateReader {
    inner: DeflateInner,
}

/// The sniffed bytes replayed ahead of the rest of the body.
#[cfg(feature = "deflate")]
type Replayed = std::io::Chain<io::Cursor<Vec<u8>>, Box<dyn Read + Send>>;

#[cfg(feature = "deflate")]
enum DeflateInner {
    /// Not enough bytes read yet to tell the two framings apart.
    Sniffing {
        reader: Option<Box<dyn Read + Send>>,
        peeked: Vec<u8>,
    },
    Zlib(Box<flate2::read::ZlibDecoder<Replayed>>),
    Raw(Box<flate2::read::DeflateDecoder<Replayed>>),
}

#[cfg(feature = "deflate")]
impl DeflateReader {
    fn new(reader: Box<dyn Read + Send>) -> DeflateReader {
        DeflateReader {
            inner: DeflateInner::Sniffing {
                reader: Some(reader),
                peeked: Vec::with_capacity(2),
            },
        }
    }
}

#[cfg(feature = "deflate")]
impl Read for DeflateReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match &mut self.inner {
                DeflateInner::Sniffing { reader, peeked } => {
                    let source = reader.as_mut().expect("reader taken while sniffing");
                    while peeked.len() < 2 {
                        let mut byte = [0u8; 1];
                        match source.read(&mut byte)? {
                            0 => break,
                            _ => peeked.push(byte[0]),
                        }
                    }
                    let zlib = peeked.len() == 2 && is_zlib_header(peeked[0], peeked[1]);
                    let head = io::Cursor::new(std::mem::take(peeked));
                    let chained = head.chain(reader.take().expect("reader present"));
                    self.inner = if zlib {
                        DeflateInner::Zlib(Box::new(flate2::read::ZlibDecoder::new(chained)))
                    } else {
                        DeflateInner::Raw(Box::new(flate2::read::DeflateDecoder::new(chained)))
                    };
                }
                DeflateInner::Zlib(decoder) => return decoder.read(buf),
                DeflateInner::Raw(decoder) => return decoder.read(buf),
            }
        }
    }
}

/// RFC 1950 §2.2: CMF/FLG, with CM=8 and the two bytes forming a multiple
/// of 31 when read big-endian.
#[cfg(feature = "deflate")]
fn is_zlib_header(cmf: u8, flg: u8) -> bool {
    cmf & 0x0f == 8 && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
}

impl Read for Decoder {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Plain(body) => body.read(buf),
            Inner::Decoding(reader) => reader.read(buf),
            Inner::Memory(cursor) => cursor.read(buf),
        }
    }
}

/// Rewrites the headers that described the encoded body: the length no
/// longer matches, and only the codings still applied stay listed.
fn strip_encoding_headers(headers: &mut HeaderMap, remaining: &[String]) {
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(CONTENT_ENCODING);
    if !remaining.is_empty()
        && let Ok(value) = HeaderValue::from_str(&remaining.join(", "))
    {
        headers.insert(CONTENT_ENCODING, value);
    }
}
