//! multipart/form-data
//!
//! Requires the `multipart` feature. A [`Form`] is sent with
//! [`RequestBuilder::multipart`][crate::RequestBuilder::multipart].
//!
//! ```rust,no_run
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let form = bangboo::multipart::Form::new()
//!     .text("username", "seanmonstar")
//!     .file("photo", "/path/to/photo.png")?;
//!
//! let client = bangboo::Client::new();
//! let res = client
//!     .post("http://localhost/multipart")
//!     .multipart(form)
//!     .send()?;
//! # Ok(())
//! # }
//! ```

use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::Path;

use http::HeaderMap;
use mime::Mime;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

/// A multipart/form-data request body.
pub struct Form {
    boundary: String,
    fields: Vec<(Cow<'static, str>, Part)>,
    percent_encoding: PercentEncoding,
}

/// A field in a multipart form.
pub struct Part {
    value: PartValue,
    mime: Option<Mime>,
    file_name: Option<Cow<'static, str>>,
    headers: HeaderMap,
}

enum PartValue {
    Bytes(Cow<'static, [u8]>),
    /// A streaming source, with its length when known.
    Reader(Box<dyn Read + Send>, Option<u64>),
}

/// How field names and file names are escaped in the part headers.
#[derive(Clone, Copy, Debug)]
enum PercentEncoding {
    PathSegment,
    AttrChar,
    NoOp,
}

// https://url.spec.whatwg.org/#path-percent-encode-set
const PATH_SEGMENT: &AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'%')
    .add(b'/');

// https://datatracker.ietf.org/doc/html/rfc5987#section-3.2.1 (attr-char)
const ATTR_CHAR: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'!')
    .remove(b'#')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b'-')
    .remove(b'.')
    .remove(b'^')
    .remove(b'_')
    .remove(b'`')
    .remove(b'|')
    .remove(b'~');

impl Default for Form {
    fn default() -> Self {
        Self::new()
    }
}

impl Form {
    /// Creates a new async Form without any content.
    pub fn new() -> Form {
        Form {
            boundary: generate_boundary(),
            fields: Vec::new(),
            percent_encoding: PercentEncoding::PathSegment,
        }
    }

    /// Get the boundary that this form will use.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Add a data field with supplied name and value.
    pub fn text<T, U>(self, name: T, value: U) -> Form
    where
        T: Into<Cow<'static, str>>,
        U: Into<Cow<'static, str>>,
    {
        self.part(name, Part::text(value))
    }

    /// Adds a file field.
    ///
    /// The path will be used to try to guess the filename and mime.
    ///
    /// # Errors
    ///
    /// Errors when the file cannot be opened.
    pub fn file<T, U>(self, name: T, path: U) -> io::Result<Form>
    where
        T: Into<Cow<'static, str>>,
        U: AsRef<Path>,
    {
        Ok(self.part(name, Part::file(path)?))
    }

    /// Adds a customized Part.
    pub fn part<T>(mut self, name: T, part: Part) -> Form
    where
        T: Into<Cow<'static, str>>,
    {
        self.fields.push((name.into(), part));
        self
    }

    /// Configure this `Form` to percent-encode using the `path-segment`
    /// rules. This is the default.
    pub fn percent_encode_path_segment(mut self) -> Form {
        self.percent_encoding = PercentEncoding::PathSegment;
        self
    }

    /// Configure this `Form` to percent-encode using the `attr-char` rules.
    pub fn percent_encode_attr_chars(mut self) -> Form {
        self.percent_encoding = PercentEncoding::AttrChar;
        self
    }

    /// Configure this `Form` to skip percent-encoding.
    pub fn percent_encode_noop(mut self) -> Form {
        self.percent_encoding = PercentEncoding::NoOp;
        self
    }

    /// Consume this form and return a `Read` over its serialization.
    pub fn into_reader(self) -> impl Read + Send {
        FormReader::new(self)
    }

    /// The total length of the serialized form, if every part has a known
    /// length.
    pub(crate) fn compute_length(&self) -> Option<u64> {
        let mut total = 0u64;
        for (name, part) in &self.fields {
            let len = match &part.value {
                PartValue::Bytes(bytes) => bytes.len() as u64,
                PartValue::Reader(_, len) => (*len)?,
            };
            total += self.part_header(name, part).len() as u64 + len + 2;
        }
        Some(total + self.boundary.len() as u64 + 6)
    }

    pub(crate) fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// The `--boundary` line plus headers that precede a part's data.
    fn part_header(&self, name: &str, part: &Part) -> Vec<u8> {
        let mut header = Vec::with_capacity(128);
        header.extend_from_slice(b"--");
        header.extend_from_slice(self.boundary.as_bytes());
        header.extend_from_slice(b"\r\ncontent-disposition: form-data; name=");
        header.extend_from_slice(self.encode_param(name).as_bytes());
        if let Some(file_name) = &part.file_name {
            header.extend_from_slice(b"; filename=");
            header.extend_from_slice(self.encode_param(file_name).as_bytes());
        }
        if let Some(mime) = &part.mime {
            header.extend_from_slice(b"\r\ncontent-type: ");
            header.extend_from_slice(mime.as_ref().as_bytes());
        }
        for (key, value) in part.headers.iter() {
            header.extend_from_slice(b"\r\n");
            header.extend_from_slice(key.as_str().as_bytes());
            header.extend_from_slice(b": ");
            header.extend_from_slice(value.as_bytes());
        }
        header.extend_from_slice(b"\r\n\r\n");
        header
    }

    /// Quotes and escapes a `content-disposition` parameter value.
    fn encode_param(&self, value: &str) -> String {
        let escaped = match self.percent_encoding {
            PercentEncoding::PathSegment => {
                percent_encoding::utf8_percent_encode(value, PATH_SEGMENT).to_string()
            }
            PercentEncoding::AttrChar => {
                percent_encoding::utf8_percent_encode(value, ATTR_CHAR).to_string()
            }
            // Without percent-encoding the value still must not break out
            // of its quotes, nor inject header lines with CR/LF.
            PercentEncoding::NoOp => {
                percent_encoding::utf8_percent_encode(value, percent_encoding::CONTROLS)
                    .to_string()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            }
        };
        format!("\"{escaped}\"")
    }
}

impl fmt::Debug for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("Form");
        builder.field("boundary", &self.boundary);
        for (name, part) in &self.fields {
            builder.field(name, part);
        }
        builder.finish()
    }
}

impl Part {
    /// Makes a text parameter.
    pub fn text<T>(value: T) -> Part
    where
        T: Into<Cow<'static, str>>,
    {
        let value = match value.into() {
            Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
            Cow::Owned(s) => Cow::Owned(s.into_bytes()),
        };
        Part::new(PartValue::Bytes(value))
    }

    /// Makes a new parameter from arbitrary bytes.
    pub fn bytes<T>(value: T) -> Part
    where
        T: Into<Cow<'static, [u8]>>,
    {
        Part::new(PartValue::Bytes(value.into()))
    }

    /// Adds a generic reader.
    ///
    /// Does not set the filename or mime.
    pub fn reader<T: Read + Send + 'static>(value: T) -> Part {
        Part::new(PartValue::Reader(Box::new(value), None))
    }

    /// Adds a generic reader with a known length.
    ///
    /// Allows the form to compute its `Content-Length` instead of falling
    /// back to chunked framing. Does not set the filename or mime.
    pub fn reader_with_length<T: Read + Send + 'static>(value: T, length: u64) -> Part {
        Part::new(PartValue::Reader(Box::new(value), Some(length)))
    }

    /// Makes a file parameter.
    ///
    /// The filename and mime are guessed from `path`.
    ///
    /// # Errors
    ///
    /// Errors when the file cannot be opened.
    pub fn file<T: AsRef<Path>>(path: T) -> io::Result<Part> {
        let path = path.as_ref();
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned().into());
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        let file = File::open(path)?;
        let len = file.metadata().map(|meta| meta.len()).ok();
        Ok(Part {
            value: PartValue::Reader(Box::new(file), len),
            mime: Some(mime),
            file_name,
            headers: HeaderMap::new(),
        })
    }

    fn new(value: PartValue) -> Part {
        Part {
            value,
            mime: None,
            file_name: None,
            headers: HeaderMap::new(),
        }
    }

    /// Tries to set the mime of this part.
    pub fn mime_str(mut self, mime: &str) -> crate::Result<Part> {
        self.mime = Some(mime.parse().map_err(crate::error::builder)?);
        Ok(self)
    }

    /// Sets the filename, overriding any value that was guessed.
    pub fn file_name<T>(mut self, filename: T) -> Part
    where
        T: Into<Cow<'static, str>>,
    {
        self.file_name = Some(filename.into());
        self
    }

    /// Sets custom headers for the part.
    pub fn headers(mut self, headers: HeaderMap) -> Part {
        self.headers = headers;
        self
    }
}

impl fmt::Debug for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Part")
            .field("value", &"..")
            .field("mime", &self.mime)
            .field("file_name", &self.file_name)
            .field("headers", &self.headers)
            .finish()
    }
}

/// Streams a `Form`: for each field the part header, then its data, then a
/// CRLF; finally the closing boundary.
struct FormReader {
    /// Remaining fields, in reverse order so they can be popped.
    pending: Vec<(Vec<u8>, PartValue)>,
    current: Option<Box<dyn Read + Send>>,
    tail: Cursor<Vec<u8>>,
}

impl FormReader {
    fn new(mut form: Form) -> FormReader {
        let fields = std::mem::take(&mut form.fields);
        let mut pending: Vec<(Vec<u8>, PartValue)> = fields
            .into_iter()
            .map(|(name, part)| (form.part_header(&name, &part), part.value))
            .collect();
        pending.reverse();
        FormReader {
            pending,
            current: None,
            tail: Cursor::new(format!("--{}--\r\n", form.boundary).into_bytes()),
        }
    }
}

impl Read for FormReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(reader) = self.current.as_mut() {
                let n = reader.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                self.current = None;
            }
            match self.pending.pop() {
                Some((header, value)) => {
                    let head = Cursor::new(header);
                    let body: Box<dyn Read + Send> = match value {
                        PartValue::Bytes(bytes) => Box::new(Cursor::new(bytes.into_owned())),
                        PartValue::Reader(reader, _) => reader,
                    };
                    self.current =
                        Some(Box::new(head.chain(body).chain(Cursor::new(b"\r\n".to_vec()))));
                }
                None => return self.tail.read(buf),
            }
        }
    }
}

/// A random boundary that will not appear in any reasonable payload.
fn generate_boundary() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let a = rng.random::<u64>();
    let b = rng.random::<u64>();
    format!("{a:016x}-{b:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declared length must equal the bytes actually streamed: a
    /// Content-Length that disagrees with the body desyncs the connection.
    #[test]
    fn computed_length_matches_serialization() {
        let cases: Vec<fn() -> Form> = vec![
            Form::new,
            || Form::new().text("a", "1"),
            || {
                Form::new()
                    .text("a", "1")
                    .text("b", "")
                    .text("unicode-名前", "值")
            },
            || {
                let part = Part::bytes(&b"\x00\xff binary"[..])
                    .file_name("f.bin")
                    .mime_str("application/octet-stream")
                    .unwrap();
                Form::new().part("p", part)
            },
            || {
                let part = Part::reader_with_length(Cursor::new(b"0123456789".to_vec()), 10);
                Form::new().text("t", "x").part("r", part)
            },
            || {
                let mut headers = HeaderMap::new();
                headers.insert("x-a", "1".parse().unwrap());
                headers.insert("x-b", "2".parse().unwrap());
                Form::new().part("h", Part::text("v").headers(headers))
            },
            || Form::new().percent_encode_attr_chars().text("na me", "v"),
        ];

        for (i, make) in cases.iter().enumerate() {
            let declared = make().compute_length();
            let mut serialized = Vec::new();
            make().into_reader().read_to_end(&mut serialized).unwrap();
            assert_eq!(
                declared,
                Some(serialized.len() as u64),
                "case {i} length mismatch, body was:\n{}",
                String::from_utf8_lossy(&serialized)
            );
        }
    }

    /// Even with percent-encoding disabled, a field name must not be able
    /// to inject part headers or a boundary line.
    #[test]
    fn noop_encoding_still_blocks_crlf_injection() {
        let form = Form::new()
            .percent_encode_noop()
            .text("a\r\ncontent-type: text/html\r\n\r\ninjected", "v");
        let mut serialized = Vec::new();
        form.into_reader().read_to_end(&mut serialized).unwrap();
        let body = String::from_utf8_lossy(&serialized);
        // The CRLFs are escaped, so they cannot start a header line of
        // their own or end the part's header block early.
        assert!(
            !body.contains("\r\ncontent-type: text/html"),
            "body: {body}"
        );
        assert_eq!(body.matches("\r\n\r\n").count(), 1, "body: {body}");
    }

    /// A part whose length is unknown makes the whole form unsized.
    #[test]
    fn unsized_part_makes_form_unsized() {
        let form = Form::new()
            .text("known", "1")
            .part("unknown", Part::reader(Cursor::new(Vec::new())));
        assert_eq!(form.compute_length(), None);
    }
}
