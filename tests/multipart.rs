//! multipart/form-data bodies.
#![cfg(feature = "multipart")]

mod support;

use std::io::Write;

use support::{read_request, respond, server};

/// Runs `form` against a test server and returns the request head and the
/// raw body the server received.
fn send(form: bangboo::multipart::Form) -> (String, String) {
    let (tx, rx) = std::sync::mpsc::channel();
    let addr = server(move |mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        tx.send((head, String::from_utf8_lossy(&body).into_owned()))
            .unwrap();
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let res = bangboo::Client::new()
        .post(format!("http://{addr}/"))
        .multipart(form)
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "ok");
    rx.recv().unwrap()
}

#[test]
fn text_fields() {
    let form = bangboo::multipart::Form::new()
        .text("a", "1")
        .text("b", "two");
    let boundary = form.boundary().to_string();
    let (head, body) = send(form);

    let lower = head.to_lowercase();
    assert!(
        lower.contains(&format!(
            "content-type: multipart/form-data; boundary={boundary}"
        )),
        "head: {head}"
    );
    // A form of only text parts has a known length, so no chunked framing.
    assert!(lower.contains("content-length:"), "head: {head}");
    assert!(!lower.contains("transfer-encoding"), "head: {head}");

    let expected = format!(
        "--{boundary}\r\ncontent-disposition: form-data; name=\"a\"\r\n\r\n1\r\n\
         --{boundary}\r\ncontent-disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n\
         --{boundary}--\r\n"
    );
    assert_eq!(body, expected);
}

#[test]
fn content_length_matches_computed_length() {
    let form = bangboo::multipart::Form::new().text("field", "value");
    let expected = form.boundary().len();
    let (head, body) = send(form);
    let declared: usize = head
        .to_lowercase()
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length:")
                .map(|v| v.trim().to_owned())
        })
        .expect("no content-length")
        .parse()
        .unwrap();
    assert_eq!(declared, body.len());
    assert!(expected > 0);
}

#[test]
fn part_with_mime_and_filename() {
    let part = bangboo::multipart::Part::bytes(&b"binary"[..])
        .file_name("data.bin")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = bangboo::multipart::Form::new().part("upload", part);
    let (_, body) = send(form);

    assert!(
        body.contains("content-disposition: form-data; name=\"upload\"; filename=\"data.bin\""),
        "body: {body}"
    );
    assert!(
        body.contains("content-type: application/octet-stream"),
        "body: {body}"
    );
    assert!(body.contains("binary"), "body: {body}");
}

#[test]
fn unsized_reader_falls_back_to_chunked() {
    let part = bangboo::multipart::Part::reader(std::io::Cursor::new(b"streamed".to_vec()));
    let form = bangboo::multipart::Form::new().part("stream", part);
    let (head, body) = send(form);

    let lower = head.to_lowercase();
    assert!(lower.contains("transfer-encoding: chunked"), "head: {head}");
    assert!(!lower.contains("content-length:"), "head: {head}");
    assert!(body.contains("streamed"), "body: {body}");
}

#[test]
fn reader_with_length_keeps_content_length() {
    let part =
        bangboo::multipart::Part::reader_with_length(std::io::Cursor::new(b"exactly".to_vec()), 7);
    let form = bangboo::multipart::Form::new().part("sized", part);
    let (head, body) = send(form);

    assert!(
        head.to_lowercase().contains("content-length:"),
        "head: {head}"
    );
    assert!(body.contains("exactly"), "body: {body}");
}

#[test]
fn file_part_guesses_name_and_mime() {
    let dir = std::env::temp_dir().join("bangboo-multipart-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hello.txt");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"file contents").unwrap();
    drop(file);

    let form = bangboo::multipart::Form::new().file("doc", &path).unwrap();
    let (head, body) = send(form);

    assert!(
        head.to_lowercase().contains("content-length:"),
        "head: {head}"
    );
    assert!(body.contains("filename=\"hello.txt\""), "body: {body}");
    assert!(body.contains("content-type: text/plain"), "body: {body}");
    assert!(body.contains("file contents"), "body: {body}");

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn field_names_are_escaped() {
    let form = bangboo::multipart::Form::new().text("na\"me", "v");
    let (_, body) = send(form);
    // The default path-segment encoding percent-escapes the quote instead
    // of letting it break out of the quoted string.
    assert!(body.contains("name=\"na%22me\""), "body: {body}");

    let form = bangboo::multipart::Form::new()
        .percent_encode_noop()
        .text("na\"me", "v");
    let (_, body) = send(form);
    assert!(body.contains("name=\"na\\\"me\""), "body: {body}");
}

#[test]
fn custom_part_headers() {
    let mut headers = bangboo::header::HeaderMap::new();
    headers.insert("x-part", "yes".parse().unwrap());
    let part = bangboo::multipart::Part::text("v").headers(headers);
    let form = bangboo::multipart::Form::new().part("f", part);
    let (_, body) = send(form);
    assert!(body.contains("x-part: yes"), "body: {body}");
}

#[test]
fn empty_form() {
    let form = bangboo::multipart::Form::new();
    let boundary = form.boundary().to_string();
    let (_, body) = send(form);
    assert_eq!(body, format!("--{boundary}--\r\n"));
}
