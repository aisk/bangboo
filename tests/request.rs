//! Request construction: query strings, body encoders (json/form), and
//! authentication headers.

mod support;

use serde::{Deserialize, Serialize};
use support::{read_request, respond, server};

#[test]
fn query_building() {
    let client = bangboo::Client::new();
    let req = client
        .get("http://example.com/search?base=1")
        .query(&[("q", "hello world"), ("page", "2")])
        .build()
        .unwrap();
    assert_eq!(
        req.url().as_str(),
        "http://example.com/search?base=1&q=hello+world&page=2"
    );
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Message {
    lang: String,
    stars: u32,
}

#[test]
fn json_roundtrip() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head.to_lowercase().contains("content-type: application/json"));
        respond(
            &mut stream,
            "200 OK",
            "content-type: application/json\r\n",
            &body,
        );
    });

    let sent = Message {
        lang: "rust".into(),
        stars: 100_000,
    };
    let client = bangboo::Client::new();
    let received: Message = client
        .post(format!("http://{addr}/json"))
        .json(&sent)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(received, sent);
}

#[test]
fn form_body() {
    let addr = server(|mut stream| {
        let (head, body) = read_request(&mut stream).unwrap();
        assert!(head
            .to_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"));
        respond(&mut stream, "200 OK", "", &body);
    });

    let client = bangboo::Client::new();
    let res = client
        .post(format!("http://{addr}/form"))
        .form(&[("lang", "rust"), ("q", "a b")])
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "lang=rust&q=a+b");
}

#[test]
fn auth_and_default_headers() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        let head = head.to_lowercase();
        assert!(head.contains("authorization: basic dxnlcjpwyxnz"));
        assert!(head.contains("user-agent: bangboo-test/1.0"));
        assert!(head.contains("accept: */*"));
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let client = bangboo::Client::builder()
        .user_agent("bangboo-test/1.0")
        .build()
        .unwrap();
    let res = client
        .get(format!("http://{addr}/"))
        .basic_auth("user", Some("pass"))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}

#[test]
fn userinfo_in_url_becomes_basic_auth() {
    let addr = server(|mut stream| {
        let (head, _) = read_request(&mut stream).unwrap();
        // base64("user:p@ss") == dXNlcjpwQHNz
        assert!(
            head.to_lowercase().contains("authorization: basic dxnlcjpwqhnz"),
            "got head: {head}"
        );
        respond(&mut stream, "200 OK", "", b"ok");
    });

    let res = bangboo::get(format!("http://user:p%40ss@{addr}/")).unwrap();
    assert_eq!(res.text().unwrap(), "ok");
}

#[test]
fn request_from_http_request() {
    let http_req = http::Request::builder()
        .method("POST")
        .uri("http://example.com/path?x=1")
        .header("x-test", "1")
        .body("payload")
        .unwrap();
    let req = bangboo::Request::try_from(http_req).unwrap();
    assert_eq!(req.method(), &bangboo::Method::POST);
    assert_eq!(req.url().as_str(), "http://example.com/path?x=1");
    assert_eq!(req.headers()["x-test"], "1");
    assert_eq!(req.body().unwrap().as_bytes().unwrap(), b"payload");
}

#[test]
fn response_from_http_response() {
    let http_res = http::Response::builder()
        .status(418)
        .header("x-test", "1")
        .body("teapot")
        .unwrap();
    let res = bangboo::Response::from(http_res);
    assert_eq!(res.status(), bangboo::StatusCode::IM_A_TEAPOT);
    assert_eq!(res.headers()["x-test"], "1");
    assert_eq!(res.text().unwrap(), "teapot");
}
