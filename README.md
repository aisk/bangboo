# bangboo

![Bangboo](https://cdn.oneesports.gg/wp-content/uploads/2024/07/ZenlessZoneZero_TheBangboo.jpg)

A truly synchronous HTTP/1.1 client for Rust, with an API modeled after `reqwest::blocking`. Unlike `reqwest::blocking` (which runs a tokio runtime on a background thread), bangboo is built directly on `std::net::TcpStream`, with no async runtime anywhere.

## Installation

Add it to your `Cargo.toml`:

```toml
[dependencies]
bangboo = "0.1"
```

TLS support (via rustls) is enabled by default. To build without it:

```toml
bangboo = { version = "0.1", default-features = false }
```

## Usage

For a single request, use the `get` shortcut:

```rust
let body = bangboo::get("https://www.rust-lang.org")?.text()?;
println!("{body}");
```

If you plan to make multiple requests, create a `Client` and reuse it to benefit from keep-alive connection pooling:

```rust
let client = bangboo::Client::new();
let res = client
    .post("http://httpbin.org/post")
    .body("the exact body that is sent")
    .send()?;
```

## License

MIT
