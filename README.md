# bangboo

![Bangboo](https://cdn.oneesports.gg/wp-content/uploads/2024/07/ZenlessZoneZero_TheBangboo.jpg)

A truly synchronous HTTP/1.1 client for Rust, with an API modeled after `reqwest::blocking`. Unlike `reqwest::blocking` (which runs a tokio runtime on a background thread), bangboo is built directly on `std::net::TcpStream`, with no async runtime anywhere.

## Installation

Add it to your `Cargo.toml`:

```toml
[dependencies]
bangboo = "0.2"
```

TLS (via rustls) and charset-aware text decoding are enabled by default. To build without them:

```toml
bangboo = { version = "0.2", default-features = false }
```

### Features

| Feature | Default | What it adds |
|---|---|---|
| `tls` | yes | HTTPS via rustls, and the `tls` configuration module |
| `charset` | yes | charset-aware `Response::text` and `text_with_charset` |
| `native-roots` | no | validate against the OS certificate store instead of the bundled roots |
| `cookies` | no | cookie store, `Set-Cookie` handling, `Response::cookies` |
| `gzip`, `deflate`, `brotli`, `zstd` | no | transparent response body decompression |
| `multipart` | no | `multipart/form-data` bodies |

Proxies (HTTP, HTTPS and SOCKS4/5, plus the `*_proxy` environment variables), DNS overrides, custom root certificates, mutual TLS and the usual TCP socket options are always available.

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

`Response` implements `std::io::Read`, so bodies can be streamed instead of buffered:

```rust
let mut res = bangboo::get("https://www.rust-lang.org")?;
let mut file = std::fs::File::create("page.html")?;
res.copy_to(&mut file)?;
```

## Differences from `reqwest::blocking`

bangboo implements only HTTP/1.1 and 1.0. Everything in reqwest's blocking API that exists because of its async internals or requires HTTP/2+ is out of scope: `http2_*`, `http3_*`, and tower connector layers. Retry behavior is not configurable, though an idempotent request on a stale pooled connection is still retried once.

## License

MIT
