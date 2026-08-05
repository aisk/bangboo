//! Fetch a URL and print the response: `cargo run --example get -- <url>`

use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_string());

    let client = bangboo::Client::builder()
        .user_agent(concat!("bangboo/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let mut res = client.get(&url).send()?;
    eprintln!("status: {}", res.status());
    eprintln!("version: {:?}", res.version());
    for (name, value) in res.headers() {
        eprintln!("{name}: {}", value.to_str().unwrap_or("<binary>"));
    }
    eprintln!();

    let mut body = String::new();
    res.read_to_string(&mut body)?;
    println!("{body}");
    Ok(())
}
