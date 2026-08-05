use url::Url;

/// A trait to try to convert some type into a `Url`.
///
/// This trait is "sealed", such that only types within bangboo can
/// implement it.
pub trait IntoUrl: sealed::Sealed {
    #[doc(hidden)]
    fn into_url(self) -> crate::Result<Url>;
}

impl IntoUrl for Url {
    fn into_url(self) -> crate::Result<Url> {
        if self.host_str().is_none() {
            return Err(crate::error::builder(format!(
                "URL scheme is not allowed or missing host: {self}"
            )));
        }
        match self.scheme() {
            "http" | "https" => Ok(self),
            _ => Err(crate::error::builder(format!(
                "URL scheme is not allowed: {self}"
            ))),
        }
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> crate::Result<Url> {
        Url::parse(self)
            .map_err(crate::error::builder)?
            .into_url()
    }
}

impl IntoUrl for &String {
    fn into_url(self) -> crate::Result<Url> {
        self.as_str().into_url()
    }
}

impl IntoUrl for String {
    fn into_url(self) -> crate::Result<Url> {
        self.as_str().into_url()
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for url::Url {}
    impl Sealed for &str {}
    impl Sealed for &String {}
    impl Sealed for String {}
}
