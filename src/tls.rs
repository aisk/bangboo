//! TLS configuration
//!
//! Requires the `tls` feature (enabled by default). Server certificates are
//! validated against the bundled Mozilla root set ([`webpki-roots`]) unless
//! custom roots are configured with
//! [`ClientBuilder::add_root_certificate`][crate::ClientBuilder::add_root_certificate]
//! or [`tls_certs_only`][crate::ClientBuilder::tls_certs_only]. With the
//! `native-roots` feature the operating system's certificate store is used
//! instead of the bundled set.
//!
//! [`webpki-roots`]: https://docs.rs/webpki-roots

use std::fmt;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

/// Represents a server X509 certificate.
#[derive(Clone)]
pub struct Certificate {
    der: CertificateDer<'static>,
}

impl Certificate {
    /// Create a `Certificate` from a binary DER encoded certificate.
    pub fn from_der(der: &[u8]) -> crate::Result<Certificate> {
        Ok(Certificate {
            der: CertificateDer::from(der.to_vec()),
        })
    }

    /// Create a `Certificate` from a PEM encoded certificate.
    pub fn from_pem(pem: &[u8]) -> crate::Result<Certificate> {
        Ok(Certificate {
            der: CertificateDer::from_pem_slice(pem).map_err(crate::error::builder)?,
        })
    }

    /// Create a collection of `Certificate`s from a PEM encoded certificate
    /// bundle.
    pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<Certificate>> {
        CertificateDer::pem_slice_iter(pem_bundle)
            .map(|result| {
                result
                    .map(|der| Certificate { der })
                    .map_err(crate::error::builder)
            })
            .collect()
    }

    pub(crate) fn into_der(self) -> CertificateDer<'static> {
        self.der
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate").finish()
    }
}

/// Represents a private key and X509 certificate chain, used for mutual TLS
/// (client authentication).
pub struct Identity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl Identity {
    /// Parses a chain of PEM encoded X509 certificates, with the leaf
    /// certificate first, along with the (PKCS#8, PKCS#1 or SEC1 encoded)
    /// private key anywhere in the same buffer.
    pub fn from_pem(buf: &[u8]) -> crate::Result<Identity> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(buf)
            .collect::<Result<_, _>>()
            .map_err(crate::error::builder)?;
        if certs.is_empty() {
            return Err(crate::error::builder("identity PEM contains no certificate"));
        }
        let key = PrivateKeyDer::from_pem_slice(buf).map_err(crate::error::builder)?;
        Ok(Identity { certs, key })
    }

    /// Creates an `Identity` from separate PEM buffers holding the
    /// certificate chain and the private key.
    pub fn from_pkcs8_pem(pem: &[u8], key: &[u8]) -> crate::Result<Identity> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<_, _>>()
            .map_err(crate::error::builder)?;
        if certs.is_empty() {
            return Err(crate::error::builder("identity PEM contains no certificate"));
        }
        let key = PrivateKeyDer::from_pem_slice(key).map_err(crate::error::builder)?;
        Ok(Identity { certs, key })
    }

    pub(crate) fn into_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.certs, self.key)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").finish()
    }
}

/// A certificate revocation list, used to reject revoked server
/// certificates during validation.
#[derive(Clone)]
pub struct CertificateRevocationList {
    der: CertificateRevocationListDer<'static>,
}

impl CertificateRevocationList {
    /// Parses a PEM encoded CRL.
    pub fn from_pem(pem: &[u8]) -> crate::Result<CertificateRevocationList> {
        Ok(CertificateRevocationList {
            der: CertificateRevocationListDer::from_pem_slice(pem)
                .map_err(crate::error::builder)?,
        })
    }

    /// Creates a collection of `CertificateRevocationList`s from a PEM
    /// encoded CRL bundle.
    pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<CertificateRevocationList>> {
        CertificateRevocationListDer::pem_slice_iter(pem_bundle)
            .map(|result| {
                result
                    .map(|der| CertificateRevocationList { der })
                    .map_err(crate::error::builder)
            })
            .collect()
    }

    pub(crate) fn into_der(self) -> CertificateRevocationListDer<'static> {
        self.der
    }
}

impl fmt::Debug for CertificateRevocationList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateRevocationList").finish()
    }
}

/// A TLS protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

impl Version {
    /// Version 1.0 of the TLS protocol. Not supported by rustls; only
    /// useful as a lower bound.
    pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
    /// Version 1.1 of the TLS protocol. Not supported by rustls; only
    /// useful as a lower bound.
    pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);
}

/// Information about the TLS session of a response, stored in the
/// response's [`extensions()`][crate::Response::extensions] when
/// [`ClientBuilder::tls_info`][crate::ClientBuilder::tls_info] is enabled.
#[derive(Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Vec<u8>>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }
}

impl fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsInfo").finish()
    }
}

/// All TLS knobs collected by the `ClientBuilder`, resolved into a rustls
/// `ClientConfig` at `build()` time.
pub(crate) struct TlsSettings {
    pub(crate) accept_invalid_certs: bool,
    pub(crate) accept_invalid_hostnames: bool,
    pub(crate) sni: bool,
    pub(crate) built_in_root_certs: bool,
    pub(crate) root_certs: Vec<Certificate>,
    /// `Some` when `tls_certs_only` was used: replaces built-in and merged
    /// roots entirely.
    pub(crate) root_certs_only: Option<Vec<Certificate>>,
    pub(crate) identity: Option<Identity>,
    pub(crate) crls: Vec<CertificateRevocationList>,
    pub(crate) min_version: Option<Version>,
    pub(crate) max_version: Option<Version>,
    pub(crate) tls_info: bool,
}

impl Default for TlsSettings {
    fn default() -> Self {
        TlsSettings {
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
            sni: true,
            built_in_root_certs: true,
            root_certs: Vec::new(),
            root_certs_only: None,
            identity: None,
            crls: Vec::new(),
            min_version: None,
            max_version: None,
            tls_info: false,
        }
    }
}

impl TlsSettings {
    pub(crate) fn build_config(self) -> crate::Result<std::sync::Arc<rustls::ClientConfig>> {
        use std::sync::Arc;

        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier;

        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Protocol versions within [min, max]; rustls only implements 1.2
        // and 1.3, lower bounds are simply permissive.
        let min = self.min_version.unwrap_or(Version::TLS_1_0);
        let max = self.max_version.unwrap_or(Version::TLS_1_3);
        let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
        if min <= Version::TLS_1_2 && Version::TLS_1_2 <= max {
            versions.push(&rustls::version::TLS12);
        }
        if min <= Version::TLS_1_3 && Version::TLS_1_3 <= max {
            versions.push(&rustls::version::TLS13);
        }
        if versions.is_empty() {
            return Err(crate::error::builder(
                "no TLS versions supported by rustls fall within the configured min/max",
            ));
        }

        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .map_err(crate::error::builder)?;

        let verifier: Arc<dyn ServerCertVerifier> = if self.accept_invalid_certs {
            Arc::new(danger::NoVerify)
        } else {
            let mut roots = rustls::RootCertStore::empty();
            match self.root_certs_only {
                Some(certs) => {
                    for cert in certs {
                        roots.add(cert.into_der()).map_err(crate::error::builder)?;
                    }
                }
                None => {
                    if self.built_in_root_certs {
                        add_built_in_roots(&mut roots);
                    }
                    for cert in self.root_certs {
                        roots.add(cert.into_der()).map_err(crate::error::builder)?;
                    }
                }
            }
            if roots.is_empty() {
                return Err(crate::error::builder(
                    "no trusted root certificates configured",
                ));
            }
            let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .with_crls(self.crls.into_iter().map(|crl| crl.into_der()))
                .build()
                .map_err(crate::error::builder)?;
            if self.accept_invalid_hostnames {
                Arc::new(danger::IgnoreHostname { inner: verifier })
            } else {
                verifier
            }
        };

        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let mut config = match self.identity {
            Some(identity) => {
                let (certs, key) = identity.into_parts();
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(crate::error::builder)?
            }
            None => builder.with_no_client_auth(),
        };
        config.enable_sni = self.sni;
        Ok(Arc::new(config))
    }
}

#[cfg(feature = "native-roots")]
fn add_built_in_roots(roots: &mut rustls::RootCertStore) {
    // Certificates the platform store hands out that fail to parse are
    // skipped, like reqwest does.
    let result = rustls_native_certs::load_native_certs();
    let (added, _ignored) = roots.add_parsable_certificates(result.certs);
    if added == 0 {
        // Nothing loaded (or everything unparsable): fall back to the
        // bundled Mozilla set so https doesn't silently break.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
}

#[cfg(not(feature = "native-roots"))]
fn add_built_in_roots(roots: &mut rustls::RootCertStore) {
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
}

pub(crate) mod danger {
    use std::sync::Arc;

    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};

    /// Accepts any certificate and any hostname.
    #[derive(Debug)]
    pub(crate) struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }

    /// Verifies the certificate chain normally but ignores hostname
    /// mismatches (`danger_accept_invalid_hostnames`).
    #[derive(Debug)]
    pub(crate) struct IgnoreHostname {
        pub(crate) inner: Arc<WebPkiServerVerifier>,
    }

    impl ServerCertVerifier for IgnoreHostname {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            match self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::NotValidForName
                    | CertificateError::NotValidForNameContext { .. },
                )) => Ok(ServerCertVerified::assertion()),
                other => other,
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }
}
