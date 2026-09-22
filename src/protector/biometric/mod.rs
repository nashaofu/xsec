#[cfg(all(feature = "biometric", target_os = "windows"))]
mod windows;

#[cfg(feature = "biometric")]
#[cfg(target_os = "windows")]
pub use windows::XSecBiometricProtector;

#[cfg(all(feature = "biometric", not(target_os = "windows")))]
pub struct XSecBiometricProtector {
    _name: String,
}

#[cfg(all(feature = "biometric", not(target_os = "windows")))]
impl XSecBiometricProtector {
    pub fn new(name: impl Into<String>) -> Self {
        Self { _name: name.into() }
    }
}

#[cfg(all(feature = "biometric", not(target_os = "windows")))]
impl crate::XSecKeyProtector for XSecBiometricProtector {
    fn kind(&self) -> &'static str {
        "biometric"
    }

    async fn wrap_key<'a>(
        &'a self,
        _key: &'a secrecy::SecretBox<[u8; 32]>,
    ) -> crate::XSecResult<Vec<u8>> {
        Err(crate::XSecError::Crypto)
    }

    async fn unwrap_key<'a>(
        &'a self,
        _payload: &'a [u8],
    ) -> crate::XSecResult<secrecy::SecretBox<[u8; 32]>> {
        Err(crate::XSecError::Crypto)
    }
}
