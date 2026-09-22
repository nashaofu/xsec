#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::XSecSystemProtector;

#[cfg(not(target_os = "windows"))]
pub struct XSecSystemProtector {
    _name: String,
}

#[cfg(not(target_os = "windows"))]
impl XSecSystemProtector {
    pub fn new(name: impl Into<String>) -> Self {
        Self { _name: name.into() }
    }
}

#[cfg(not(target_os = "windows"))]
impl crate::XSecKeyProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        "system"
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
