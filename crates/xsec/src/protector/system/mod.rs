use sha2::{Digest, Sha256};

const MAX_IDENTITY_SIZE: usize = 4096;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::XSecSystemProtector;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::XSecSystemProtector;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::XSecSystemProtector;

fn hash_identity(identity: &str) -> [u8; 32] {
    assert!(
        identity.len() <= MAX_IDENTITY_SIZE,
        "XSec system protector identity exceeds 4096 UTF-8 bytes"
    );
    let mut hash = Sha256::new();
    hash.update(b"xsec:system-protector");
    hash.update((identity.len() as u32).to_be_bytes());
    hash.update(identity.as_bytes());
    hash.finalize().into()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub struct XSecSystemProtector {
    _identity: [u8; 32],
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl XSecSystemProtector {
    pub fn new(identity: impl Into<String>) -> Self {
        let identity = hash_identity(&identity.into());
        Self {
            _identity: identity,
        }
    }

    pub async fn check_availability(&self) -> crate::XSecResult<()> {
        let _ = self;
        Err(crate::XSecError::SystemProtectorUnavailable)
    }

    pub async fn delete(&self) -> crate::XSecResult<()> {
        let _ = self;
        Err(crate::XSecError::SystemProtectorUnavailable)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl crate::XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        "system"
    }

    async fn wrap_key<'a>(
        &'a self,
        _key: &'a secrecy::SecretBox<[u8; 32]>,
    ) -> crate::XSecResult<Vec<u8>> {
        Err(crate::XSecError::SystemProtectorUnavailable)
    }

    async fn unwrap_key<'a>(
        &'a self,
        _payload: &'a [u8],
    ) -> crate::XSecResult<secrecy::SecretBox<[u8; 32]>> {
        let _ = (self, _payload);
        Err(crate::XSecError::SystemProtectorUnavailable)
    }
}
