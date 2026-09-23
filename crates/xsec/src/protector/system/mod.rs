#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::XSecSystemProtector;

#[cfg(not(target_os = "windows"))]
pub struct XSecSystemProtector {
    identity_hash: [u8; 32],
}

#[cfg(not(target_os = "windows"))]
impl XSecSystemProtector {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            identity_hash: identity_hash(&name.into()),
        }
    }

    pub async fn check_availability(&self) -> crate::XSecResult<()> {
        let _ = self;
        Err(crate::XSecError::SystemProtectorUnavailable)
    }
}

#[cfg(not(target_os = "windows"))]
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
        let _ = (self, payload);
        Err(crate::XSecError::SystemProtectorUnavailable)
    }
}

#[cfg(not(target_os = "windows"))]
fn identity_hash(identity: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"xsec:system-protector:v1");
    h.update((identity.len() as u32).to_be_bytes());
    h.update(identity.as_bytes());
    h.finalize().into()
}
