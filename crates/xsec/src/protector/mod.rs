use std::future::Future;

use secrecy::SecretBox;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum XSecProtectorError {
    #[error("key protector is unsupported")]
    Unsupported,
    #[error("key protector is unavailable")]
    Unavailable,
    #[error("key protector is not configured")]
    NotConfigured,
    #[error("key protector is incompatible")]
    Incompatible,
    #[error("key protector access was denied")]
    AccessDenied,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("authentication was cancelled")]
    AuthenticationCancelled,
    #[error("user verification is required")]
    UserVerificationRequired,
    #[error("protector key was not found")]
    KeyNotFound,
    #[error("protector key was invalidated")]
    KeyInvalidated,
    #[error("key protector data is invalid")]
    InvalidData,
    #[error("key protector failed")]
    Internal,
}

pub type XSecProtectorResult<T> = Result<T, XSecProtectorError>;

pub trait XSecProtector: Send + Sync {
    fn kind(&self) -> &'static str;
    fn wrap_key<'a>(
        &'a self,
        key: &'a SecretBox<[u8; 32]>,
    ) -> impl Future<Output = XSecProtectorResult<Vec<u8>>> + Send + 'a;
    fn unwrap_key<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> impl Future<Output = XSecProtectorResult<SecretBox<[u8; 32]>>> + Send + 'a;
}

#[cfg(feature = "password-protector")]
mod password;

#[cfg(feature = "password-protector")]
pub use password::XSecPasswordProtector;

#[cfg(feature = "system-protector")]
mod system;

#[cfg(feature = "system-protector")]
pub use system::XSecSystemProtector;
