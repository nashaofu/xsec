use std::future::Future;

use secrecy::SecretBox;

use crate::XSecResult;

pub trait XSecKeyProtector: Send + Sync {
    fn kind(&self) -> &'static str;
    fn wrap_key<'a>(
        &'a self,
        key: &'a SecretBox<[u8; 32]>,
    ) -> impl Future<Output = XSecResult<Vec<u8>>> + Send + 'a;
    fn unwrap_key<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> impl Future<Output = XSecResult<SecretBox<[u8; 32]>>> + Send + 'a;
}

#[cfg(feature = "password-protector")]
mod password;

#[cfg(feature = "password-protector")]
pub use password::XSecPasswordProtector;

#[cfg(all(feature = "windows-hello", target_os = "windows"))]
mod windows;

#[cfg(all(feature = "windows-hello", target_os = "windows"))]
pub use windows::XSecWindowsHelloProtector;
