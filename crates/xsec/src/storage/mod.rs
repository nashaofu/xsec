use std::future::Future;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum XSecStorageError {
    #[error("storage operation conflicted")]
    Conflict,
    #[error("storage access was denied")]
    AccessDenied,
    #[error("storage resources were exhausted")]
    ResourceExhausted,
    #[error("storage is unavailable")]
    Unavailable,
    #[error("storage limit was exceeded")]
    LimitExceeded,
    #[error("storage backend failed")]
    Internal,
}

pub type XSecStorageResult<T> = Result<T, XSecStorageError>;

pub trait XSecStorage: Send + Sync {
    fn load(&self) -> impl Future<Output = XSecStorageResult<Option<Vec<u8>>>> + Send + '_;
    fn save<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Future<Output = XSecStorageResult<()>> + Send + 'a;
    fn delete(&self) -> impl Future<Output = XSecStorageResult<()>> + Send + '_;
}

#[cfg(feature = "file-storage")]
mod file;

#[cfg(feature = "file-storage")]
pub use file::XSecFileStorage;
