use std::future::Future;

use crate::XSecResult;

pub trait XSecStorage: Send + Sync {
    fn load(&self) -> impl Future<Output = XSecResult<Option<Vec<u8>>>> + Send + '_;
    fn save<'a>(&'a self, data: &'a [u8]) -> impl Future<Output = XSecResult<()>> + Send + 'a;
    fn delete(&self) -> impl Future<Output = XSecResult<()>> + Send + '_;
}

#[cfg(feature = "file-storage")]
mod file;

#[cfg(feature = "file-storage")]
pub use file::XSecFileStorage;
