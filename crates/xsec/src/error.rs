use thiserror::Error;

use crate::{protector::XSecProtectorError, storage::XSecStorageError};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum XSecError {
    #[error("XSec metadata was not found")]
    NotFound,
    #[error("XSec metadata already exists")]
    AlreadyExists,
    #[error("XSec storage has not been loaded")]
    StorageNotLoaded,
    #[error("XSec storage has already been loaded")]
    AlreadyLoaded,
    #[error("XSec is not initialized")]
    NotInitialized,
    #[error("XSec is locked")]
    Locked,
    #[error("XSec has been destroyed")]
    Destroyed,
    #[error("XSec is already unlocked")]
    AlreadyUnlocked,
    #[error("XSec metadata is corrupted")]
    Corrupted,
    #[error("ciphertext is invalid")]
    InvalidCiphertext,
    #[error("format version is unsupported")]
    UnsupportedVersion,
    #[error("algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error("key protector was not found")]
    ProtectorNotFound,
    #[error("key protector already exists")]
    ProtectorAlreadyExists,
    #[error("the last key protector cannot be removed")]
    LastProtector,
    #[error(transparent)]
    Storage(#[from] XSecStorageError),
    #[error(transparent)]
    Protector(#[from] XSecProtectorError),
    #[error("cryptographic operation failed")]
    Crypto,
}

pub type XSecResult<T> = Result<T, XSecError>;
