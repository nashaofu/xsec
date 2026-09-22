use thiserror::Error;

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
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("Windows Hello is not supported")]
    WindowsHelloNotSupported,
    #[error("Windows Hello is not configured")]
    WindowsHelloNotConfigured,
    #[error("the cryptographic provider does not support required user verification")]
    ProviderNotSupported,
    #[error("user verification is required")]
    UserVerificationRequired,
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
    #[error("storage error: {source}")]
    Storage {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("key protector error: {source}")]
    Protector {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("cryptographic operation failed")]
    Crypto,
}

impl XSecError {
    #[cfg(feature = "file-storage")]
    pub(crate) fn storage<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Storage {
            source: Box::new(source),
        }
    }

    #[cfg(feature = "password-protector")]
    pub(crate) fn protector<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Protector {
            source: Box::new(source),
        }
    }
}

pub type XSecResult<T> = Result<T, XSecError>;
