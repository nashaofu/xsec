mod ciphertext;
mod metadata;

pub mod error;
pub mod protector;
pub mod storage;
pub mod xsec;

pub use error::{XSecError, XSecResult};
pub use protector::XSecProtector;
pub use storage::XSecStorage;
pub use xsec::{XSec, XSecStatus};

#[cfg(feature = "password-protector")]
pub use protector::XSecPasswordProtector;

#[cfg(feature = "system-protector")]
pub use protector::XSecSystemProtector;

#[cfg(feature = "file-storage")]
pub use storage::XSecFileStorage;
