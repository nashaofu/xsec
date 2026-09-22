mod ciphertext;
mod metadata;

pub mod error;
pub mod protector;
pub mod storage;
pub mod xsec;

pub use error::{XSecError, XSecResult};
pub use protector::XSecKeyProtector;
pub use storage::XSecStorage;
pub use xsec::XSec;

#[cfg(feature = "password-protector")]
pub use protector::XSecPasswordProtector;

#[cfg(all(feature = "windows-hello", target_os = "windows"))]
pub use protector::XSecWindowsHelloProtector;

#[cfg(feature = "file-storage")]
pub use storage::XSecFileStorage;
