use std::io;

use thiserror::Error;
use xsec::XSecError;

use crate::environment::{MAX_ENCRYPTED_ENV_FILE_SIZE, MAX_ENV_FILE_SIZE, MAX_PASSWORD_SIZE};

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error(transparent)]
    XSec(#[from] XSecError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("the environment file is invalid")]
    InvalidEnvironment,
    #[error("environment variable `{0}` contains an invalid encrypted value")]
    InvalidEncryptedVariable(String),
    #[error("environment variable `{0}` is declared more than once")]
    DuplicateVariable(String),
    #[error("environment variable `{0}` contains a NUL byte")]
    InvalidVariable(String),
    #[error("`{0}` is not a valid environment variable name")]
    InvalidVariableName(String),
    #[error(
        "environment values must be valid UTF-8 and must not contain NUL or carriage-return bytes"
    )]
    InvalidEnvironmentValue,
    #[error("the environment value exceeds the {MAX_ENV_FILE_SIZE}-byte limit")]
    EnvironmentValueTooLarge,
    #[error("the encrypted environment exceeds the {MAX_ENCRYPTED_ENV_FILE_SIZE}-byte limit")]
    UpdatedEnvironmentTooLarge,
    #[error("the decrypted environment exceeds the {MAX_ENV_FILE_SIZE}-byte limit")]
    DecryptedEnvironmentTooLarge,
    #[error("`{0}` changed while it was being updated")]
    ConcurrentModification(String),
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("the password must not be empty")]
    EmptyPassword,
    #[error("the password exceeds {MAX_PASSWORD_SIZE} bytes")]
    PasswordTooLarge,
    #[error("standard input contains more than {MAX_PASSWORD_SIZE} password bytes")]
    PasswordInputTooLarge,
    #[error("`--password` can only be used with the password protector")]
    UnexpectedPasswordInput,
    #[error("storage has not been initialized at `{0}`")]
    StorageNotInitialized(String),
    #[error("select a configured protector with `--protector`; available: {0}")]
    ProtectorSelectionRequired(String),
    #[error("select a configured protector with `--unlock-with`; available: {0}")]
    UnlockProtectorSelectionRequired(String),
    #[error("protector `{0}` is not configured")]
    ProtectorNotConfigured(String),
    #[error("protector `{0}` is not supported by this CLI")]
    UnsupportedProtector(String),
    #[error("refusing to overwrite `{0}` without `--force`")]
    OutputExists(String),
    #[error("input and output must be different files")]
    SameInputAndOutput,
    #[error("`{path}` exceeds the {limit}-byte limit")]
    FileTooLarge { path: String, limit: usize },
    #[error("the background file operation failed")]
    FileTaskFailed,
    #[error("failed to start the child process: {0}")]
    ChildProcess(#[source] io::Error),
}

pub(crate) type CliResult<T> = Result<T, CliError>;

pub(crate) fn io_error(context: impl Into<String>, source: io::Error) -> CliError {
    CliError::Io {
        context: context.into(),
        source,
    }
}
