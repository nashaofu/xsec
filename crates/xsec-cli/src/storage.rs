use std::{
    io::{self, Read},
    path::Path,
};

use secrecy::{ExposeSecret, SecretBox};
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector};
use zeroize::Zeroize;

use crate::{
    cli::{ProtectorKind, UnlockArgs},
    environment::MAX_PASSWORD_SIZE,
    error::{CliError, CliResult, io_error},
};

pub(crate) type FileXSec = XSec<XSecFileStorage>;

pub(crate) async fn load_and_unlock(args: &UnlockArgs) -> CliResult<FileXSec> {
    let mut xsec = load_initialized_storage(&args.storage).await?;
    let configured = protector_names(&xsec);
    let kind = match args.protector {
        Some(kind) => kind,
        None if configured.len() == 1 => ProtectorKind::from_kind(&configured[0])?,
        None => {
            return Err(CliError::ProtectorSelectionRequired(configured.join(", ")));
        }
    };
    if !configured.iter().any(|value| value == kind.as_str()) {
        return Err(CliError::ProtectorNotConfigured(kind.as_str().to_owned()));
    }
    unlock_with(&mut xsec, kind, args.password).await?;
    Ok(xsec)
}

pub(crate) async fn unlock_with(
    xsec: &mut FileXSec,
    kind: ProtectorKind,
    password_stdin: bool,
) -> CliResult<()> {
    match kind {
        ProtectorKind::Password => {
            let protector = password_protector(password_stdin, false)?;
            xsec.unlock(&protector).await?;
        }
        ProtectorKind::System => {
            if password_stdin {
                return Err(CliError::UnexpectedPasswordInput);
            }
            xsec.unlock_system().await?;
        }
    }
    Ok(())
}

pub(crate) async fn load_storage(path: &Path) -> CliResult<FileXSec> {
    let mut xsec = XSec::new();
    xsec.load(XSecFileStorage::new(path)).await?;
    Ok(xsec)
}

pub(crate) async fn load_initialized_storage(path: &Path) -> CliResult<FileXSec> {
    let xsec = load_storage(path).await?;
    if !xsec.is_initialized() {
        return Err(CliError::StorageNotInitialized(path.display().to_string()));
    }
    Ok(xsec)
}

pub(crate) fn protector_names(xsec: &FileXSec) -> Vec<String> {
    xsec.key_protector_kinds().map(str::to_owned).collect()
}

pub(crate) fn password_protector(
    password_stdin: bool,
    confirm_password: bool,
) -> CliResult<XSecPasswordProtector> {
    Ok(XSecPasswordProtector::new(read_password(
        password_stdin,
        confirm_password,
    )?))
}

fn read_password(from_stdin: bool, confirm: bool) -> CliResult<SecretBox<Vec<u8>>> {
    let mut password = if from_stdin {
        let mut bytes = Vec::new();
        io::stdin()
            .take((MAX_PASSWORD_SIZE + 2) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("failed to read password from standard input", source))?;
        strip_line_ending(&mut bytes);
        if bytes.len() > MAX_PASSWORD_SIZE {
            bytes.zeroize();
            return Err(CliError::PasswordInputTooLarge);
        }
        bytes
    } else {
        rpassword::prompt_password("Password: ")
            .map_err(|source| io_error("failed to read password", source))?
            .into_bytes()
    };

    validate_password(&mut password)?;
    let password = SecretBox::new(Box::new(password));
    if confirm && !from_stdin {
        let mut confirmation = rpassword::prompt_password("Confirm password: ")
            .map_err(|source| io_error("failed to confirm password", source))?
            .into_bytes();
        let matches = password.expose_secret().as_slice() == confirmation.as_slice();
        confirmation.zeroize();
        if !matches {
            return Err(CliError::PasswordMismatch);
        }
    }
    Ok(password)
}

fn validate_password(password: &mut Vec<u8>) -> CliResult<()> {
    if password.is_empty() {
        return Err(CliError::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_SIZE {
        password.zeroize();
        return Err(CliError::PasswordTooLarge);
    }
    Ok(())
}

pub(crate) fn strip_line_ending(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}
