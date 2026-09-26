use std::io;

use crate::{
    cli::SetArgs,
    environment::{
        MAX_ENCRYPTED_ENV_FILE_SIZE, encrypt_environment_value, load_environment_document,
        read_environment_value, validate_environment, validate_variable_name,
    },
    error::{CliError, CliResult},
    file::{atomic_replace_if_unchanged, read_limited},
    storage::load_and_unlock,
};

pub(super) async fn execute(args: SetArgs) -> CliResult<()> {
    validate_variable_name(&args.key)?;
    let value = read_environment_value(args.value)?;
    let original = match read_limited(&args.file, MAX_ENCRYPTED_ENV_FILE_SIZE).await {
        Ok(original) => Some(original),
        Err(CliError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let xsec = load_and_unlock(&args.unlock).await?;
    let mut document = load_environment_document(original.clone().unwrap_or_default())?;
    let encryption_key = document
        .stored_name(&args.key)
        .unwrap_or(args.key.as_str())
        .to_owned();
    let encrypted = encrypt_environment_value(&encryption_key, &value, &xsec)?;
    document.set(&args.key, &encrypted)?;
    validate_environment(&document.source)?;
    atomic_replace_if_unchanged(&args.file, document.source.to_vec(), original).await
}
