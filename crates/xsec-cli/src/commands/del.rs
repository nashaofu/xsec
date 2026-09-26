use crate::{
    cli::DelArgs,
    environment::{
        MAX_ENCRYPTED_ENV_FILE_SIZE, load_environment_document, validate_environment,
        validate_variable_name,
    },
    error::CliResult,
    file::{atomic_replace_if_unchanged, read_limited},
};

pub(super) async fn execute(args: DelArgs) -> CliResult<u8> {
    validate_variable_name(&args.key)?;
    let original = read_limited(&args.file, MAX_ENCRYPTED_ENV_FILE_SIZE).await?;
    let mut document = load_environment_document(original.clone())?;
    if !document.unset(&args.key) {
        return Ok(1);
    }
    validate_environment(&document.source)?;
    atomic_replace_if_unchanged(&args.file, document.source.to_vec(), Some(original)).await?;
    Ok(0)
}
