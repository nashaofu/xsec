use tokio::io::AsyncWriteExt;

use crate::{
    cli::GetArgs,
    environment::{
        MAX_ENCRYPTED_ENV_FILE_SIZE, decrypt_environment_value, load_environment_document,
        normalized_environment_key, parse_environment, validate_variable_name, zeroize_environment,
    },
    error::{CliResult, io_error},
    file::read_limited,
    storage::load_and_unlock,
};

pub(super) async fn execute(args: GetArgs) -> CliResult<u8> {
    validate_variable_name(&args.key)?;
    let encrypted = read_limited(&args.file, MAX_ENCRYPTED_ENV_FILE_SIZE).await?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let document = load_environment_document(encrypted)?;
    let mut environment = parse_environment(&document.source)?;
    let comparison_key = normalized_environment_key(&args.key);
    let value = environment
        .iter()
        .find(|(key, _)| normalized_environment_key(key) == comparison_key)
        .map(|(key, value)| decrypt_environment_value(key, value, &xsec))
        .transpose();
    let value = match value {
        Ok(Some(value)) => value,
        Ok(None) => {
            zeroize_environment(&mut environment);
            return Ok(1);
        }
        Err(error) => {
            zeroize_environment(&mut environment);
            return Err(error);
        }
    };
    let mut stdout = tokio::io::stdout();
    let result = match stdout.write_all(&value).await {
        Ok(()) => stdout.flush().await,
        Err(error) => Err(error),
    };
    zeroize_environment(&mut environment);
    result.map_err(|source| io_error("failed to write environment value", source))?;
    Ok(0)
}
