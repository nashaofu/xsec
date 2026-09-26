use zeroize::Zeroizing;

use crate::{
    cli::EncryptArgs,
    environment::{EnvDocument, MAX_ENV_FILE_SIZE, encrypt_environment_document},
    error::CliResult,
    file::{atomic_write, ensure_distinct_paths, read_limited},
    storage::load_and_unlock,
};

pub(super) async fn execute(args: EncryptArgs) -> CliResult<()> {
    ensure_distinct_paths(&args.input, &args.output).await?;
    let plaintext = Zeroizing::new(read_limited(&args.input, MAX_ENV_FILE_SIZE).await?);
    let xsec = load_and_unlock(&args.unlock).await?;
    let mut document = EnvDocument::parse(plaintext)?;
    encrypt_environment_document(&mut document, &xsec)?;
    atomic_write(&args.output, document.source.to_vec(), args.force).await?;
    println!(
        "Encrypted {} to {}",
        args.input.display(),
        args.output.display()
    );
    Ok(())
}
