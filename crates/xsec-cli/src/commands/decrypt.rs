use tokio::io::AsyncWriteExt;

use crate::{
    cli::DecryptArgs,
    environment::{
        MAX_ENCRYPTED_ENV_FILE_SIZE, decrypt_environment_document, load_environment_document,
    },
    error::{CliResult, io_error},
    file::{atomic_write, ensure_distinct_paths, read_limited},
    storage::load_and_unlock,
};

pub(super) async fn execute(args: DecryptArgs) -> CliResult<()> {
    if let Some(output) = &args.output {
        ensure_distinct_paths(&args.input, output).await?;
    }
    let encrypted = read_limited(&args.input, MAX_ENCRYPTED_ENV_FILE_SIZE).await?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let mut document = load_environment_document(encrypted)?;
    decrypt_environment_document(&mut document, &xsec)?;

    match args.output {
        Some(output) => {
            atomic_write(&output, document.source.to_vec(), args.force).await?;
            println!("Decrypted {} to {}", args.input.display(), output.display());
        }
        None => {
            let _ = args.stdout;
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(&document.source)
                .await
                .map_err(|source| io_error("failed to write decrypted output", source))?;
            stdout
                .flush()
                .await
                .map_err(|source| io_error("failed to flush decrypted output", source))?;
        }
    }
    Ok(())
}
