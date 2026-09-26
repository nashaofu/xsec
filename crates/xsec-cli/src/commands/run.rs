use std::process::{ExitStatus, Stdio};

use crate::{
    cli::RunArgs,
    environment::{
        MAX_ENCRYPTED_ENV_FILE_SIZE, decrypt_environment_values, load_environment_document,
        zeroize_environment,
    },
    error::{CliError, CliResult},
    file::read_limited,
    storage::load_and_unlock,
};

pub(super) async fn execute(args: RunArgs) -> CliResult<u8> {
    let encrypted = read_limited(&args.file, MAX_ENCRYPTED_ENV_FILE_SIZE).await?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let document = load_environment_document(encrypted)?;
    let mut environment = decrypt_environment_values(&document, &xsec)?;

    let executable = args.command.first().expect("clap requires a command");
    let mut command = tokio::process::Command::new(executable);
    command
        .args(&args.command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    for (key, value) in &environment {
        if args.r#override || std::env::var_os(key).is_none() {
            command.env(key, value);
        }
    }
    zeroize_environment(&mut environment);

    let status = command.status().await.map_err(CliError::ChildProcess)?;
    Ok(exit_status_code(status))
}

fn exit_status_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return u8::try_from(128 + signal).unwrap_or(1);
        }
    }
    1
}
