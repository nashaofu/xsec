use std::{
    collections::HashSet,
    ffi::OsString,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{ExitCode, ExitStatus, Stdio},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretBox};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use xsec::{
    XSec, XSecError, XSecFileStorage, XSecPasswordProtector, XSecProtector, XSecResult,
    XSecSystemProtector,
};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_METADATA_PATH: &str = ".xsec.meta";
const DEFAULT_ENV_INPUT_PATH: &str = ".env";
const DEFAULT_ENCRYPTED_ENV_PATH: &str = ".xsec";
const ENV_AAD: &[u8] = b"xsec-cli:env:v1";
const MAX_ENV_FILE_SIZE: usize = 1024 * 1024;
const MAX_CIPHERTEXT_FILE_SIZE: usize = MAX_ENV_FILE_SIZE + 1024;
const MAX_PASSWORD_SIZE: usize = 4096;

#[derive(Parser)]
#[command(name = "xsec", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize the project key metadata.
    Init(InitArgs),
    /// Encrypt or decrypt environment files.
    Env(EnvArgs),
    /// Decrypt an environment file and run a command.
    Run(RunArgs),
    /// Show non-secret metadata information.
    Inspect(InspectArgs),
    /// Inspect configured key protectors.
    Protector(ProtectorArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Path used to persist protected key metadata.
    #[arg(long, default_value = DEFAULT_METADATA_PATH)]
    metadata: PathBuf,
    /// Protection mechanism used to unlock the data key.
    #[arg(long, value_enum, default_value = "password")]
    protector: ProtectorKind,
    /// Stable logical identity required by the system protector.
    #[arg(long)]
    identity: Option<String>,
    /// Read the password from standard input instead of prompting.
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args)]
struct EnvArgs {
    #[command(subcommand)]
    command: EnvCommand,
}

#[derive(Subcommand)]
enum EnvCommand {
    /// Encrypt a complete dotenv document.
    Encrypt(EncryptArgs),
    /// Decrypt an environment document.
    Decrypt(DecryptArgs),
}

#[derive(Args)]
struct EncryptArgs {
    /// Plaintext dotenv input.
    #[arg(short, long, default_value = DEFAULT_ENV_INPUT_PATH)]
    input: PathBuf,
    /// Encrypted output.
    #[arg(short, long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    output: PathBuf,
    /// Replace an existing encrypted output.
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    unlock: UnlockArgs,
}

#[derive(Args)]
struct DecryptArgs {
    /// Encrypted environment input.
    #[arg(short, long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    input: PathBuf,
    /// Write plaintext to a file instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Write plaintext to standard output.
    #[arg(long, conflicts_with = "output")]
    stdout: bool,
    /// Replace an existing plaintext output.
    #[arg(long, requires = "output")]
    force: bool,
    #[command(flatten)]
    unlock: UnlockArgs,
}

#[derive(Args)]
struct RunArgs {
    /// Encrypted environment input.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    file: PathBuf,
    /// Override environment variables already present in the process.
    #[arg(long)]
    r#override: bool,
    #[command(flatten)]
    unlock: UnlockArgs,
    /// Command and arguments to execute.
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[derive(Args)]
struct UnlockArgs {
    /// Path containing protected key metadata.
    #[arg(long, default_value = DEFAULT_METADATA_PATH)]
    metadata: PathBuf,
    /// Protector to use when more than one is configured.
    #[arg(long, value_enum)]
    protector: Option<ProtectorKind>,
    /// Stable logical identity required by the system protector.
    #[arg(long)]
    identity: Option<String>,
    /// Read the password from standard input instead of prompting.
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args)]
struct InspectArgs {
    /// Path containing protected key metadata.
    #[arg(long, default_value = DEFAULT_METADATA_PATH)]
    metadata: PathBuf,
}

#[derive(Args)]
struct ProtectorArgs {
    #[command(subcommand)]
    command: ProtectorCommand,
}

#[derive(Subcommand)]
enum ProtectorCommand {
    /// List protector hints stored in metadata.
    List(InspectArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum ProtectorKind {
    Password,
    System,
}

impl ProtectorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::System => "system",
        }
    }

    fn from_kind(kind: &str) -> CliResult<Self> {
        match kind {
            "password" => Ok(Self::Password),
            "system" => Ok(Self::System),
            _ => Err(CliError::UnsupportedProtector(kind.to_owned())),
        }
    }
}

enum CliProtector {
    Password(XSecPasswordProtector),
    System(XSecSystemProtector),
}

impl CliProtector {
    async fn check_availability(&self) -> XSecResult<()> {
        match self {
            Self::Password(_) => Ok(()),
            Self::System(protector) => protector.check_availability().await,
        }
    }
}

impl XSecProtector for CliProtector {
    fn kind(&self) -> &'static str {
        match self {
            Self::Password(protector) => protector.kind(),
            Self::System(protector) => protector.kind(),
        }
    }

    async fn wrap_key<'a>(&'a self, key: &'a SecretBox<[u8; 32]>) -> XSecResult<Vec<u8>> {
        match self {
            Self::Password(protector) => protector.wrap_key(key).await,
            Self::System(protector) => protector.wrap_key(key).await,
        }
    }

    async fn unwrap_key<'a>(&'a self, payload: &'a [u8]) -> XSecResult<SecretBox<[u8; 32]>> {
        match self {
            Self::Password(protector) => protector.unwrap_key(payload).await,
            Self::System(protector) => protector.unwrap_key(payload).await,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
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
    #[error("environment variable `{0}` is declared more than once")]
    DuplicateVariable(String),
    #[error("environment variable `{0}` contains a NUL byte")]
    InvalidVariable(String),
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("the password must not be empty")]
    EmptyPassword,
    #[error("the password exceeds {MAX_PASSWORD_SIZE} bytes")]
    PasswordTooLarge,
    #[error("standard input contains more than {MAX_PASSWORD_SIZE} password bytes")]
    PasswordInputTooLarge,
    #[error("`--identity` is required for the system protector")]
    MissingSystemIdentity,
    #[error("`--identity` can only be used with the system protector")]
    UnexpectedSystemIdentity,
    #[error("`--password-stdin` can only be used with the password protector")]
    UnexpectedPasswordInput,
    #[error("metadata has not been initialized at `{0}`")]
    MetadataNotInitialized(String),
    #[error("select a configured protector with `--protector`; available: {0}")]
    ProtectorSelectionRequired(String),
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

type CliResult<T> = Result<T, CliError>;
type FileXSec = XSec<XSecFileStorage>;

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> CliResult<u8> {
    match cli.command {
        Command::Init(args) => initialize(args).await?,
        Command::Env(args) => match args.command {
            EnvCommand::Encrypt(args) => encrypt_environment(args).await?,
            EnvCommand::Decrypt(args) => decrypt_environment(args).await?,
        },
        Command::Run(args) => return run_command(args).await,
        Command::Inspect(args) => inspect_metadata(&args.metadata).await?,
        Command::Protector(args) => match args.command {
            ProtectorCommand::List(args) => list_protectors(&args.metadata).await?,
        },
    }
    Ok(0)
}

async fn initialize(args: InitArgs) -> CliResult<()> {
    let protector = create_protector(args.protector, args.identity, args.password_stdin, true)?;
    protector.check_availability().await?;

    let mut xsec = XSec::new();
    xsec.load(XSecFileStorage::new(&args.metadata)).await?;
    xsec.create(&protector).await?;
    println!("Initialized XSec metadata at {}", args.metadata.display());
    Ok(())
}

async fn encrypt_environment(args: EncryptArgs) -> CliResult<()> {
    ensure_distinct_paths(&args.input, &args.output).await?;
    let plaintext = Zeroizing::new(read_limited(&args.input, MAX_ENV_FILE_SIZE).await?);
    validate_environment(&plaintext)?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let ciphertext = xsec.encrypt_with_aad(&plaintext, ENV_AAD)?;
    drop(plaintext);
    atomic_write(&args.output, ciphertext, args.force).await?;
    println!(
        "Encrypted {} to {}",
        args.input.display(),
        args.output.display()
    );
    Ok(())
}

async fn decrypt_environment(args: DecryptArgs) -> CliResult<()> {
    if let Some(output) = &args.output {
        ensure_distinct_paths(&args.input, output).await?;
    }
    let ciphertext = read_limited(&args.input, MAX_CIPHERTEXT_FILE_SIZE).await?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, ENV_AAD)?;
    validate_environment(&plaintext)?;

    match args.output {
        Some(output) => {
            atomic_write(&output, plaintext.to_vec(), args.force).await?;
            println!("Decrypted {} to {}", args.input.display(), output.display());
        }
        None => {
            let _ = args.stdout;
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(&plaintext)
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

async fn run_command(args: RunArgs) -> CliResult<u8> {
    let ciphertext = read_limited(&args.file, MAX_CIPHERTEXT_FILE_SIZE).await?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, ENV_AAD)?;
    let mut environment = parse_environment(&plaintext)?;
    drop(plaintext);

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

async fn inspect_metadata(path: &Path) -> CliResult<()> {
    let xsec = load_metadata(path).await?;
    println!("metadata: {}", path.display());
    println!("initialized: {}", xsec.is_initialized());
    if xsec.is_initialized() {
        println!("status: locked");
        println!("protectors: {}", protector_names(&xsec).join(", "));
    }
    Ok(())
}

async fn list_protectors(path: &Path) -> CliResult<()> {
    let xsec = load_initialized_metadata(path).await?;
    for kind in protector_names(&xsec) {
        println!("{kind}");
    }
    Ok(())
}

async fn load_and_unlock(args: &UnlockArgs) -> CliResult<FileXSec> {
    let mut xsec = load_initialized_metadata(&args.metadata).await?;
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
    let protector = create_protector(kind, args.identity.clone(), args.password_stdin, false)?;
    xsec.unlock(&protector).await?;
    Ok(xsec)
}

async fn load_metadata(path: &Path) -> CliResult<FileXSec> {
    let mut xsec = XSec::new();
    xsec.load(XSecFileStorage::new(path)).await?;
    Ok(xsec)
}

async fn load_initialized_metadata(path: &Path) -> CliResult<FileXSec> {
    let xsec = load_metadata(path).await?;
    if !xsec.is_initialized() {
        return Err(CliError::MetadataNotInitialized(path.display().to_string()));
    }
    Ok(xsec)
}

fn protector_names(xsec: &FileXSec) -> Vec<String> {
    xsec.key_protector_kinds().map(str::to_owned).collect()
}

fn create_protector(
    kind: ProtectorKind,
    identity: Option<String>,
    password_stdin: bool,
    confirm_password: bool,
) -> CliResult<CliProtector> {
    match kind {
        ProtectorKind::Password => {
            if identity.is_some() {
                return Err(CliError::UnexpectedSystemIdentity);
            }
            let password = read_password(password_stdin, confirm_password)?;
            Ok(CliProtector::Password(XSecPasswordProtector::new(password)))
        }
        ProtectorKind::System => {
            if password_stdin {
                return Err(CliError::UnexpectedPasswordInput);
            }
            let identity = identity.ok_or(CliError::MissingSystemIdentity)?;
            Ok(CliProtector::System(XSecSystemProtector::new(identity)))
        }
    }
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

fn strip_line_ending(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

fn validate_environment(bytes: &[u8]) -> CliResult<()> {
    let mut environment = parse_environment(bytes)?;
    zeroize_environment(&mut environment);
    Ok(())
}

fn parse_environment(bytes: &[u8]) -> CliResult<Vec<(String, String)>> {
    let mut environment = Vec::new();
    let mut names = HashSet::new();
    for entry in dotenvy::from_read_iter(bytes) {
        let (key, value) = match entry {
            Ok(entry) => entry,
            Err(_) => {
                zeroize_environment(&mut environment);
                return Err(CliError::InvalidEnvironment);
            }
        };
        if key.contains('\0') || value.contains('\0') {
            let mut value = value;
            value.zeroize();
            zeroize_environment(&mut environment);
            return Err(CliError::InvalidVariable(key));
        }
        let comparison_key = normalized_environment_key(&key);
        if !names.insert(comparison_key) {
            let mut value = value;
            value.zeroize();
            zeroize_environment(&mut environment);
            return Err(CliError::DuplicateVariable(key));
        }
        environment.push((key, value));
    }
    Ok(environment)
}

#[cfg(target_os = "windows")]
fn normalized_environment_key(key: &str) -> String {
    key.to_ascii_uppercase()
}

#[cfg(not(target_os = "windows"))]
fn normalized_environment_key(key: &str) -> String {
    key.to_owned()
}

fn zeroize_environment(environment: &mut Vec<(String, String)>) {
    for (key, value) in environment {
        key.zeroize();
        value.zeroize();
    }
}

async fn read_limited(path: &Path, limit: usize) -> CliResult<Vec<u8>> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|source| io_error(format!("failed to inspect `{}`", path.display()), source))?;
    if metadata.len() > limit as u64 {
        return Err(CliError::FileTooLarge {
            path: path.display().to_string(),
            limit,
        });
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|source| io_error(format!("failed to read `{}`", path.display()), source))?;
    if bytes.len() > limit {
        return Err(CliError::FileTooLarge {
            path: path.display().to_string(),
            limit,
        });
    }
    Ok(bytes)
}

async fn ensure_distinct_paths(input: &Path, output: &Path) -> CliResult<()> {
    if input == output {
        return Err(CliError::SameInputAndOutput);
    }
    if tokio::fs::try_exists(output)
        .await
        .map_err(|source| io_error(format!("failed to inspect `{}`", output.display()), source))?
    {
        let input = tokio::fs::canonicalize(input).await.map_err(|source| {
            io_error(format!("failed to resolve `{}`", input.display()), source)
        })?;
        let output = tokio::fs::canonicalize(output).await.map_err(|source| {
            io_error(format!("failed to resolve `{}`", output.display()), source)
        })?;
        if input == output {
            return Err(CliError::SameInputAndOutput);
        }
    }
    Ok(())
}

async fn atomic_write(path: &Path, data: Vec<u8>, overwrite: bool) -> CliResult<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let data = Zeroizing::new(data);
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).map_err(|source| {
            io_error(format!("failed to create `{}`", parent.display()), source)
        })?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| {
            io_error(
                format!(
                    "failed to create a temporary file in `{}`",
                    parent.display()
                ),
                source,
            )
        })?;
        temporary
            .write_all(&data)
            .map_err(|source| io_error(format!("failed to write `{}`", path.display()), source))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|source| {
                    io_error(
                        format!("failed to set permissions on `{}`", path.display()),
                        source,
                    )
                })?;
        }

        temporary
            .as_file()
            .sync_all()
            .map_err(|source| io_error(format!("failed to sync `{}`", path.display()), source))?;

        if overwrite {
            temporary.persist(&path).map_err(|error| {
                io_error(
                    format!("failed to replace `{}`", path.display()),
                    error.error,
                )
            })?;
        } else {
            temporary.persist_noclobber(&path).map_err(|error| {
                if error.error.kind() == io::ErrorKind::AlreadyExists {
                    CliError::OutputExists(path.display().to_string())
                } else {
                    io_error(
                        format!("failed to create `{}`", path.display()),
                        error.error,
                    )
                }
            })?;
        }

        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| {
                io_error(
                    format!("failed to sync directory `{}`", parent.display()),
                    source,
                )
            })?;
        Ok(())
    })
    .await
    .map_err(|_| CliError::FileTaskFailed)?
}

fn io_error(context: impl Into<String>, source: io::Error) -> CliError {
    CliError::Io {
        context: context.into(),
        source,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_run_command_after_separator() {
        let cli =
            Cli::try_parse_from(["xsec", "run", "-f", ".xsec.test", "--", "printenv"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Run(RunArgs { file, command, .. })
                if file == PathBuf::from(".xsec.test")
                    && command == vec![OsString::from("printenv")]
        ));
    }

    #[test]
    fn rejects_stdout_with_output_file() {
        assert!(
            Cli::try_parse_from(["xsec", "env", "decrypt", "--stdout", "--output", ".env"])
                .is_err()
        );
    }

    #[test]
    fn parses_environment_without_mutating_process_environment() {
        let environment = parse_environment(b"FIRST=one\nSECOND=\"two words\"\n").unwrap();
        assert_eq!(
            environment,
            vec![
                ("FIRST".to_owned(), "one".to_owned()),
                ("SECOND".to_owned(), "two words".to_owned())
            ]
        );
    }

    #[test]
    fn rejects_duplicate_environment_variables() {
        assert!(matches!(
            parse_environment(b"DUPLICATE=one\nDUPLICATE=two\n"),
            Err(CliError::DuplicateVariable(key)) if key == "DUPLICATE"
        ));
    }

    #[test]
    fn strips_one_terminal_line_ending_from_stdin_password() {
        let mut password = b"secret\r\n".to_vec();
        strip_line_ending(&mut password);
        assert_eq!(password, b"secret");
    }
}
