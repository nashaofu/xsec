use std::{
    collections::HashSet,
    ffi::OsString,
    io::{self, Read, Write},
    ops::Range,
    path::{Path, PathBuf},
    process::{ExitCode, ExitStatus, Stdio},
};

use base64ct::{Base64, Encoding};
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
const ENV_VALUE_AAD: &[u8] = b"xsec-cli:env:value:v1\0";
const ENCRYPTED_VALUE_PREFIX: &str = "encrypted:xsec:";
const MAX_ENV_FILE_SIZE: usize = 1024 * 1024;
const MAX_ENCRYPTED_ENV_FILE_SIZE: usize = MAX_ENV_FILE_SIZE * 16;
const MAX_PASSWORD_SIZE: usize = 4096;

#[derive(Parser)]
#[command(name = "xsec", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decrypt an environment file and run a command.
    Run(RunArgs),
    /// Print one decrypted environment value.
    Get(GetArgs),
    /// Set one environment value and re-encrypt the document.
    Set(SetArgs),
    /// Remove one environment value and re-encrypt the document.
    Del(DelArgs),
    /// Encrypt values in a dotenv document.
    Encrypt(EncryptArgs),
    /// Decrypt an environment document.
    Decrypt(DecryptArgs),
    /// Initialize the project key metadata.
    Init(InitArgs),
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
struct GetArgs {
    /// Environment variable name.
    key: String,
    /// Encrypted environment input.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    file: PathBuf,
    #[command(flatten)]
    unlock: UnlockArgs,
}

#[derive(Args)]
struct SetArgs {
    /// Environment variable name.
    key: String,
    /// Environment variable value. Prompts without echo when omitted.
    #[arg(conflicts_with = "stdin")]
    value: Option<String>,
    /// Encrypted environment file to update.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    file: PathBuf,
    /// Read the exact value from standard input instead of prompting.
    #[arg(long, conflicts_with = "value")]
    stdin: bool,
    #[command(flatten)]
    unlock: UnlockArgs,
}

#[derive(Args)]
struct DelArgs {
    /// Environment variable name.
    key: String,
    /// Encrypted environment file to update.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    file: PathBuf,
}

#[derive(Args)]
struct RunArgs {
    /// Encrypted environment input.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    file: PathBuf,
    /// Override environment variables already present in the process.
    #[arg(short = 'o', long)]
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
    #[error("`--stdin` and `--password-stdin` cannot be used together")]
    ConflictingStandardInput,
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
        Command::Run(args) => return run_command(args).await,
        Command::Get(args) => return get_environment(args).await,
        Command::Set(args) => set_environment(args).await?,
        Command::Del(args) => return delete_environment(args).await,
        Command::Encrypt(args) => encrypt_environment(args).await?,
        Command::Decrypt(args) => decrypt_environment(args).await?,
        Command::Init(args) => initialize(args).await?,
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

async fn decrypt_environment(args: DecryptArgs) -> CliResult<()> {
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

async fn get_environment(args: GetArgs) -> CliResult<u8> {
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

async fn set_environment(args: SetArgs) -> CliResult<()> {
    validate_variable_name(&args.key)?;
    if args.stdin && args.unlock.password_stdin {
        return Err(CliError::ConflictingStandardInput);
    }
    let value = read_environment_value(args.value, args.stdin)?;
    let original = read_limited(&args.file, MAX_ENCRYPTED_ENV_FILE_SIZE).await?;
    let xsec = load_and_unlock(&args.unlock).await?;
    let mut document = load_environment_document(original.clone())?;
    let encryption_key = document
        .stored_name(&args.key)
        .unwrap_or(args.key.as_str())
        .to_owned();
    let encrypted = encrypt_environment_value(&encryption_key, &value, &xsec)?;
    document.set(&args.key, &encrypted)?;
    validate_environment(&document.source)?;
    atomic_replace_if_unchanged(&args.file, document.source.to_vec(), original).await
}

async fn delete_environment(args: DelArgs) -> CliResult<u8> {
    validate_variable_name(&args.key)?;
    let original = read_limited(&args.file, MAX_ENCRYPTED_ENV_FILE_SIZE).await?;
    let mut document = load_environment_document(original.clone())?;
    if !document.unset(&args.key) {
        return Ok(1);
    }
    validate_environment(&document.source)?;
    atomic_replace_if_unchanged(&args.file, document.source.to_vec(), original).await?;
    Ok(0)
}

async fn run_command(args: RunArgs) -> CliResult<u8> {
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

struct EnvDocument {
    source: Zeroizing<Vec<u8>>,
    entries: Vec<EnvEntry>,
}

struct EnvEntry {
    name: String,
    declaration: Range<usize>,
    value: Range<usize>,
}

impl EnvDocument {
    fn parse(source: Zeroizing<Vec<u8>>) -> CliResult<Self> {
        let mut environment = parse_environment(&source)?;
        let entries = index_environment(&source)?;
        let matches = entries.len() == environment.len()
            && entries
                .iter()
                .zip(&environment)
                .all(|(entry, (name, _))| entry.name == *name);
        zeroize_environment(&mut environment);
        if !matches {
            return Err(CliError::InvalidEnvironment);
        }
        Ok(Self { source, entries })
    }

    fn set(&mut self, key: &str, value: &[u8]) -> CliResult<()> {
        let mut encoded = encode_environment_value(value)?;
        let comparison_key = normalized_environment_key(key);
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| normalized_environment_key(&entry.name) == comparison_key)
        {
            if self.source.get(entry.value.end) == Some(&b'#') {
                encoded.push(b' ');
            }
            self.source
                .splice(entry.value.clone(), encoded.iter().copied());
        } else {
            self.append(key.as_bytes(), &encoded);
        }
        if self.source.len() > MAX_ENCRYPTED_ENV_FILE_SIZE {
            return Err(CliError::UpdatedEnvironmentTooLarge);
        }
        Ok(())
    }

    fn stored_name(&self, key: &str) -> Option<&str> {
        let comparison_key = normalized_environment_key(key);
        self.entries
            .iter()
            .find(|entry| normalized_environment_key(&entry.name) == comparison_key)
            .map(|entry| entry.name.as_str())
    }

    fn unset(&mut self, key: &str) -> bool {
        let comparison_key = normalized_environment_key(key);
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| normalized_environment_key(&entry.name) == comparison_key)
        else {
            return false;
        };
        self.source.drain(entry.declaration.clone());
        true
    }

    fn append(&mut self, key: &[u8], encoded: &[u8]) {
        let newline = if self.source.windows(2).any(|value| value == b"\r\n") {
            b"\r\n".as_slice()
        } else {
            b"\n".as_slice()
        };
        let had_terminal_newline = self.source.ends_with(b"\n");
        if !self.source.is_empty() && !had_terminal_newline {
            self.source.extend_from_slice(newline);
        }
        self.source.extend_from_slice(key);
        self.source.push(b'=');
        self.source.extend_from_slice(encoded);
        if had_terminal_newline {
            self.source.extend_from_slice(newline);
        }
    }

    fn replace_values(
        &mut self,
        replacements: Vec<(Range<usize>, Zeroizing<Vec<u8>>)>,
    ) -> CliResult<()> {
        for (range, value) in replacements.into_iter().rev() {
            self.source.splice(range, value.iter().copied());
        }
        self.entries = index_environment(&self.source)?;
        Ok(())
    }
}

fn encrypt_environment_document(document: &mut EnvDocument, xsec: &FileXSec) -> CliResult<()> {
    let mut environment = parse_environment(&document.source)?;
    let mut replacements = Vec::new();
    let result = document.entries.iter().zip(&environment).try_for_each(
        |(entry, (key, value))| -> CliResult<()> {
            if value.starts_with(ENCRYPTED_VALUE_PREFIX) {
                decrypt_environment_value(key, value, xsec)?;
                return Ok(());
            }
            let encrypted = encrypt_environment_value(key, value.as_bytes(), xsec)?;
            replacements.push((entry.value.clone(), encode_environment_value(&encrypted)?));
            Ok(())
        },
    );
    zeroize_environment(&mut environment);
    result?;
    document.replace_values(replacements)?;
    if document.source.len() > MAX_ENCRYPTED_ENV_FILE_SIZE {
        return Err(CliError::UpdatedEnvironmentTooLarge);
    }
    validate_environment(&document.source)
}

fn decrypt_environment_document(document: &mut EnvDocument, xsec: &FileXSec) -> CliResult<()> {
    let mut environment = parse_environment(&document.source)?;
    let mut replacements = Vec::new();
    let result = document.entries.iter().zip(&environment).try_for_each(
        |(entry, (key, value))| -> CliResult<()> {
            if value.starts_with(ENCRYPTED_VALUE_PREFIX) {
                let plaintext = decrypt_environment_value(key, value, xsec)?;
                replacements.push((entry.value.clone(), encode_environment_value(&plaintext)?));
            }
            Ok(())
        },
    );
    zeroize_environment(&mut environment);
    result?;
    document.replace_values(replacements)?;
    if document.source.len() > MAX_ENV_FILE_SIZE {
        return Err(CliError::DecryptedEnvironmentTooLarge);
    }
    validate_environment(&document.source)
}

fn decrypt_environment_values(
    document: &EnvDocument,
    xsec: &FileXSec,
) -> CliResult<Vec<(String, String)>> {
    let mut environment = parse_environment(&document.source)?;
    let result = environment
        .iter_mut()
        .try_for_each(|(key, value)| -> CliResult<()> {
            let plaintext = decrypt_environment_value(key, value, xsec)?;
            let decoded = std::str::from_utf8(&plaintext)
                .map_err(|_| CliError::InvalidEncryptedVariable(key.clone()))?
                .to_owned();
            value.zeroize();
            *value = decoded;
            Ok(())
        });
    if let Err(error) = result {
        zeroize_environment(&mut environment);
        return Err(error);
    }
    Ok(environment)
}

fn encrypt_environment_value(
    key: &str,
    value: &[u8],
    xsec: &FileXSec,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let ciphertext = xsec.encrypt_with_aad(value, &environment_value_aad(key))?;
    let encoded = Base64::encode_string(&ciphertext);
    let mut result = Zeroizing::new(Vec::with_capacity(
        ENCRYPTED_VALUE_PREFIX.len() + encoded.len(),
    ));
    result.extend_from_slice(ENCRYPTED_VALUE_PREFIX.as_bytes());
    result.extend_from_slice(encoded.as_bytes());
    Ok(result)
}

fn decrypt_environment_value(
    key: &str,
    value: &str,
    xsec: &FileXSec,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let Some(encoded) = value.strip_prefix(ENCRYPTED_VALUE_PREFIX) else {
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    };
    let ciphertext = Base64::decode_vec(encoded)
        .map_err(|_| CliError::InvalidEncryptedVariable(key.to_owned()))?;
    xsec.decrypt_with_aad(&ciphertext, &environment_value_aad(key))
        .map_err(|_| CliError::InvalidEncryptedVariable(key.to_owned()))
}

fn environment_value_aad(key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENV_VALUE_AAD.len() + key.len());
    aad.extend_from_slice(ENV_VALUE_AAD);
    aad.extend_from_slice(key.as_bytes());
    aad
}

fn load_environment_document(encrypted: Vec<u8>) -> CliResult<EnvDocument> {
    EnvDocument::parse(Zeroizing::new(encrypted))
}

fn index_environment(source: &[u8]) -> CliResult<Vec<EnvEntry>> {
    std::str::from_utf8(source).map_err(|_| CliError::InvalidEnvironment)?;
    let mut entries = Vec::new();
    let mut start = 0;
    while start < source.len() {
        let end = environment_declaration_end(source, start);
        if let Some(entry) = index_environment_declaration(source, start..end)? {
            entries.push(entry);
        }
        start = end;
    }
    Ok(entries)
}

fn environment_declaration_end(source: &[u8], start: usize) -> usize {
    let mut quote = None;
    let mut escaped = false;
    let mut comment = false;
    let mut whitespace = true;
    let mut index = start;

    while index < source.len() {
        let byte = source[index];
        if byte == b'\n' && quote.is_none() {
            return index + 1;
        }
        if comment {
            index += 1;
            continue;
        }
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            match byte {
                b'\\' => escaped = true,
                value if value == delimiter => quote = None,
                _ => {}
            }
            index += 1;
            continue;
        }
        match byte {
            b'#' if whitespace => comment = true,
            b'\'' | b'"' => {
                quote = Some(byte);
                whitespace = false;
            }
            b'\\' => {
                escaped = true;
                whitespace = false;
            }
            b' ' | b'\t' | b'\r' => whitespace = true,
            _ => whitespace = false,
        }
        index += 1;
    }
    source.len()
}

fn index_environment_declaration(
    source: &[u8],
    declaration: Range<usize>,
) -> CliResult<Option<EnvEntry>> {
    let mut content_end = declaration.end;
    if content_end > declaration.start && source[content_end - 1] == b'\n' {
        content_end -= 1;
        if content_end > declaration.start && source[content_end - 1] == b'\r' {
            content_end -= 1;
        }
    }

    let mut index = skip_environment_whitespace(source, declaration.start, content_end);
    if index == content_end || source[index] == b'#' {
        return Ok(None);
    }

    let (mut name, next) = parse_environment_name(source, index, content_end)?;
    index = skip_environment_whitespace(source, next, content_end);
    if name == "export" && source.get(index) != Some(&b'=') {
        let parsed = parse_environment_name(source, index, content_end)?;
        name = parsed.0;
        index = skip_environment_whitespace(source, parsed.1, content_end);
    }
    if source.get(index) != Some(&b'=') {
        return Err(CliError::InvalidEnvironment);
    }
    index = skip_environment_whitespace(source, index + 1, content_end);
    let value_start = index;
    let value_end = environment_value_end(source, value_start, content_end);

    Ok(Some(EnvEntry {
        name,
        declaration,
        value: value_start..value_end,
    }))
}

fn parse_environment_name(source: &[u8], start: usize, end: usize) -> CliResult<(String, usize)> {
    if start == end || !(source[start].is_ascii_alphabetic() || source[start] == b'_') {
        return Err(CliError::InvalidEnvironment);
    }
    let mut index = start + 1;
    while index < end
        && (source[index].is_ascii_alphanumeric() || source[index] == b'_' || source[index] == b'.')
    {
        index += 1;
    }
    let name = std::str::from_utf8(&source[start..index])
        .map_err(|_| CliError::InvalidEnvironment)?
        .to_owned();
    Ok((name, index))
}

fn skip_environment_whitespace(source: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && source[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn environment_value_end(source: &[u8], start: usize, end: usize) -> usize {
    if source.get(start) == Some(&b'#') {
        return start;
    }
    let mut quote = None;
    let mut escaped = false;
    let mut index = start;
    while index < end {
        let byte = source[index];
        if escaped {
            escaped = false;
        } else if let Some(delimiter) = quote {
            match byte {
                b'\\' => escaped = true,
                value if value == delimiter => quote = None,
                _ => {}
            }
        } else {
            match byte {
                b'\\' => escaped = true,
                b'\'' | b'"' => quote = Some(byte),
                b' ' | b'\t' => return index,
                _ => {}
            }
        }
        index += 1;
    }
    end
}

fn validate_variable_name(key: &str) -> CliResult<()> {
    let bytes = key.as_bytes();
    if bytes.is_empty()
        || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'.')
    {
        return Err(CliError::InvalidVariableName(key.to_owned()));
    }
    Ok(())
}

fn read_environment_value(
    argument: Option<String>,
    from_stdin: bool,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let value = if let Some(value) = argument {
        value.into_bytes()
    } else if from_stdin {
        let mut bytes = Vec::new();
        io::stdin()
            .take((MAX_ENV_FILE_SIZE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| {
                io_error(
                    "failed to read environment value from standard input",
                    source,
                )
            })?;
        if bytes.len() > MAX_ENV_FILE_SIZE {
            bytes.zeroize();
            return Err(CliError::EnvironmentValueTooLarge);
        }
        bytes
    } else {
        rpassword::prompt_password("Value: ")
            .map_err(|source| io_error("failed to read environment value", source))?
            .into_bytes()
    };
    let value = Zeroizing::new(value);
    if value.len() > MAX_ENV_FILE_SIZE {
        return Err(CliError::EnvironmentValueTooLarge);
    }
    if value.contains(&b'\0') || value.contains(&b'\r') || std::str::from_utf8(&value).is_err() {
        return Err(CliError::InvalidEnvironmentValue);
    }
    Ok(value)
}

fn encode_environment_value(value: &[u8]) -> CliResult<Zeroizing<Vec<u8>>> {
    if value.contains(&b'\0') || std::str::from_utf8(value).is_err() {
        return Err(CliError::InvalidEnvironmentValue);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(value.len() + 2));
    encoded.push(b'"');
    for byte in value {
        match byte {
            b'\\' => encoded.extend_from_slice(b"\\\\"),
            b'"' => encoded.extend_from_slice(b"\\\""),
            b'$' => encoded.extend_from_slice(b"\\$"),
            b'\n' => encoded.extend_from_slice(b"\\n"),
            value => encoded.push(*value),
        }
    }
    encoded.push(b'"');
    Ok(encoded)
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

async fn atomic_replace_if_unchanged(
    path: &Path,
    data: Vec<u8>,
    expected: Vec<u8>,
) -> CliResult<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let data = Zeroizing::new(data);
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
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

        let current = std::fs::read(&path).map_err(|source| {
            io_error(format!("failed to re-read `{}`", path.display()), source)
        })?;
        if current != expected {
            return Err(CliError::ConcurrentModification(path.display().to_string()));
        }
        temporary.persist(&path).map_err(|error| {
            io_error(
                format!("failed to replace `{}`", path.display()),
                error.error,
            )
        })?;

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

    async fn create_test_xsec() -> (tempfile::TempDir, FileXSec) {
        let directory = tempfile::tempdir().unwrap();
        let protector = XSecPasswordProtector::new(SecretBox::new(Box::new(b"password".to_vec())));
        let mut xsec = XSec::new();
        xsec.load(XSecFileStorage::new(directory.path().join("metadata")))
            .await
            .unwrap();
        xsec.create(&protector).await.unwrap();
        (directory, xsec)
    }

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
        assert!(Cli::try_parse_from(["xsec", "decrypt", "--stdout", "--output", ".env"]).is_err());
    }

    #[test]
    fn parses_top_level_set_with_a_positional_value() {
        let cli =
            Cli::try_parse_from(["xsec", "set", "TOKEN", "secret", "-f", ".xsec.test"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Set(SetArgs {
                key,
                value: Some(value),
                file,
                ..
            }) if key == "TOKEN"
                && value == "secret"
                && file == PathBuf::from(".xsec.test")
        ));
    }

    #[test]
    fn rejects_set_value_with_stdin() {
        assert!(Cli::try_parse_from(["xsec", "set", "TOKEN", "secret", "--stdin"]).is_err());
    }

    #[test]
    fn parses_top_level_del() {
        let cli = Cli::try_parse_from(["xsec", "del", "TOKEN", "-f", ".xsec.test"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Del(DelArgs { key, file, .. })
                if key == "TOKEN" && file == PathBuf::from(".xsec.test")
        ));
    }

    #[test]
    fn set_preserves_document_formatting_and_other_values() {
        let source = Zeroizing::new(
            b"# heading\r\nexport FIRST = 'old' # keep\r\nMULTI=\"line1\r\nline2\"\r\nEMPTY=   # empty\r\n"
                .to_vec(),
        );
        let mut document = EnvDocument::parse(source).unwrap();

        document.set("FIRST", b"new $\"\n\\").unwrap();

        assert_eq!(
            document.source.as_slice(),
            b"# heading\r\nexport FIRST = \"new \\$\\\"\\n\\\\\" # keep\r\nMULTI=\"line1\r\nline2\"\r\nEMPTY=   # empty\r\n"
        );
        validate_environment(&document.source).unwrap();
    }

    #[test]
    fn set_preserves_an_inline_comment_after_an_empty_value() {
        let mut document =
            EnvDocument::parse(Zeroizing::new(b"EMPTY=   # keep\n".to_vec())).unwrap();

        document.set("EMPTY", b"value").unwrap();

        assert_eq!(document.source.as_slice(), b"EMPTY=   \"value\" # keep\n");
    }

    #[test]
    fn set_appends_with_the_existing_newline_style() {
        let mut document = EnvDocument::parse(Zeroizing::new(b"FIRST=one\r\n".to_vec())).unwrap();

        document.set("SECOND", b"two").unwrap();

        assert_eq!(
            document.source.as_slice(),
            b"FIRST=one\r\nSECOND=\"two\"\r\n"
        );
    }

    #[test]
    fn unset_removes_only_the_exact_multiline_declaration() {
        let source =
            Zeroizing::new(b"KEY=\"first\nsecond\"\nKEY_SUFFIX=keep\n# trailing\n".to_vec());
        let mut document = EnvDocument::parse(source).unwrap();

        assert!(document.unset("KEY"));

        assert_eq!(document.source.as_slice(), b"KEY_SUFFIX=keep\n# trailing\n");
    }

    #[test]
    fn unset_reports_a_missing_exact_key_without_changes() {
        let source = b"KEY_SUFFIX=keep\n".to_vec();
        let mut document = EnvDocument::parse(Zeroizing::new(source.clone())).unwrap();

        assert!(!document.unset("KEY"));

        assert_eq!(document.source.as_slice(), source);
    }

    #[test]
    fn environment_value_encoding_round_trips() {
        let encoded = encode_environment_value(b"slash\\ quote\" dollar$ line\n").unwrap();
        let mut document = b"VALUE=".to_vec();
        document.extend_from_slice(&encoded);
        document.push(b'\n');

        assert_eq!(
            parse_environment(&document).unwrap(),
            vec![(
                "VALUE".to_owned(),
                "slash\\ quote\" dollar$ line\n".to_owned()
            )]
        );
    }

    #[tokio::test]
    async fn encrypts_and_decrypts_each_environment_value() {
        let (_directory, xsec) = create_test_xsec().await;
        let source = Zeroizing::new(b"# heading\nFIRST=one # keep\nSECOND=one\n".to_vec());
        let mut document = EnvDocument::parse(source).unwrap();

        encrypt_environment_document(&mut document, &xsec).unwrap();

        let encrypted = parse_environment(&document.source).unwrap();
        assert!(
            encrypted
                .iter()
                .all(|(_, value)| value.starts_with(ENCRYPTED_VALUE_PREFIX))
        );
        assert_ne!(encrypted[0].1, encrypted[1].1);
        let encrypted_source = std::str::from_utf8(&document.source).unwrap();
        assert!(encrypted_source.starts_with("# heading\n"));
        assert!(encrypted_source.contains(" # keep\nSECOND=\"encrypted:xsec:"));

        decrypt_environment_document(&mut document, &xsec).unwrap();

        assert_eq!(
            parse_environment(&document.source).unwrap(),
            vec![
                ("FIRST".to_owned(), "one".to_owned()),
                ("SECOND".to_owned(), "one".to_owned())
            ]
        );
        assert!(document.source.starts_with(b"# heading\n"));
    }

    #[tokio::test]
    async fn encryption_is_idempotent_for_encrypted_values() {
        let (_directory, xsec) = create_test_xsec().await;
        let mut document = EnvDocument::parse(Zeroizing::new(b"KEY=value\n".to_vec())).unwrap();
        encrypt_environment_document(&mut document, &xsec).unwrap();
        let encrypted = document.source.clone();

        encrypt_environment_document(&mut document, &xsec).unwrap();

        assert_eq!(document.source, encrypted);
    }

    #[tokio::test]
    async fn encrypted_value_is_bound_to_its_key() {
        let (_directory, xsec) = create_test_xsec().await;
        let encrypted = encrypt_environment_value("FIRST", b"secret", &xsec).unwrap();
        let encrypted = std::str::from_utf8(&encrypted).unwrap();

        assert!(matches!(
            decrypt_environment_value("SECOND", encrypted, &xsec),
            Err(CliError::InvalidEncryptedVariable(key)) if key == "SECOND"
        ));
    }

    #[test]
    fn rejects_legacy_whole_document_ciphertext() {
        assert!(matches!(
            load_environment_document(b"XSecCT legacy ciphertext".to_vec()),
            Err(CliError::InvalidEnvironment)
        ));
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
