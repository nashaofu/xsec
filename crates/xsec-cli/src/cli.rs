use std::{ffi::OsString, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::error::{CliError, CliResult};

pub(crate) const DEFAULT_STORAGE_PATH: &str = ".xsec.keys";
const DEFAULT_ENV_INPUT_PATH: &str = ".env";
const DEFAULT_ENCRYPTED_ENV_PATH: &str = ".xsec";

#[derive(Parser)]
#[command(name = "xsec", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
    /// Initialize the project key storage.
    Init(InitArgs),
    /// Show non-secret storage information.
    Inspect(InspectArgs),
    /// Inspect configured key protectors.
    Protector(ProtectorArgs),
}

#[derive(Args)]
pub(crate) struct InitArgs {
    /// Path used to persist protected key material.
    #[arg(long, default_value = DEFAULT_STORAGE_PATH)]
    pub(crate) storage: PathBuf,
    /// Read the password from standard input instead of prompting.
    #[arg(long)]
    pub(crate) password: bool,
}

#[derive(Args)]
pub(crate) struct EncryptArgs {
    /// Plaintext dotenv input.
    #[arg(short, long, default_value = DEFAULT_ENV_INPUT_PATH)]
    pub(crate) input: PathBuf,
    /// Encrypted output.
    #[arg(short, long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    pub(crate) output: PathBuf,
    /// Replace an existing encrypted output.
    #[arg(long)]
    pub(crate) force: bool,
    #[command(flatten)]
    pub(crate) unlock: UnlockArgs,
}

#[derive(Args)]
pub(crate) struct DecryptArgs {
    /// Encrypted environment input.
    #[arg(short, long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    pub(crate) input: PathBuf,
    /// Write plaintext to a file instead of standard output.
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,
    /// Write plaintext to standard output.
    #[arg(long, conflicts_with = "output")]
    pub(crate) stdout: bool,
    /// Replace an existing plaintext output.
    #[arg(long, requires = "output")]
    pub(crate) force: bool,
    #[command(flatten)]
    pub(crate) unlock: UnlockArgs,
}

#[derive(Args)]
pub(crate) struct GetArgs {
    /// Environment variable name.
    pub(crate) key: String,
    /// Encrypted environment input.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    pub(crate) file: PathBuf,
    #[command(flatten)]
    pub(crate) unlock: UnlockArgs,
}

#[derive(Args)]
pub(crate) struct SetArgs {
    /// Environment variable name.
    pub(crate) key: String,
    /// Environment variable value. Prompts securely when omitted.
    pub(crate) value: Option<String>,
    /// Encrypted environment file to update.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    pub(crate) file: PathBuf,
    #[command(flatten)]
    pub(crate) unlock: UnlockArgs,
}

#[derive(Args)]
pub(crate) struct DelArgs {
    /// Environment variable name.
    pub(crate) key: String,
    /// Encrypted environment file to update.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    pub(crate) file: PathBuf,
}

#[derive(Args)]
pub(crate) struct RunArgs {
    /// Encrypted environment input.
    #[arg(short = 'f', long, default_value = DEFAULT_ENCRYPTED_ENV_PATH)]
    pub(crate) file: PathBuf,
    /// Override environment variables already present in the process.
    #[arg(short = 'o', long)]
    pub(crate) r#override: bool,
    #[command(flatten)]
    pub(crate) unlock: UnlockArgs,
    /// Command and arguments to execute.
    #[arg(last = true, required = true)]
    pub(crate) command: Vec<OsString>,
}

#[derive(Args)]
pub(crate) struct UnlockArgs {
    /// Path containing protected key material.
    #[arg(long, default_value = DEFAULT_STORAGE_PATH)]
    pub(crate) storage: PathBuf,
    /// Protector to use when more than one is configured.
    #[arg(long, value_enum)]
    pub(crate) protector: Option<ProtectorKind>,
    /// Read the password from standard input instead of prompting.
    #[arg(long)]
    pub(crate) password: bool,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    /// Path containing protected key material.
    #[arg(long, default_value = DEFAULT_STORAGE_PATH)]
    pub(crate) storage: PathBuf,
}

#[derive(Args)]
pub(crate) struct ProtectorArgs {
    #[command(subcommand)]
    pub(crate) command: ProtectorCommand,
}

#[derive(Subcommand)]
pub(crate) enum ProtectorCommand {
    /// List protector hints stored in the configured storage.
    List(InspectArgs),
    /// Add another protector to the configured storage.
    Add(ProtectorAddArgs),
    /// Remove a protector from the configured storage.
    Remove(RemoveProtectorArgs),
}

#[derive(Args)]
pub(crate) struct ProtectorAddArgs {
    #[command(subcommand)]
    pub(crate) protector: ProtectorAddCommand,
}

#[derive(Subcommand)]
pub(crate) enum ProtectorAddCommand {
    /// Add system protection to password-initialized storage.
    System(AddSystemProtectorArgs),
}

#[derive(Args)]
pub(crate) struct AddSystemProtectorArgs {
    /// Stable logical identity for the system protector.
    #[arg(long)]
    pub(crate) identity: String,
    /// Path containing protected key material.
    #[arg(long, default_value = DEFAULT_STORAGE_PATH)]
    pub(crate) storage: PathBuf,
    /// Read the existing password from standard input instead of prompting.
    #[arg(long)]
    pub(crate) password: bool,
}

#[derive(Args)]
pub(crate) struct RemoveProtectorArgs {
    /// Protector to remove.
    #[arg(value_enum)]
    pub(crate) kind: ProtectorKind,
    /// Path containing protected key material.
    #[arg(long, default_value = DEFAULT_STORAGE_PATH)]
    pub(crate) storage: PathBuf,
    /// Protector used to authorize the removal.
    #[arg(long, value_enum)]
    pub(crate) unlock_with: Option<ProtectorKind>,
    /// Read the password from standard input instead of prompting.
    #[arg(long)]
    pub(crate) password: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ProtectorKind {
    Password,
    System,
}

impl ProtectorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::System => "system",
        }
    }

    pub(crate) fn from_kind(kind: &str) -> CliResult<Self> {
        match kind {
            "password" => Ok(Self::Password),
            "system" => Ok(Self::System),
            _ => Err(CliError::UnsupportedProtector(kind.to_owned())),
        }
    }
}
