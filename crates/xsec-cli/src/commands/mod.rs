mod decrypt;
mod del;
mod encrypt;
mod get;
mod init;
mod inspect;
mod protector;
mod run;
mod set;

use crate::{
    cli::{Cli, Command},
    error::CliResult,
};

pub(crate) async fn execute(cli: Cli) -> CliResult<u8> {
    match cli.command {
        Command::Run(args) => return run::execute(args).await,
        Command::Get(args) => return get::execute(args).await,
        Command::Set(args) => set::execute(args).await?,
        Command::Del(args) => return del::execute(args).await,
        Command::Encrypt(args) => encrypt::execute(args).await?,
        Command::Decrypt(args) => decrypt::execute(args).await?,
        Command::Init(args) => init::execute(args).await?,
        Command::Inspect(args) => inspect::execute(args).await?,
        Command::Protector(args) => protector::execute(args).await?,
    }
    Ok(0)
}
