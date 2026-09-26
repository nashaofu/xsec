use xsec::{XSec, XSecFileStorage};

use crate::{cli::InitArgs, error::CliResult, storage::password_protector};

pub(super) async fn execute(args: InitArgs) -> CliResult<()> {
    let protector = password_protector(args.password, true)?;

    let mut xsec = XSec::new();
    xsec.load(XSecFileStorage::new(&args.storage)).await?;
    xsec.create(&protector).await?;
    println!("Initialized XSec storage at {}", args.storage.display());
    Ok(())
}
