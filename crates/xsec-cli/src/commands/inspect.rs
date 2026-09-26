use crate::{
    cli::InspectArgs,
    error::CliResult,
    storage::{load_storage, protector_names},
};

pub(super) async fn execute(args: InspectArgs) -> CliResult<()> {
    let xsec = load_storage(&args.storage).await?;
    println!("storage: {}", args.storage.display());
    println!("initialized: {}", xsec.is_initialized());
    if xsec.is_initialized() {
        println!("status: locked");
        println!("protectors: {}", protector_names(&xsec).join(", "));
    }
    Ok(())
}
