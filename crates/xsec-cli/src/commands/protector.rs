use xsec::XSecSystemProtector;

use crate::{
    cli::{
        AddSystemProtectorArgs, ProtectorAddCommand, ProtectorArgs, ProtectorCommand,
        ProtectorKind, RemoveProtectorArgs,
    },
    error::{CliError, CliResult},
    storage::{load_initialized_storage, password_protector, protector_names, unlock_with},
};

pub(super) async fn execute(args: ProtectorArgs) -> CliResult<()> {
    match args.command {
        ProtectorCommand::List(args) => list(&args.storage).await,
        ProtectorCommand::Add(args) => match args.protector {
            ProtectorAddCommand::System(args) => add_system(args).await,
        },
        ProtectorCommand::Remove(args) => remove(args).await,
    }
}

async fn add_system(args: AddSystemProtectorArgs) -> CliResult<()> {
    let mut xsec = load_initialized_storage(&args.storage).await?;
    let configured = protector_names(&xsec);
    if !configured.iter().any(|kind| kind == "password") {
        return Err(CliError::ProtectorNotConfigured("password".to_owned()));
    }

    let password = password_protector(args.password, false)?;
    xsec.unlock(&password).await?;

    let protector = XSecSystemProtector::new(args.identity);
    protector.check_availability().await?;
    xsec.add_key_protector(&protector).await?;
    println!(
        "Added system protector to XSec storage at {}",
        args.storage.display()
    );
    Ok(())
}

async fn remove(args: RemoveProtectorArgs) -> CliResult<()> {
    let mut xsec = load_initialized_storage(&args.storage).await?;
    let configured = protector_names(&xsec);
    let target = args.kind.as_str();
    if !configured.iter().any(|kind| kind == target) {
        return Err(CliError::ProtectorNotConfigured(target.to_owned()));
    }

    let alternatives = configured
        .iter()
        .filter(|kind| kind.as_str() != target)
        .collect::<Vec<_>>();
    let unlock_kind = match args.unlock_with {
        Some(kind) => kind,
        None if alternatives.len() == 1 => ProtectorKind::from_kind(alternatives[0])?,
        None if alternatives.is_empty() => args.kind,
        None => {
            return Err(CliError::UnlockProtectorSelectionRequired(
                alternatives
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
    };
    if !configured.iter().any(|kind| kind == unlock_kind.as_str()) {
        return Err(CliError::ProtectorNotConfigured(
            unlock_kind.as_str().to_owned(),
        ));
    }

    unlock_with(&mut xsec, unlock_kind, args.password).await?;
    xsec.remove_key_protector(target).await?;
    println!(
        "Removed {target} protector from XSec storage at {}",
        args.storage.display()
    );
    Ok(())
}

async fn list(path: &std::path::Path) -> CliResult<()> {
    let xsec = load_initialized_storage(path).await?;
    for kind in protector_names(&xsec) {
        println!("{kind}");
    }
    Ok(())
}
