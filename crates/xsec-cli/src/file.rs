use std::{
    io::{self, Write},
    path::Path,
};

use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::error::{CliError, CliResult, io_error};

pub(crate) async fn read_limited(path: &Path, limit: usize) -> CliResult<Vec<u8>> {
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

pub(crate) async fn ensure_distinct_paths(input: &Path, output: &Path) -> CliResult<()> {
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

pub(crate) async fn atomic_write(path: &Path, data: Vec<u8>, overwrite: bool) -> CliResult<()> {
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

pub(crate) async fn atomic_replace_if_unchanged(
    path: &Path,
    data: Vec<u8>,
    expected: Option<Vec<u8>>,
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

        match expected {
            Some(expected) => {
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
            }
            None => {
                temporary.persist_noclobber(&path).map_err(|error| {
                    if error.error.kind() == io::ErrorKind::AlreadyExists {
                        CliError::ConcurrentModification(path.display().to_string())
                    } else {
                        io_error(
                            format!("failed to create `{}`", path.display()),
                            error.error,
                        )
                    }
                })?;
            }
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
