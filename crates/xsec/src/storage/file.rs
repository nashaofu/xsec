use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tempfile::NamedTempFile;

use crate::{
    metadata::MAX_METADATA_LENGTH,
    storage::{XSecStorage, XSecStorageError, XSecStorageResult},
};

pub struct XSecFileStorage {
    path: PathBuf,
    lock: Arc<Mutex<Option<File>>>,
}

impl XSecFileStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(None)),
        }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn exists(&self) -> XSecStorageResult<bool> {
        tokio::fs::try_exists(&self.path)
            .await
            .map_err(map_io_error)
    }

    async fn lock(&self) -> XSecStorageResult<()> {
        let path = lock_path(&self.path);
        let lock = Arc::clone(&self.lock);
        tokio::task::spawn_blocking(move || {
            let mut held = lock.lock().map_err(|_| XSecStorageError::Internal)?;
            if held.is_some() {
                return Ok(());
            }
            let parent = path
                .parent()
                .filter(|value| !value.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::create_dir_all(parent).map_err(map_io_error)?;
            let file = open_lock_file(&path)?;
            match file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Err(XSecStorageError::Conflict),
                Err(TryLockError::Error(error)) => return Err(map_io_error(error)),
            }
            *held = Some(file);
            Ok(())
        })
        .await
        .map_err(|_| XSecStorageError::Internal)?
    }
}

impl XSecStorage for XSecFileStorage {
    async fn load(&self) -> XSecStorageResult<Option<Vec<u8>>> {
        self.lock().await?;
        let metadata = match tokio::fs::metadata(&self.path).await {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_io_error(error)),
        };
        if metadata.len() > MAX_METADATA_LENGTH as u64 {
            return Err(XSecStorageError::LimitExceeded);
        }
        let bytes = tokio::fs::read(&self.path).await.map_err(map_io_error)?;
        if bytes.len() > MAX_METADATA_LENGTH {
            return Err(XSecStorageError::LimitExceeded);
        }
        Ok(Some(bytes))
    }

    async fn save<'a>(&'a self, data: &'a [u8]) -> XSecStorageResult<()> {
        self.lock().await?;
        if data.len() > MAX_METADATA_LENGTH {
            return Err(XSecStorageError::LimitExceeded);
        }
        let path = self.path.clone();
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            let parent = path
                .parent()
                .filter(|value| !value.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::create_dir_all(parent).map_err(map_io_error)?;
            let mut temporary = NamedTempFile::new_in(parent).map_err(map_io_error)?;
            temporary.write_all(&data).map_err(map_io_error)?;
            temporary.as_file().sync_all().map_err(map_io_error)?;
            temporary
                .persist(&path)
                .map_err(|error| map_io_error(error.error))?;
            #[cfg(unix)]
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(map_io_error)?;
            Ok(())
        })
        .await
        .map_err(|_| XSecStorageError::Internal)?
    }

    async fn delete(&self) -> XSecStorageResult<()> {
        self.lock().await?;
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(map_io_error(error)),
        }
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    value.into()
}

fn open_lock_file(path: &Path) -> XSecStorageResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(map_io_error)
}

fn map_io_error(error: Error) -> XSecStorageError {
    match error.kind() {
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => {
            XSecStorageError::AccessDenied
        }
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded | ErrorKind::OutOfMemory => {
            XSecStorageError::ResourceExhausted
        }
        ErrorKind::FileTooLarge => XSecStorageError::LimitExceeded,
        ErrorKind::WouldBlock | ErrorKind::ResourceBusy | ErrorKind::ExecutableFileBusy => {
            XSecStorageError::Conflict
        }
        _ => XSecStorageError::Unavailable,
    }
}
