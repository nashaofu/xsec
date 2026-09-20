use std::{
    io::Write,
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

use crate::{XSecError, XSecResult, metadata::MAX_METADATA_LENGTH, storage::XSecStorage};

pub struct XSecFileStorage {
    path: PathBuf,
}

impl XSecFileStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn exists(&self) -> XSecResult<bool> {
        tokio::fs::try_exists(&self.path)
            .await
            .map_err(XSecError::storage)
    }
}

impl XSecStorage for XSecFileStorage {
    async fn load(&self) -> XSecResult<Option<Vec<u8>>> {
        let metadata = match tokio::fs::metadata(&self.path).await {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(XSecError::storage(error)),
        };
        if metadata.len() > MAX_METADATA_LENGTH as u64 {
            return Err(XSecError::Corrupted);
        }
        let bytes = tokio::fs::read(&self.path)
            .await
            .map_err(XSecError::storage)?;
        if bytes.len() > MAX_METADATA_LENGTH {
            return Err(XSecError::Corrupted);
        }
        Ok(Some(bytes))
    }

    async fn save<'a>(&'a self, data: &'a [u8]) -> XSecResult<()> {
        if data.len() > MAX_METADATA_LENGTH {
            return Err(XSecError::Corrupted);
        }
        let path = self.path.clone();
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            let parent = path
                .parent()
                .filter(|value| !value.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::create_dir_all(parent).map_err(XSecError::storage)?;
            let mut temporary = NamedTempFile::new_in(parent).map_err(XSecError::storage)?;
            temporary.write_all(&data).map_err(XSecError::storage)?;
            temporary.as_file().sync_all().map_err(XSecError::storage)?;
            temporary
                .persist(&path)
                .map_err(|error| XSecError::storage(error.error))?;
            #[cfg(unix)]
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(XSecError::storage)?;
            Ok(())
        })
        .await
        .map_err(XSecError::storage)?
    }

    async fn delete(&self) -> XSecResult<()> {
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(XSecError::storage(error)),
        }
    }
}
