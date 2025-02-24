mod local;

#[cfg(s3)]
mod s3;

use std::{io::{Error, ErrorKind}, path::{Path, PathBuf}, time::SystemTime};

use rocket::fs::TempFile;

enum FSType {
    Local(local::LocalFSBackend),

    #[cfg(s3)]
    S3(s3::S3FSBackend),
}

pub(crate) trait PersistentFSBackend: Sized {
    fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self>;
    async fn read(self) -> std::io::Result<Vec<u8>>;
    async fn write(self, buf: &[u8]) -> std::io::Result<()>;
    async fn path_exists(self) -> std::io::Result<bool>;
    async fn file_exists(self) -> std::io::Result<bool>;
    async fn path_is_dir(self) -> std::io::Result<bool>;
    async fn canonicalize(self) -> std::io::Result<PathBuf>;
    async fn create_dir_all(self) -> std::io::Result<()>;
    async fn persist_temp_file(self, temp_file: TempFile<'_>) -> std::io::Result<()>;
    async fn remove_file(self) -> std::io::Result<()>;
    async fn remove_dir_all(self) -> std::io::Result<()>;
    async fn last_modified(self) -> std::io::Result<SystemTime>;
    async fn download_url(self, local_host: &str) -> std::io::Result<String>;
}

impl PersistentFSBackend for FSType {
    fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        #[cfg(s3)]
        if path.as_ref().starts_with("s3://") {
            return Ok(FSType::S3(s3::S3FSBackend::new(path)?));
        }
        
        Ok(FSType::Local(local::LocalFSBackend::new(path)?))
    }

    async fn read(self) -> std::io::Result<Vec<u8>> {
        match self {
            FSType::Local(fs) => fs.read().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.read().await,
        }
    }

    async fn write(self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            FSType::Local(fs) => fs.write(buf).await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.write(buf).await,
        }
    }

    async fn path_exists(self) -> std::io::Result<bool> {
        match self {
            FSType::Local(fs) => fs.path_exists().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.path_exists().await,
        }
    }

    async fn file_exists(self) -> std::io::Result<bool> {
        match self {
            FSType::Local(fs) => fs.file_exists().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.file_exists().await,
        }
    }

    async fn path_is_dir(self) -> std::io::Result<bool> {
        match self {
            FSType::Local(fs) => fs.path_is_dir().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.path_is_dir().await,
        }
    }

    async fn canonicalize(self) -> std::io::Result<PathBuf> {
        match self {
            FSType::Local(fs) => fs.canonicalize().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.canonicalize().await,
        }
    }

    async fn create_dir_all(self) -> std::io::Result<()> {
        match self {
            FSType::Local(fs) => fs.create_dir_all().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.create_dir_all().await,
        }
    }

    async fn persist_temp_file(self, temp_file: TempFile<'_>) -> std::io::Result<()> {
        match self {
            FSType::Local(fs) => fs.persist_temp_file(temp_file).await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.persist_temp_file(temp_file).await,
        }
    }

    async fn remove_file(self) -> std::io::Result<()> {
        match self {
            FSType::Local(fs) => fs.remove_file().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.remove_file().await,
        }
    }

    async fn remove_dir_all(self) -> std::io::Result<()> {
        match self {
            FSType::Local(fs) => fs.remove_dir_all().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.remove_dir_all().await,
        }
    }

    async fn last_modified(self) -> std::io::Result<SystemTime> {
        match self {
            FSType::Local(fs) => fs.last_modified().await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.last_modified().await,
        }
    }

    async fn download_url(self, local_host: &str) -> std::io::Result<String> {
        match self {
            FSType::Local(fs) => fs.download_url(local_host).await,
            #[cfg(s3)]
            FSType::S3(fs) => fs.download_url(local_host).await,
        }
    }
}

/// Reads the contents of a file at the given path.
///
/// # Arguments
///
/// * `path` - A reference to the path of the file to read.
///
/// # Returns
///
/// * `std::io::Result<Vec<u8>>` - A result containing a vector of bytes with the
///                                file contents if successful, or an I/O error.
pub(crate) async fn read<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    FSType::new(path)?.read().await
}

/// Writes data to a file at the given path.
///
/// If the file does not exist, it will be created. If it does exist, it will be
/// overwritten.
///
/// # Arguments
///
/// * `path` - A reference to the path of the file to write.
/// * `buf` - A byte slice containing the data to write to the file.
///
/// # Returns
///
/// * `std::io::Result<()>` - A result indicating success or an I/O error.
pub(crate) async fn write<P: AsRef<Path>>(path: P, buf: &[u8]) -> std::io::Result<()> {
    FSType::new(path)?.write(buf).await
}

/// Checks whether a path exists.
///
/// This function returns `true` in all cases where the path exists, including
/// as a file, directory, or symlink.
///
/// # Arguments
///
/// * `path` - A reference to the path to check.
///
/// # Returns
///
/// * `std::io::Result<bool>` - A result containing a boolean value indicating
///                             whether the path exists.
pub(crate) async fn path_exists<P: AsRef<Path>>(path: P) -> std::io::Result<bool> {
    FSType::new(path)?.path_exists().await
}

/// Checks whether a regular file exists at the given path.
///
/// This function returns `false` if the path is a symlink.
///
/// # Arguments
///
/// * `path` - A reference to the path to check.
///
/// # Returns
///
/// * `std::io::Result<bool>` - A result containing a boolean value indicating
///                             whether a regular file exists at the given path.
pub(crate) async fn file_exists<P: AsRef<Path>>(path: P) -> std::io::Result<bool> {
    FSType::new(path)?.file_exists().await
}

/// Checks whether a directory exists at the given path.
///
/// This function returns `false` if the path is a symlink.
///
/// # Arguments
///
/// * `path` - A reference to the path to check.
///
/// # Returns
///
/// * `std::io::Result<bool>` - A result containing a boolean value indicating
///                             whether a directory exists at the given path.
pub(crate) async fn path_is_dir<P: AsRef<Path>>(path: P) -> std::io::Result<bool> {
    FSType::new(path)?.path_is_dir().await
}

/// Canonicalizes the given path.
///
/// This function resolves the given path to an absolute path, eliminating any
/// symbolic links and relative path components.
///
/// # Arguments
///
/// * `path` - A reference to the path to canonicalize.
///
/// # Returns
///
/// * `std::io::Result<PathBuf>` - A result containing the canonicalized path if successful,
///                                or an I/O error.
pub(crate) async fn canonicalize<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    FSType::new(path)?.canonicalize().await
}

/// Creates a directory and all its parent components as needed.
///
/// # Arguments
///
/// * `path` - A reference to the path of the directory to create.
///
/// # Returns
///
/// * `std::io::Result<()>` - A result indicating success or an I/O error.
pub(crate) async fn create_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    FSType::new(path)?.create_dir_all().await
}

/// Persists a temporary file to a permanent location.
///
/// # Arguments
///
/// * `temp_file` - The temporary file to persist.
/// * `path` - A reference to the path where the file should be persisted.
///
/// # Returns
///
/// * `std::io::Result<()>` - A result indicating success or an I/O error.
pub(crate) async fn persist_temp_file<P: AsRef<Path>>(temp_file: TempFile<'_>, path: P) -> std::io::Result<()> {
    FSType::new(path)?.persist_temp_file(temp_file).await
}

/// Removes a file at the given path.
///
/// # Arguments
///
/// * `path` - A reference to the path of the file to remove.
///
/// # Returns
///
/// * `std::io::Result<()>` - A result indicating success or an I/O error.
pub(crate) async fn remove_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    FSType::new(path)?.remove_file().await
}

/// Removes a directory and all its contents at the given path.
///
/// # Arguments
///
/// * `path` - A reference to the path of the directory to remove.
///
/// # Returns
///
/// * `std::io::Result<()>` - A result indicating success or an I/O error.
pub(crate) async fn remove_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    FSType::new(path)?.remove_dir_all().await
}

pub(crate) async fn file_is_expired<P: AsRef<Path>>(path: P, ttl: u64) -> Result<bool, Error> {
    let path = path.as_ref();

    let modified = FSType::new(path)?.last_modified().await?;
    
    let age = SystemTime::now().duration_since(modified)
        .map_err(|e| Error::new(
            ErrorKind::InvalidData,
            format!("Failed to determine file age for {path:?} from last modified timestamp '{modified:#?}': {e:?}"
        )))?;

    Ok(ttl > 0 && ttl <= age.as_secs())
}

/// Generates a pre-signed url to download attachment and send files.
///
/// # Arguments
///
/// * `path` - A reference to the path of the file to read.
/// * `local_host` - This API server host.
///
/// # Returns
///
/// * `std::io::Result<String>` - A result containing the url if successful, or an I/O error.
pub(crate) async fn download_url<P: AsRef<Path>>(path: P, local_host: &str) -> std::io::Result<String> {
    FSType::new(path)?.download_url(local_host).await
}