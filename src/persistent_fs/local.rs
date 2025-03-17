use std::{io::{Error, ErrorKind}, path::{Path, PathBuf}, time::SystemTime};

use rocket::fs::TempFile;
use tokio::{fs::{File, OpenOptions}, io::{AsyncReadExt, AsyncWriteExt}};

use super::PersistentFSBackend;

pub(crate) struct LocalFSBackend(String);

impl AsRef<Path> for LocalFSBackend {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl PersistentFSBackend for LocalFSBackend {
    fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Ok(Self(path
            .as_ref()
            .to_str()
            .ok_or_else(||
                Error::new(
                    ErrorKind::InvalidInput,
                    "Data folder path {path:?} is not valid UTF-8"
                )
            )?
            .to_string()
        ))
    }
    
    async fn read(self) -> std::io::Result<Vec<u8>> {
        let mut file = File::open(self).await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        Ok(buffer)
    }
    
    async fn write(self, buf: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(self).await?;
        file.write_all(buf).await?;
        Ok(())
    }
    
    async fn path_exists(self) -> std::io::Result<bool> {
        match tokio::fs::metadata(self).await {
            Ok(_) => Ok(true),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(false),
                _ => Err(e),
            },
        }
    }
    
    async fn file_exists(self) -> std::io::Result<bool> {
        match tokio::fs::metadata(self).await {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(false),
                _ => Err(e),
            },
        }
    }
    
    async fn path_is_dir(self) -> std::io::Result<bool> {
        match tokio::fs::metadata(self).await {
            Ok(metadata) => Ok(metadata.is_dir()),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(false),
                _ => Err(e),
            },
        }
    }
    
    async fn canonicalize(self) -> std::io::Result<PathBuf> {
        tokio::fs::canonicalize(self).await
    }
    
    async fn create_dir_all(self) -> std::io::Result<()> {
        tokio::fs::create_dir_all(self).await
    }
    
    async fn persist_temp_file(self, mut temp_file: TempFile<'_>) -> std::io::Result<()> {
        if temp_file.persist_to(&self).await.is_err() {
            temp_file.move_copy_to(self).await?;
        }

        Ok(())
    }
    
    async fn remove_file(self) -> std::io::Result<()> {
        tokio::fs::remove_file(self).await
    }
    
    async fn remove_dir_all(self) -> std::io::Result<()> {
        tokio::fs::remove_dir_all(self).await
    }
    
    async fn last_modified(self) -> std::io::Result<SystemTime> {
        tokio::fs::symlink_metadata(self)
            .await?
            .modified()
    }

    async fn download_url(self, local_host: &str) -> std::io::Result<String> {
        use std::sync::LazyLock;
        use crate::{
            auth::{encode_jwt, generate_file_download_claims, generate_send_claims},
            db::models::{AttachmentId, CipherId, SendId, SendFileId},
            CONFIG
        };

        let LocalFSBackend(path) = self;

        static ATTACHMENTS_PREFIX: LazyLock<String> = LazyLock::new(|| format!("{}/", CONFIG.attachments_folder()));
        static SENDS_PREFIX: LazyLock<String> = LazyLock::new(|| format!("{}/", CONFIG.sends_folder()));

        if path.starts_with(&*ATTACHMENTS_PREFIX) {
            let attachment_parts = path.trim_start_matches(&*ATTACHMENTS_PREFIX).split('/').collect::<Vec<&str>>();
            
            let [cipher_uuid, attachment_id] = attachment_parts[..] else {
                return Err(Error::new(ErrorKind::InvalidInput, format!("Attachment path {path:?} does not match a known download URL path pattern")));
            };

            let token = encode_jwt(&generate_file_download_claims(CipherId::from(cipher_uuid.to_string()), AttachmentId(attachment_id.to_string())));

            Ok(format!("{}/attachments/{}/{}?token={}", local_host, cipher_uuid, attachment_id, token))
        } else if path.starts_with(&*SENDS_PREFIX) {
            let send_parts = path.trim_start_matches(&*SENDS_PREFIX).split('/').collect::<Vec<&str>>();

            let [send_id, file_id] = send_parts[..] else {
                return Err(Error::new(ErrorKind::InvalidInput, format!("Send path {path:?} does not match a known download URL path pattern")));
            };

            let token = encode_jwt(&generate_send_claims(&SendId::from(send_id.to_string()), &SendFileId::from(file_id.to_string())));

            Ok(format!("{}/api/sends/{}/{}?t={}", local_host, send_id, file_id, token))
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "Data folder path {path:?} does not match a known download URL path pattern"))
        }
    }
}