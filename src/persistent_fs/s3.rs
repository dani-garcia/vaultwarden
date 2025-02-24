use std::{io::{Error, ErrorKind}, path::{Path, PathBuf}, time::SystemTime};

use aws_sdk_s3::{client::Client, primitives::ByteStream, types::StorageClass::IntelligentTiering};
use rocket::{fs::TempFile, http::ContentType};
use tokio::{fs::File, io::AsyncReadExt};
use url::Url;

use crate::aws::aws_sdk_config;

use super::PersistentFSBackend;

pub(crate) struct S3FSBackend {
    path: PathBuf,
    bucket: String,
    key: String,
}

fn s3_client() -> std::io::Result<Client> {
    static AWS_S3_CLIENT: std::sync::LazyLock<std::io::Result<Client>> = std::sync::LazyLock::new(|| {
        Ok(Client::new(aws_sdk_config()?))
    });

    (*AWS_S3_CLIENT)
        .as_ref()
        .map(|client| client.clone())
        .map_err(|e| match e.get_ref() {
            Some(inner) => Error::new(e.kind(), inner),
            None => Error::from(e.kind()),
        })
}

impl PersistentFSBackend for S3FSBackend {
    fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();

        let url = Url::parse(path.to_str().ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Invalid path"))?)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid data folder S3 URL {path:?}: {e}")))?;

        let bucket = url.host_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("Missing Bucket name in data folder S3 URL {path:?}")))?
            .to_string();

        let key = url.path().trim_start_matches('/').to_string();

        Ok(S3FSBackend {
            path: path.to_path_buf(),
            bucket,
            key,
        })
    }

    async fn read(self) -> std::io::Result<Vec<u8>> {
        let S3FSBackend { path, key, bucket } = self;

        let result = s3_client()?
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await;

        match result {
            Ok(response) => {
                let mut buffer = Vec::new();
                response.body.into_async_read().read_to_end(&mut buffer).await?;
                Ok(buffer)
            }
            Err(e) => {
                if let Some(service_error) = e.as_service_error() {
                    if service_error.is_no_such_key() {
                        Err(Error::new(ErrorKind::NotFound, format!("Data folder S3 object {path:?} not found")))
                    } else {
                        Err(Error::other(format!("Failed to request data folder S3 object {path:?}: {e:?}")))
                    }
                } else {
                    Err(Error::other(format!("Failed to request data folder S3 object {path:?}: {e:?}")))
                }
            }
        }
    }

    async fn write(self, buf: &[u8]) -> std::io::Result<()> {
        let S3FSBackend { path, key, bucket } = self;

        let content_type = Path::new(&key)
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| ContentType::from_extension(ext))
            .and_then(|t| Some(t.to_string()));

        s3_client()?
            .put_object()
            .bucket(bucket)
            .set_content_type(content_type)
            .key(key)
            .storage_class(IntelligentTiering)
            .body(ByteStream::from(buf.to_vec()))
            .send()
            .await
            .map_err(|e| Error::other(format!("Failed to write to data folder S3 object {path:?}: {e:?}")))?;

        Ok(())
    }

    async fn path_exists(self) -> std::io::Result<bool> {
        Ok(true)
    }

    async fn file_exists(self) -> std::io::Result<bool> {
        let S3FSBackend { path, key, bucket } = self;

        match s3_client()?
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await {
            Ok(_) => Ok(true),
            Err(e) => {
                if let Some(service_error) = e.as_service_error() {
                    if service_error.is_not_found() {
                        Ok(false)
                    } else {
                        Err(Error::other(format!("Failed to request data folder S3 object {path:?}: {e:?}")))
                    }
                } else {
                    Err(Error::other(format!("Failed to request data folder S3 object {path:?}: {e:?}")))
                }
            }
        }
    }

    async fn path_is_dir(self) -> std::io::Result<bool> {
        Ok(true)
    }

    async fn canonicalize(self) -> std::io::Result<PathBuf> {
        Ok(self.path)
    }

    async fn create_dir_all(self) -> std::io::Result<()> {
        Ok(())
    }

    async fn persist_temp_file(self, temp_file: TempFile<'_>) -> std::io::Result<()> {
        let S3FSBackend { path, key, bucket } = self;

        // We want to stream the TempFile directly to S3 without copying it into
        // another memory buffer. The official AWS SDK makes it easy to stream
        // from a `tokio::fs::File`, but does not have a reasonable way to stream
        // from an `impl AsyncBufRead`.
        //
        // A TempFile's contents may be saved in memory or on disk. We use the
        // SDK to stream the file if we can access it on disk, otherwise we fall
        // back to a second copy in memory.
        let file = match temp_file.path() {
            Some(path) => File::open(path).await.ok(),
            None => None,
        };

        let byte_stream = match file {
            Some(file) => ByteStream::read_from().file(file).build().await.ok(),
            None => None,
        };

        let byte_stream = match byte_stream {
            Some(byte_stream) => byte_stream,
            None => {
                // TODO: Implement a mechanism to stream the file directly to S3
                // without buffering it again in memory. This would require
                // chunking it into a multi-part upload. See example here:
                // https://imfeld.dev/writing/rust_s3_streaming_upload
                let mut read_stream = temp_file.open().await?;
                let mut buf = Vec::with_capacity(temp_file.len() as usize);
                read_stream.read_to_end(&mut buf).await?;
                ByteStream::from(buf)
            }
        };

        let content_type = temp_file
            .content_type()
            .map(|t| t.to_string())
            .or_else(||
                temp_file.name()
                    .and_then(|name| Path::new(name).extension())
                    .and_then(|ext| ext.to_str())
                    .and_then(|ext| ContentType::from_extension(ext))
                    .and_then(|t| Some(t.to_string()))
            );

        s3_client()?
            .put_object()
            .bucket(bucket)
            .key(key)
            .storage_class(IntelligentTiering)
            .set_content_type(content_type)
            .body(byte_stream)
            .send()
            .await
            .map_err(|e| Error::other(format!("Failed to write to data folder S3 object {path:?}: {e:?}")))?;

        Ok(())
    }

    async fn remove_file(self) -> std::io::Result<()> {
        let S3FSBackend { path, key, bucket } = self;

        s3_client()?
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::other(format!("Failed to delete data folder S3 object {path:?}: {e:?}")))?;

        Ok(())
    }

    async fn remove_dir_all(self) -> std::io::Result<()> {
        use aws_sdk_s3::types::{Delete, ObjectIdentifier};

        let S3FSBackend { path, key: prefix, bucket } = self;

        let s3_client = s3_client()?;

        let mut list_response = s3_client
            .list_objects_v2()
            .bucket(bucket.clone())
            .prefix(format!("{prefix}/"))
            .into_paginator()
            .send();

        while let Some(list_result) = list_response.next().await {
            let list_result = list_result
                .map_err(|e| Error::other(format!("Failed to list data folder S3 objects with prefix {path:?}/ intended for deletion: {e:?}")))?;

            let objects = list_result
                .contents
                .ok_or_else(|| Error::other(format!("Failed to list data folder S3 objects with prefix {path:?}/ intended for deletion: Missing contents")))?;

            let keys = objects.into_iter()
                .map(|object| object.key
                    .ok_or_else(|| Error::other(format!("Failed to list data folder S3 objects with prefix {path:?}/ intended for deletion: An object is missing its key")))
                )
                .collect::<std::io::Result<Vec<_>>>()?;

            let mut delete = Delete::builder().quiet(true);

            for key in keys {
                delete = delete.objects(
                    ObjectIdentifier::builder()
                        .key(key)
                        .build()
                        .map_err(|e| Error::other(format!("Failed to delete data folder S3 objects with prefix {path:?}/: {e:?}")))?
                );
            }

            let delete = delete
                .build()
                .map_err(|e| Error::other(format!("Failed to delete data folder S3 objects with prefix {path:?}/: {e:?}")))?;

            s3_client
                .delete_objects()
                .bucket(bucket.clone())
                .delete(delete)
                .send()
                .await
                .map_err(|e| Error::other(format!("Failed to delete data folder S3 objects with prefix {path:?}/: {e:?}")))?;
        }

        Ok(())
    }

    async fn last_modified(self) -> std::io::Result<SystemTime> {
        let S3FSBackend { path, key, bucket } = self;

        let response = s3_client()?
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| match e.as_service_error() {
                Some(service_error) if service_error.is_not_found() => Error::new(ErrorKind::NotFound, format!("Failed to get metadata for data folder S3 object {path:?}: Object does not exist")),
                Some(service_error) => Error::other(format!("Failed to get metadata for data folder S3 object {path:?}: {service_error:?}")),
                None => Error::other(format!("Failed to get metadata for data folder S3 object {path:?}: {e:?}")),
            })?;

        let last_modified = response.last_modified
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("Failed to get metadata for data folder S3 object {path:?}: Missing last modified data")))?;

        SystemTime::try_from(last_modified)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Failed to parse last modified date for data folder S3 object {path:?}: {e:?}")))
    }

    async fn download_url(self, _local_host: &str) -> std::io::Result<String> {
        use std::time::Duration;
        use aws_sdk_s3::presigning::PresigningConfig;

        let S3FSBackend { path, key, bucket } = self;

        s3_client()?
            .get_object()
            .bucket(bucket)
            .key(key)
            .presigned(
                PresigningConfig::expires_in(Duration::from_secs(5 * 60))
                    .map_err(|e| Error::other(
                        format!("Failed to generate presigned config for GetObject URL for data folder S3 object {path:?}: {e:?}")
                    ))?
            )
            .await
            .map(|presigned| presigned.uri().to_string())
            .map_err(|e| Error::other(format!("Failed to generate presigned URL for GetObject for data folder S3 object {path:?}: {e:?}")))
    }
}