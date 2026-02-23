# S3-Compatible Object Storage

This page documents Vaultwarden's S3-compatible storage support based on `s3://` URIs with query parameters (OpenDAL S3 config).

## Scope

Supported providers (via S3 API):

- AWS S3
- MinIO
- Cloudflare R2
- Ceph RGW and similar S3-compatible services

The same URI format applies to:

- `DATA_FOLDER`
- `ATTACHMENTS_FOLDER`
- `ICON_CACHE_FOLDER`
- `SENDS_FOLDER`

## URI Format

```text
s3://bucket/prefix?endpoint=https%3A%2F%2Fs3.example.com&enable_virtual_host_style=false&default_storage_class=STANDARD&region=us-east-1
```

Supported query parameters:

- `endpoint`
- `region`
- `enable_virtual_host_style`
- `default_storage_class`
- `disable_virtual_host_style` (alias)

Notes:

- AWS S3 works with defaults.
- For path-style providers, set `enable_virtual_host_style=false`.
- To omit storage class header, set `default_storage_class=` (empty).
- Unknown parameters are rejected.

## Build Requirement

Use images/binaries built with both:

1. a DB backend feature (`sqlite`, `postgresql`, or `mysql`)
2. `s3`

Examples:

- `sqlite,s3`
- `postgresql,s3`
- `mysql,s3`

## Cloudflare R2 Example

```env
ATTACHMENTS_FOLDER=s3://vaultwarden/attachments?endpoint=https://<accountid>.r2.cloudflarestorage.com&region=auto&enable_virtual_host_style=false&default_storage_class=
ICON_CACHE_FOLDER=s3://vaultwarden/icon_cache?endpoint=https://<accountid>.r2.cloudflarestorage.com&region=auto&enable_virtual_host_style=false&default_storage_class=
SENDS_FOLDER=s3://vaultwarden/sends?endpoint=https://<accountid>.r2.cloudflarestorage.com&region=auto&enable_virtual_host_style=false&default_storage_class=
```

## Browser Downloads: CSP + CORS

When attachments are stored in object storage, Web Vault downloads use presigned URLs and the browser fetches objects directly from the storage endpoint.

You must configure both sides:

1. Vaultwarden CSP (`ALLOWED_CONNECT_SRC`)
2. Bucket/provider CORS policy

### 1) Vaultwarden CSP

```env
ALLOWED_CONNECT_SRC=https://<accountid>.r2.cloudflarestorage.com
```

### 2) Bucket CORS Policy (example)

```json
[
  {
    "AllowedOrigins": ["https://vault.example.com"],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["ETag", "Content-Length", "Content-Type", "Content-Disposition"],
    "MaxAgeSeconds": 3600
  }
]
```

## Troubleshooting

- `violates the document's Content Security Policy`
  - Configure/fix `ALLOWED_CONNECT_SRC`.
- `No 'Access-Control-Allow-Origin' header`
  - Configure/fix CORS on the bucket/provider.
- `S3 support is not enabled`
  - Image/binary was built without `s3` feature.

## Security Notes

- Prefer IAM/service account/environment credentials.
- URI credentials are supported only as a last resort.
- If credentials were exposed in logs/chats, rotate them immediately.
