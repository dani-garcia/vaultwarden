# Vaultwarden API Integration Guide

## Overview

Vaultwarden implements the Bitwarden Client API. This guide covers the main endpoints for integration.

## Authentication

### Register

```http
POST /api/accounts/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "master_password_hash",
  "passwordHint": "optional hint",
  "name": "User Name",
  "keys": {
    "encryptedPrivateKey": "...",
    "publicKey": "..."
  }
}
```

### Login

```http
POST /identity/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user@example.com&password=...&scope=api offline_access&client_id=web&client_secret=...
```

## Vault Operations

### Get Vault

```http
GET /api/sync
Authorization: Bearer <access_token>
```

### Create Item

```http
POST /api/ciphers
Content-Type: application/json
Authorization: Bearer <access_token>

{
  "type": 1,
  "name": "Login Item Name",
  "login": {
    "username": "user",
    "password": "encrypted_password",
    "uri": "https://example.com"
  },
  "favorite": false,
  "organizationId": null
}
```

### Update Item

```http
PUT /api/ciphers/:id
Content-Type: application/json
Authorization: Bearer <access_token>

{
  "id": "uuid",
  "type": 1,
  "name": "Updated Name",
  "login": {...},
  "revisionDate": "2026-04-10T00:00:00Z"
}
```

### Delete Item

```http
POST /api/ciphers/:id/delete
Authorization: Bearer <access_token>
```

## Organization API

### Create Organization

```http
POST /api/organizations
Authorization: Bearer <access_token>

{
  "name": "My Org",
  "billingEmail": "admin@example.com",
  "planType": 0
}
```

### Invite User

```http
POST /api/organizations/:id/users
Authorization: Bearer <access_token>

{
  "emails": ["user@example.com"],
  "type": 0
}
```

## Emergency Access

### Grant Emergency Access

```http
POST /api/emergency-access/:id/grant
Authorization: Bearer <access_token>
```

## Admin API

Enable with `ADMIN_TOKEN` environment variable.

```http
GET /admin
Authorization: Bearer <admin_token>
```

## Rate Limiting

Default limits:
- Login: 5 requests per IP per 5 minutes
- API: 100 requests per IP per minute

Configure via `RATE_LIMIT_*` environment variables.

## Webhooks

Configure `WEBHOOK_URL` and `WEBHOOK_EVENTS` to receive events:

```json
{
  "event": "cipher.create",
  "userId": "uuid",
  "organizationId": "uuid",
  "timestamp": "2026-04-10T00:00:00Z"
}
```

---

*Community contribution - not official documentation*
