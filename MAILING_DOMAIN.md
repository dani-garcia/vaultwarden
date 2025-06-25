# Mailing Domain Configuration

This feature allows you to configure a separate domain specifically for email templates and links, while keeping your main `DOMAIN` setting for internal server access.

## Configuration

### Environment Variable
Set the `MAILING_DOMAIN` environment variable:
```bash
MAILING_DOMAIN=https://public.example.com
```

### Docker Environment
Add to your docker-compose.yml or docker run command:
```yaml
environment:
  - MAILING_DOMAIN=https://public.example.com
```

Or with docker run:
```bash
docker run -e MAILING_DOMAIN=https://public.example.com vaultwarden/server
```

### Admin Panel
The mailing domain can also be configured through the admin panel under SMTP Email Settings.

## Use Cases

1. **Internal vs Public Access**: Your Vaultwarden server runs on an internal domain (e.g., `http://vaultwarden.internal`) but you want emails to contain links to a public domain (e.g., `https://vault.company.com`).

2. **Development vs Production**: Use different domains for email links in development and production environments.

3. **Load Balancer/Proxy**: Your server runs behind a load balancer with a different internal address than the public-facing URL.

## Behavior

- If `MAILING_DOMAIN` is set, all email templates will use this domain for links and references
- If `MAILING_DOMAIN` is not set, the system falls back to using the main `DOMAIN` setting
- This affects all email types: invitations, password resets, 2FA emails, notifications, etc.

## Example

```bash
# Main domain for server operations
DOMAIN=http://vaultwarden.internal:8080

# Public domain for email links
MAILING_DOMAIN=https://vault.company.com
```

With this configuration:
- The server operates on `http://vaultwarden.internal:8080`
- All email links will point to `https://vault.company.com`