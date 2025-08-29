# Prometheus Metrics for Vaultwarden

This document describes how to enable and configure Prometheus metrics in Vaultwarden.

## Configuration

### Environment Variables

- `ENABLE_METRICS`: Set to `true` to enable the metrics endpoint (default: `false`)
- `METRICS_TOKEN`: Optional token to secure the /metrics endpoint (default: none - public access)

### Examples

#### Enable metrics without authentication (development)
```bash
ENABLE_METRICS=true
```

#### Enable metrics with token authentication (production)
```bash
ENABLE_METRICS=true
METRICS_TOKEN=your-secret-token
```

#### Enable metrics with Argon2 hashed token (most secure)
```bash
ENABLE_METRICS=true
METRICS_TOKEN='$argon2id$v=19$m=65540,t=3,p=4$...'
```

## Build Configuration

To enable metrics support, compile with the `enable_metrics` feature:

```bash
cargo build --features enable_metrics
```

Without this feature, all metrics functions become no-ops and the endpoint is not available.

## Usage

When enabled, metrics are available at:
- `/metrics` (if no token configured)
- `/metrics?token=your-token` (with token as query parameter)
- `/metrics` with `Authorization: Bearer your-token` header

## Metrics Categories

### HTTP Metrics
- `vaultwarden_http_requests_total`: Total number of HTTP requests by method, path, and status
- `vaultwarden_http_request_duration_seconds`: HTTP request duration histograms

### Database Metrics
- `vaultwarden_db_connections_active`: Number of active database connections
- `vaultwarden_db_connections_idle`: Number of idle database connections
- `vaultwarden_db_query_duration_seconds`: Database query duration histograms

### Authentication Metrics
- `vaultwarden_auth_attempts_total`: Total authentication attempts by method and status
- `vaultwarden_user_sessions_active`: Number of active user sessions

### Business Metrics
- `vaultwarden_users_total`: Total number of users by status (enabled/disabled)
- `vaultwarden_organizations_total`: Total number of organizations
- `vaultwarden_vault_items_total`: Total number of vault items by type and organization
- `vaultwarden_collections_total`: Total number of collections per organization

### System Metrics
- `vaultwarden_uptime_seconds`: Application uptime in seconds
- `vaultwarden_build_info`: Build information (version, revision, branch)

## Security Considerations

- **Disable by default**: Metrics are disabled unless explicitly enabled
- **Token protection**: Use a strong, unique token in production environments
- **Argon2 hashing**: For maximum security, use Argon2-hashed tokens
- **Network security**: Consider restricting access to the metrics endpoint at the network level
- **Rate limiting**: The endpoint uses existing Vaultwarden rate limiting mechanisms

## Integration with Monitoring Systems

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'vaultwarden'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    bearer_token: 'your-secret-token'  # If using token authentication
    scrape_interval: 30s
```

### Grafana Dashboard

The metrics can be visualized in Grafana using the standard Prometheus data source. Common queries:

- Request rate: `rate(vaultwarden_http_requests_total[5m])`
- Error rate: `rate(vaultwarden_http_requests_total{status=~"4..|5.."}[5m])`
- Active users: `vaultwarden_users_total{status="enabled"}`
- Database connections: `vaultwarden_db_connections_active`

## Troubleshooting

### Metrics endpoint not found (404)
- Ensure `ENABLE_METRICS=true` is set
- Verify the application was compiled with `--features enable_metrics`
- Check application logs for metrics initialization messages

### Authentication errors (401)
- Verify the `METRICS_TOKEN` is correctly configured
- Ensure the token in requests matches the configured token
- Check for whitespace or encoding issues in token values

### Missing metrics data
- Metrics are populated as the application handles requests
- Some business metrics require database queries and may take time to populate
- Check application logs for any metrics collection errors

## Performance Impact

- Metrics collection has minimal performance overhead
- Database metrics queries are run only when the metrics endpoint is accessed
- Consider the frequency of metrics scraping in high-traffic environments