# Vaultwarden Monitoring Guide

This guide explains how to set up comprehensive monitoring for Vaultwarden using Prometheus metrics.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Metrics Overview](#metrics-overview)
3. [Prometheus Configuration](#prometheus-configuration)
4. [Grafana Dashboard](#grafana-dashboard)
5. [Alerting Rules](#alerting-rules)
6. [Security Considerations](#security-considerations)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Enable Metrics in Vaultwarden

```bash
# Enable metrics with token authentication
export ENABLE_METRICS=true
export METRICS_TOKEN="your-secret-token"

# Rebuild with metrics support
cargo build --features enable_metrics --release
```

### 2. Basic Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: 'vaultwarden'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    bearer_token: 'your-secret-token'
    scrape_interval: 30s
```

### 3. Test the Setup

```bash
# Test metrics endpoint directly
curl -H "Authorization: Bearer your-secret-token" http://localhost:8080/metrics

# Check Prometheus targets
curl http://localhost:9090/api/v1/targets
```

## Metrics Overview

### HTTP Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `vaultwarden_http_requests_total` | Counter | Total HTTP requests | `method`, `path`, `status` |
| `vaultwarden_http_request_duration_seconds` | Histogram | Request duration | `method`, `path` |

### Database Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `vaultwarden_db_connections_active` | Gauge | Active DB connections | `database` |
| `vaultwarden_db_connections_idle` | Gauge | Idle DB connections | `database` |
| `vaultwarden_db_query_duration_seconds` | Histogram | Query duration | `operation` |

### Authentication Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `vaultwarden_auth_attempts_total` | Counter | Authentication attempts | `method`, `status` |
| `vaultwarden_user_sessions_active` | Gauge | Active user sessions | `user_type` |

### Business Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `vaultwarden_users_total` | Gauge | Total users | `status` |
| `vaultwarden_organizations_total` | Gauge | Total organizations | `status` |
| `vaultwarden_vault_items_total` | Gauge | Total vault items | `type`, `organization` |
| `vaultwarden_collections_total` | Gauge | Total collections | `organization` |

### System Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `vaultwarden_uptime_seconds` | Gauge | Application uptime | `version` |
| `vaultwarden_build_info` | Gauge | Build information | `version`, `revision`, `branch` |

## Prometheus Configuration

### Complete Configuration Example

```yaml
# prometheus.yml
global:
  scrape_interval: 30s
  evaluation_interval: 30s

rule_files:
  - "vaultwarden_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'vaultwarden'
    static_configs:
      - targets: ['vaultwarden:8080']
    metrics_path: '/metrics'
    bearer_token: 'your-secret-token'
    scrape_interval: 30s
    scrape_timeout: 10s
    honor_labels: true
    
  # Optional: Monitor Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### Advanced Scraping with Multiple Instances

```yaml
scrape_configs:
  - job_name: 'vaultwarden'
    static_configs:
      - targets: ['vw-primary:8080', 'vw-secondary:8080']
        labels:
          environment: 'production'
      - targets: ['vw-staging:8080']
        labels:
          environment: 'staging'
    metrics_path: '/metrics'
    bearer_token: 'your-secret-token'
```

## Grafana Dashboard

### Dashboard JSON Template

Create a Grafana dashboard with these panel queries:

#### Request Rate Panel
```promql
sum(rate(vaultwarden_http_requests_total[5m])) by (path)
```

#### Error Rate Panel
```promql
sum(rate(vaultwarden_http_requests_total{status=~"4..|5.."}[5m])) / 
sum(rate(vaultwarden_http_requests_total[5m])) * 100
```

#### Response Time Panel
```promql
histogram_quantile(0.95, 
  sum(rate(vaultwarden_http_request_duration_seconds_bucket[5m])) by (le)
)
```

#### Active Users Panel
```promql
vaultwarden_users_total{status="enabled"}
```

#### Database Connections Panel
```promql
vaultwarden_db_connections_active
```

#### Vault Items Panel
```promql
sum by (type) (vaultwarden_vault_items_total)
```

### Import Dashboard

1. Download the dashboard JSON from `examples/grafana-dashboard.json`
2. In Grafana, go to Dashboards → Import
3. Upload the JSON file
4. Configure the Prometheus data source

## Alerting Rules

### Prometheus Alerting Rules

```yaml
# vaultwarden_rules.yml
groups:
  - name: vaultwarden.rules
    rules:
      # High error rate
      - alert: VaultwardenHighErrorRate
        expr: |
          (
            sum(rate(vaultwarden_http_requests_total{status=~"5.."}[5m]))
            /
            sum(rate(vaultwarden_http_requests_total[5m]))
          ) * 100 > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Vaultwarden has high error rate"
          description: "Error rate is {{ $value }}% for the last 5 minutes"

      # High response time
      - alert: VaultwardenHighResponseTime
        expr: |
          histogram_quantile(0.95,
            sum(rate(vaultwarden_http_request_duration_seconds_bucket[5m])) by (le)
          ) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Vaultwarden response time is high"
          description: "95th percentile response time is {{ $value }}s"

      # Application down
      - alert: VaultwardenDown
        expr: up{job="vaultwarden"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vaultwarden is down"
          description: "Vaultwarden has been down for more than 1 minute"

      # Database connection issues
      - alert: VaultwardenDatabaseConnections
        expr: vaultwarden_db_connections_active > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Vaultwarden database connection pool nearly exhausted"
          description: "{{ $value }} active connections out of maximum"

      # High authentication failure rate
      - alert: VaultwardenAuthFailures
        expr: |
          (
            sum(rate(vaultwarden_auth_attempts_total{status="failed"}[5m]))
            /
            sum(rate(vaultwarden_auth_attempts_total[5m]))
          ) * 100 > 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }}% of authentication attempts are failing"
```

## Security Considerations

### Token Security

1. **Use strong tokens**: Generate cryptographically secure random tokens
2. **Use Argon2 hashing**: For production environments, use hashed tokens
3. **Rotate tokens regularly**: Change metrics tokens periodically
4. **Limit network access**: Restrict metrics endpoint access to monitoring systems

### Network Security

```nginx
# Nginx configuration example
location /metrics {
    # Restrict to monitoring systems only
    allow 10.0.0.0/8;    # Private network
    allow 192.168.1.100; # Prometheus server
    deny all;
    
    proxy_pass http://vaultwarden:8080;
    proxy_set_header Authorization "Bearer your-secret-token";
}
```

### Firewall Rules

```bash
# UFW rules example
ufw allow from 192.168.1.100 to any port 8080 comment "Prometheus metrics"
ufw deny 8080 comment "Block metrics from other sources"
```

## Troubleshooting

### Common Issues

#### 1. Metrics Endpoint Returns 404

**Problem**: `/metrics` endpoint not found

**Solutions**:
- Ensure `ENABLE_METRICS=true` is set
- Verify compilation with `--features enable_metrics`
- Check application logs for metrics initialization

#### 2. Authentication Errors (401)

**Problem**: Metrics endpoint returns unauthorized

**Solutions**:
- Verify `METRICS_TOKEN` configuration
- Check token format and encoding
- Ensure Authorization header is correctly formatted

#### 3. Missing Metrics Data

**Problem**: Some metrics are not appearing

**Solutions**:
- Business metrics require database queries - wait for first scrape
- HTTP metrics populate only after requests are made
- Check application logs for metric collection errors

#### 4. High Cardinality Issues

**Problem**: Too many metric series causing performance issues

**Solutions**:
- Path normalization is automatic but verify it's working
- Consider reducing scrape frequency
- Monitor Prometheus memory usage

### Diagnostic Commands

```bash
# Test metrics endpoint
curl -v -H "Authorization: Bearer your-token" http://localhost:8080/metrics

# Check metrics format
curl -H "Authorization: Bearer your-token" http://localhost:8080/metrics | head -20

# Verify Prometheus can scrape
curl http://prometheus:9090/api/v1/targets

# Check for metric ingestion
curl -g 'http://prometheus:9090/api/v1/query?query=up{job="vaultwarden"}'
```

### Performance Tuning

#### Prometheus Configuration

```yaml
# Optimize for high-frequency scraping
global:
  scrape_interval: 15s        # More frequent scraping
  scrape_timeout: 10s         # Allow time for DB queries
  
# Retention policy
storage:
  tsdb:
    retention.time: 30d       # Keep 30 days of data
    retention.size: 10GB      # Limit storage usage
```

#### Vaultwarden Optimization

```bash
# Reduce metrics collection overhead
ENABLE_METRICS=true
METRICS_TOKEN=your-token
DATABASE_MAX_CONNS=10        # Adequate for metrics queries
```

### Monitoring the Monitor

Set up monitoring for your monitoring stack:

```yaml
# Monitor Prometheus itself
- alert: PrometheusDown
  expr: up{job="prometheus"} == 0
  for: 5m

# Monitor scrape failures
- alert: VaultwardenScrapeFailure
  expr: up{job="vaultwarden"} == 0
  for: 2m
```

This comprehensive monitoring setup will provide full observability into your Vaultwarden instance's health, performance, and usage patterns.