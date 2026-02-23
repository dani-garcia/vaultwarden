# Vaultwarden Helm Chart

Official Helm chart for [Vaultwarden](https://github.com/dani-garcia/vaultwarden) — an unofficial Bitwarden-compatible server written in Rust.

## Quick Start

```bash
helm install vaultwarden ./helm/vaultwarden \
  --set vaultwarden.domain=https://vault.example.com
```

This deploys vaultwarden with **SQLite** (the default). Data is persisted in a 5Gi PVC.

> **For production deployments, we recommend PostgreSQL.** See [Production Setup with PostgreSQL](#production-setup-with-postgresql) below.

## Production Setup with PostgreSQL

```yaml
# values-production.yaml
vaultwarden:
  domain: https://vault.example.com
  signupsAllowed: false
  admin:
    enabled: true
    existingSecret: vaultwarden-admin
    existingSecretKey: admin-token

database:
  type: postgresql
  existingSecret: vaultwarden-db-credentials
  existingSecretKey: database-url

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-production
    cert-manager.io/private-key-algorithm: ECDSA
    cert-manager.io/private-key-size: "384"
    cert-manager.io/private-key-rotation-policy: Always
  hosts:
    - host: vault.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vault-tls
      hosts:
        - vault.example.com

persistence:
  storageClassName: longhorn  # or your preferred storage class
  size: 10Gi

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    memory: 1Gi
```

```bash
helm install vaultwarden ./helm/vaultwarden -f values-production.yaml
```

## Configuration

### Image

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `vaultwarden/server` |
| `image.tag` | Image tag (defaults to `appVersion`) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of replicas (keep at 1 for SQLite) | `1` |

### Vaultwarden

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultwarden.domain` | **(required)** Public URL of your instance | `""` |
| `vaultwarden.signupsAllowed` | Allow new user registrations | `false` |
| `vaultwarden.rocketPort` | HTTP server port | `8080` |
| `vaultwarden.websocket.enabled` | Enable websocket notifications | `true` |
| `vaultwarden.logging.level` | Log level (trace/debug/info/warn/error/off) | `info` |
| `vaultwarden.icons.service` | Icon service (internal/bitwarden/duckduckgo/google) | `internal` |

### Admin Panel

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultwarden.admin.enabled` | Enable the admin panel at `/admin` | `false` |
| `vaultwarden.admin.token` | Admin token (argon2 hash recommended) | `""` |
| `vaultwarden.admin.existingSecret` | Existing secret name for admin token | `""` |
| `vaultwarden.admin.existingSecretKey` | Key in existing secret | `admin-token` |

### Database

The chart supports two ways to configure the database connection for PostgreSQL/MySQL:

**Option 1: Full connection URL** — provide a complete `DATABASE_URL` via a secret:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.type` | Database backend: `sqlite`, `postgresql`, or `mysql` | `sqlite` |
| `database.url` | Full connection URL (inline, not recommended) | `""` |
| `database.existingSecret` | Secret containing the full database URL | `""` |
| `database.existingSecretKey` | Key in existing secret | `database-url` |

```yaml
database:
  type: postgresql
  existingSecret: my-db-url-secret
  existingSecretKey: database-url
```

**Option 2: Compose from parts** (recommended for Postgres operators) — the chart reads username and password from a credentials secret and assembles the `DATABASE_URL` automatically. This is ideal for Zalando Postgres Operator, CloudNativePG, or any operator that creates per-user credential secrets:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.host` | Database hostname (triggers compose mode) | `""` |
| `database.port` | Database port | `5432` |
| `database.dbName` | Database name | `vaultwarden` |
| `database.credentialsSecret` | Secret with `username` and `password` keys | `""` |
| `database.credentialsSecretUsernameKey` | Key for username | `username` |
| `database.credentialsSecretPasswordKey` | Key for password | `password` |

```yaml
# Example: Zalando Postgres Operator
database:
  type: postgresql
  host: vaultwarden-db.postgres-cluster
  port: 5432
  dbName: vaultwarden
  credentialsSecret: vaultwarden.user.vaultwarden-db.credentials.postgresql.acid.zalan.do
```

This renders as:

```yaml
env:
  - name: _DB_USER
    valueFrom:
      secretKeyRef:
        name: vaultwarden.user.vaultwarden-db.credentials.postgresql.acid.zalan.do
        key: username
  - name: _DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: vaultwarden.user.vaultwarden-db.credentials.postgresql.acid.zalan.do
        key: password
  - name: DATABASE_URL
    value: postgresql://$(_DB_USER):$(_DB_PASSWORD)@vaultwarden-db.postgres-cluster:5432/vaultwarden
```

**Common settings:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.maxConnections` | Max database connections | `10` |
| `database.wal` | Enable WAL mode (SQLite only) | `true` |

### SMTP (Email)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultwarden.smtp.host` | SMTP server hostname | `""` |
| `vaultwarden.smtp.from` | Sender email address | `""` |
| `vaultwarden.smtp.port` | SMTP port | `587` |
| `vaultwarden.smtp.security` | Security mode (starttls/force_tls/off) | `starttls` |
| `vaultwarden.smtp.username` | SMTP username | `""` |
| `vaultwarden.smtp.password` | SMTP password | `""` |
| `vaultwarden.smtp.existingSecret` | Existing secret for SMTP credentials | `""` |
| `vaultwarden.smtp.existingSecretUsernameKey` | Key in existing secret for username | `smtp-username` |
| `vaultwarden.smtp.existingSecretPasswordKey` | Key in existing secret for password | `smtp-password` |

### SSO (OpenID Connect)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultwarden.sso.enabled` | Enable SSO authentication | `false` |
| `vaultwarden.sso.only` | Require SSO (disable password login) | `false` |
| `vaultwarden.sso.authority` | OIDC authority URL | `""` |
| `vaultwarden.sso.clientId` | OIDC client ID | `""` |
| `vaultwarden.sso.clientSecret` | OIDC client secret | `""` |
| `vaultwarden.sso.existingSecret` | Existing secret for SSO credentials | `""` |
| `vaultwarden.sso.existingSecretClientIdKey` | Key in existing secret for client ID | `sso-client-id` |
| `vaultwarden.sso.existingSecretClientSecretKey` | Key in existing secret for client secret | `sso-client-secret` |

### Push Notifications

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultwarden.push.enabled` | Enable push notifications | `false` |
| `vaultwarden.push.installationId` | Installation ID from bitwarden.com/host | `""` |
| `vaultwarden.push.installationKey` | Installation key from bitwarden.com/host | `""` |
| `vaultwarden.push.existingSecret` | Existing secret for push credentials | `""` |
| `vaultwarden.push.relayUri` | Push relay URI | `""` |
| `vaultwarden.push.identityUri` | Push identity URI | `""` |

### Yubico OTP

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultwarden.yubico.enabled` | Enable Yubico OTP | `false` |
| `vaultwarden.yubico.clientId` | Yubico client ID | `""` |
| `vaultwarden.yubico.secretKey` | Yubico secret key | `""` |
| `vaultwarden.yubico.existingSecret` | Existing secret for Yubico credentials | `""` |

### Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type (`ClusterIP`, `NodePort`, `LoadBalancer`) | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `service.nodePort` | Node port (when type is `NodePort`) | `""` |
| `service.loadBalancerIP` | Load balancer IP (when type is `LoadBalancer`) | `""` |
| `service.externalTrafficPolicy` | External traffic policy (`Local` or `Cluster`) | `""` |
| `service.annotations` | Service annotations (e.g. for external-dns) | `{}` |
| `service.labels` | Additional service labels | `{}` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name (e.g. `nginx`, `traefik`, `haproxy`) | `""` |
| `ingress.annotations` | Ingress annotations (e.g. cert-manager, rate-limiting) | `{}` |
| `ingress.labels` | Additional ingress labels | `{}` |
| `ingress.hosts` | Ingress host rules | see `values.yaml` |
| `ingress.tls` | Ingress TLS configuration | `[]` |

Example with full ingress configuration:

```yaml
ingress:
  enabled: true
  className: traefik
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-production
    cert-manager.io/private-key-algorithm: ECDSA
    cert-manager.io/private-key-size: "384"
    cert-manager.io/private-key-rotation-policy: Always
  hosts:
    - host: vault.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vault-tls
      hosts:
        - vault.example.com
```

### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistent storage | `true` |
| `persistence.storageClassName` | Storage class name (see below) | `nil` |
| `persistence.accessModes` | PVC access modes | `[ReadWriteOnce]` |
| `persistence.size` | Storage size | `5Gi` |
| `persistence.existingClaim` | Use an existing PVC | `""` |
| `persistence.annotations` | Additional PVC annotations | `{}` |
| `persistence.labels` | Additional PVC labels | `{}` |

**Storage class behavior:**

| Value | Behavior |
|-------|----------|
| `nil` (unset) | Uses the cluster default storage class |
| `"-"` | Disables dynamic provisioning (`storageClassName: ""`) |
| `"longhorn"` | Uses the specified storage class |

**High availability (multiple replicas):** Running `replicaCount > 1` requires PostgreSQL (SQLite does not support concurrent access) and a storage class that supports `ReadWriteMany` (RWX) access mode, such as NFS, CephFS, or a cloud-native RWX provider (e.g. AWS EFS, Azure Files, GCP Filestore). Update your persistence accordingly:

```yaml
replicaCount: 2

database:
  type: postgresql
  host: my-cluster.postgres
  credentialsSecret: my-pg-credentials

persistence:
  storageClassName: efs-sc  # or any RWX-capable storage class
  accessModes:
    - ReadWriteMany
```

### Security Context

The chart runs vaultwarden as a non-root user (UID 1000) by default with a read-only root filesystem. The `ROCKET_PORT` is set to `8080` to avoid requiring privileged ports.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsUser` | Pod user ID | `1000` |
| `podSecurityContext.runAsGroup` | Pod group ID | `1000` |
| `podSecurityContext.runAsNonRoot` | Enforce non-root | `true` |
| `podSecurityContext.fsGroup` | Pod filesystem group | `1000` |
| `podSecurityContext.seccompProfile.type` | Seccomp profile | `RuntimeDefault` |
| `securityContext.readOnlyRootFilesystem` | Read-only root FS | `true` |
| `securityContext.allowPrivilegeEscalation` | Prevent privilege escalation | `false` |
| `securityContext.capabilities.drop` | Dropped capabilities | `["ALL"]` |

### Scheduling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nodeSelector` | Node selector constraints | `{}` |
| `tolerations` | Pod tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `topologySpreadConstraints` | Topology spread constraints | `[]` |
| `priorityClassName` | Priority class for pod scheduling | `""` |

### Other

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create a service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.automountServiceAccountToken` | Automount SA token | `false` |
| `resources` | CPU/memory resources | see `values.yaml` |
| `revisionHistoryLimit` | Deployment revision history limit | `3` |
| `terminationGracePeriodSeconds` | Termination grace period | `30` |
| `startupProbe` | Startup probe config (for slow starts) | `{}` |
| `initContainers` | Init containers | `[]` |
| `extraVolumes` | Additional volumes | `[]` |
| `extraVolumeMounts` | Additional volume mounts | `[]` |
| `podAnnotations` | Pod annotations | `{}` |
| `podLabels` | Additional pod labels | `{}` |

### Environment Variables

The chart provides three layers for setting environment variables, from simplest to most flexible:

**`env`** — plain key-value map for any vaultwarden env var:

```yaml
env:
  SIGNUPS_ALLOWED: "true"
  INVITATION_ORG_NAME: "My Org"
  SENDS_ALLOWED: "true"
```

**`secretEnv`** — shorthand for sourcing env vars from Kubernetes secrets:

```yaml
secretEnv:
  ADMIN_TOKEN:
    secretName: my-admin-secret
    secretKey: admin-token
  DATABASE_URL:
    secretName: my-db-secret
    secretKey: database-url
```

**`extraEnv`** — raw Kubernetes env spec for complex cases (fieldRef, resourceFieldRef, etc.):

```yaml
extraEnv:
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
```

These layers are additive and render in order: structured values (from `vaultwarden.*`), then `env`, then `secretEnv`, then `extraEnv`. Later values override earlier ones for the same env var name.

## Using Existing Secrets

For production deployments, use `existingSecret` references instead of putting credentials in `values.yaml`. All sensitive values support `existingSecret`:

```bash
# Create secrets before installing the chart
kubectl create secret generic vaultwarden-admin \
  --from-literal=admin-token='$argon2id$...'

kubectl create secret generic vaultwarden-db \
  --from-literal=database-url='postgresql://user:pass@host:5432/vaultwarden'

kubectl create secret generic vaultwarden-smtp \
  --from-literal=smtp-username='user@example.com' \
  --from-literal=smtp-password='password'

kubectl create secret generic vaultwarden-sso \
  --from-literal=sso-client-id='vaultwarden' \
  --from-literal=sso-client-secret='secret'

kubectl create secret generic vaultwarden-push \
  --from-literal=push-installation-id='...' \
  --from-literal=push-installation-key='...'
```

Then reference them in your values:

```yaml
vaultwarden:
  admin:
    enabled: true
    existingSecret: vaultwarden-admin
  smtp:
    host: smtp.example.com
    from: vault@example.com
    existingSecret: vaultwarden-smtp
  sso:
    enabled: true
    authority: https://auth.example.com/realms/main
    existingSecret: vaultwarden-sso
  push:
    enabled: true
    existingSecret: vaultwarden-push
database:
  type: postgresql
  existingSecret: vaultwarden-db
```

## Mounting Custom CA Certificates

To trust custom CA certificates (e.g. for LDAP or SSO with self-signed certs):

```yaml
extraVolumes:
  - name: custom-certs
    secret:
      secretName: ca-bundle

extraVolumeMounts:
  - name: custom-certs
    mountPath: /etc/ssl/certs/custom
    readOnly: true

extraEnv:
  - name: SSL_CERT_DIR
    value: /etc/ssl/certs:/etc/ssl/certs/custom
```
