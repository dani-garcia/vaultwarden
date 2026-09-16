# Admin Docker updates

Diagnostics reuses the yellow **Update** badge beside **Server Installed** as a
button. While the host downloads the configured image, backs up the vault, and
replaces the container, it shows **Updating…**.
After the new container is healthy, the page reloads. Refreshing the browser does
not cancel the update. An unchanged image does not restart the service.

The server operator must first deploy an image containing admin update support.
Compatible images carry the `org.vaultwarden.admin-updates=1` label. Older images
without this feature are rejected so an update cannot remove the admin endpoint.

## Supported deployment

- Linux host with Python 3.10+, Docker, and Docker Compose v2+.
- One existing Compose service, with its dedicated data directory bind-mounted at
  `/data`, a healthy Docker health check, and SQLite/all persistent data under
  `/data`. Named data volumes, external databases/storage, symlinks in data, and
  additional writable mounts are deliberately rejected before the service stops.
- Custom environment files and file-based storage configuration are not supported.
  `DATA_FOLDER` must be `/data` and `CONFIG_FILE` must use `/data/config.json`.
- The existing Compose files remain the source of truth for ports, environment,
  mounts, networks, and restart policy. Do not modify them or redeploy the same
  service while an update is active.
  Unapplied Compose configuration changes are rejected before an update starts.
- Admin authentication is required. `DISABLE_ADMIN_TOKEN=true` disables updates.

The updater runs on the Docker host and survives Vaultwarden container replacement.
Vaultwarden receives only the updater's Unix socket; it never receives the Docker
socket. The browser cannot choose images, commands, or target services. Protect the
updater configuration and socket as administrative interfaces.

## One-time installation

Adapt every example path, project name, and service name to the **existing** stack.
Do not replace the existing Compose file with a new stack. The example registry
name is a placeholder; replace it with the repository you publish or trust.

1. Build and publish a compatible image to your registry. For an amd64 server, for example:

   ```sh
   docker buildx build --platform linux/amd64 -f docker/Dockerfile.debian \
     -t registry.example.com/vaultwarden:latest --push .
   ```

   Use the server's actual architecture. Publish a versioned tag as well if you need
   release history. Only move `latest` to a reviewed, tested image. Image publishing
   is managed separately; the updater only deploys the configured image channel.

2. Install `updater.py` at `/opt/vaultwarden-updater/updater.py`, copy
   `config.example.json` to `/etc/vaultwarden-updater.json`, and fill in the actual
   Compose files (in their existing order), project, service, data path, and image.
   Use absolute paths. Keep `/var/lib/vaultwarden-updater` outside the data directory.
   Keep the config and script root-owned and not writable by the application user.
   Log in to a private registry on the host as the updater's OS user, if necessary.

3. Install `vaultwarden-updater.service` in `/etc/systemd/system/`, then run:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now vaultwarden-updater
   ```

4. Add only these settings to the existing Vaultwarden service, alongside its
   existing configuration, and deploy the first compatible image through your existing
   deployment procedure:

   ```yaml
   environment:
     UPDATER_SOCKET: /run/vaultwarden-updater/updater.sock
   volumes:
     - /run/vaultwarden-updater:/run/vaultwarden-updater:ro
   ```

   Mount the **directory**, so restarting the updater can replace its socket.
   The service defaults to root:root socket permissions `0660`, matching the
   default root Vaultwarden container. For a non-root container, set the unit's
   `Group` and the container's supplemental numeric group to the same dedicated
   group. The directory requires group traversal permission.

5. Open **Admin → Diagnostics → Update**. Do the first update on a test deployment
   and verify vault login, sync, and attachments before enabling production use.

## Deployment and recovery

The updater downloads the configured tag while the old service remains available.
It then pins the downloaded **image ID**, stops just the selected service, archives
all of `/data`, and recreates that service with `--no-deps --no-build --pull never`.
Backups are stored at `state_directory/backups/<deployment-id>/data.tar`, along with
the previous and target image IDs in `deployment.json`. Protect these archives as
vault data and manage their retention/free disk space on the host.

The selected image is persisted in `state_directory/image.override.json`. Include
this file **last** in future manual Compose commands; otherwise a manual deployment
could restore the old image from the base Compose file. For example:

```sh
docker compose --project-directory /opt/vaultwarden --project-name vaultwarden \
  -f /opt/vaultwarden/compose.yml \
  -f /var/lib/vaultwarden-updater/image.override.json ps
```

Failures before stopping the service leave it running. Failures after a stop was
requested, and updater interruptions, require host inspection and block subsequent
updates. `status.json` records the last completed stage. Full Docker output and
container environment values are never sent to the browser.

Do not simply run an old image against a database migrated by a new image. To
recover, stop the updater, inspect the container and the saved deployment metadata,
and repair the deployment. If restoring the previous version is necessary, stop
the vault, preserve its current data separately, restore the selected `data.tar`
backup with its ownership and permissions, set `image.override.json` to the saved
previous image ID, and start the service. Restoration may discard writes accepted
after the backup, so it is an operator decision, never an automatic action.

After checking the running service, clear the recovery lock while the updater
service is stopped, then start the updater again:

```sh
sudo systemctl stop vaultwarden-updater
sudo python3 /opt/vaultwarden-updater/updater.py /etc/vaultwarden-updater.json \
  --acknowledge-recovery
sudo systemctl start vaultwarden-updater
```

This command verifies the container's health and data configuration before clearing
the lock. Keep previous images until the new release is stable; image pruning can
otherwise remove the saved rollback target.

## Local verification

```sh
python3 -m unittest discover -s docker/updater -v
cargo check --locked --features sqlite
node --check src/static/scripts/admin_updates.js
```

The Python flow tests use a controlled Docker adapter and real temporary backup
archives. They cover unchanged images, rejected images/storage, download/recreation/
health failures, duplicate requests, and interrupted updater recovery. They do not
replace a test of an actual Docker deployment.
