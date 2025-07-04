## Data Backup Instructions
Regular data backups are critical to maintaining the integrity and availability of your Vaultwarden instance. Whether you're operating a personal password manager or managing access for a small organization, unexpected data loss can result in severe consequences—including permanent loss of credentials. Vaultwarden backups ensure that, in the event of hardware failure, configuration errors, or user mistakes, your encrypted vault data can be reliably recovered.

### Why Backups Matter

Vaultwarden stores sensitive information—passwords, secure notes, and credentials—for individuals and teams. Without proper backups:

* You risk **total data loss** if the server is corrupted or compromised.
* You lack a recovery option after unintended file deletions or misconfigurations.
* You limit your ability to safely **migrate Vaultwarden to another machine or VM**.

---

## Backup Script and Setup

The following script safely stops Vaultwarden, compresses your data directory, and transfers it to a secondary virtual machine (for offsite protection). This method is designed to work with Docker-based Vaultwarden deployments, but you can adapt it for your setup.

### Features

* Timestamped `.zip` archives of the entire data directory.
* Uses `scp` for secure file transfer.
* Works with SSH keys.
* Can be automated via `cron`.

### Backup Script (`transfer_vaultwarden_logs.sh`)

```bash
#!/bin/bash

# Stop Vaultwarden container to ensure data consistency
docker-compose down

# Create timestamp for backup filename
datestamp=$(date +%m-%d-%Y)

# Define local backup directory (customize this path as needed)
backup_dir="/home/<user>/vw-backups"

# Compress Vaultwarden data directory into a timestamped zip archive
zip -9 -r "${backup_dir}/${datestamp}.zip" /opt/vw-data*

# Transfer backup to a remote machine using scp (customize SSH identity and remote user/IP)
scp -i ~/.ssh/id_rsa "${backup_dir}/${datestamp}.zip" user@<REMOTE_IP>:~/vw-backups/

# Restart Vaultwarden container
docker-compose up -d
```

### Optional Automation Recommendation

To run this daily at midnight, you can add the script to `crontab -e`:

```bash
0 0 * * * /root/transfer_vaultwarden_logs.sh
```

---

## Cleanup Script (`cleanup_backups.sh`)

To avoid storage bloat on the remote VM, this script keeps only the most recent backup file (last 24 hours) and deletes the rest.

```bash
#!/bin/bash

# Path to directory containing backups
backup_dir=~/backups

# Navigate to backup directory
cd "$backup_dir" || exit

# Delete all zip files except those modified in the last 24 hours
find . -type f -name '*.zip' ! -mtime -1 -exec rm {} +

exit 0
```

You may also schedule this cleanup script daily on the remote VM using `crontab`.

---

## Using the Backup

If your Vaultwarden instance becomes corrupted or you’re migrating to a new server, you can easily restore from a previous backup.

### Restore Instructions

1. **Stop Vaultwarden**:

   ```bash
   docker-compose down
   ```

2. **Delete the current data directory**:

   ```bash
   rm -rf /opt/vw-data/*
   ```

3. **Unzip the backup archive into `/opt/vw-data`**:

   ```bash
   unzip backups/MM-DD-YYYY.zip -d /opt/
   ```

   > Ensure that the extracted folder replaces `/opt/vw-data`, or move its contents accordingly.

4. **Restart the container**:

   ```bash
   docker-compose up -d
   ```

Your Vaultwarden instance should now be restored to the state captured in the backup file.

---

## Example Use Cases

* **Migrating** Vaultwarden from one VM to another.
* **Disaster recovery** after filesystem corruption or misconfiguration.
* **Scheduled daily backups** for operational peace of mind.
* **Testing upgrades**: Back up before a major version upgrade to roll back if needed.

---

If you're running Vaultwarden in a production environment, we strongly recommend integrating this backup process into your regular operations. Always test restores periodically to ensure your backups are reliable.
