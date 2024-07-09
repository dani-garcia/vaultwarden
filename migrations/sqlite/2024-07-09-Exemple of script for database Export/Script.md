```bash
#!/bin/bash

# Variables
SRC="user@ip of database source:/your/file/for/data/base" #EDITTHIS
DEST="/destinyourmachine" #EDITTHIS
INCLUDE="db*"
SSH_KEY="/file/ssh/key" #EDITTHIS
LOG_DIR="/file/log/" #EDITTHIS
LOG_FILE="$LOG_DIR/rsync_db_$(date +'%Y-%m-%d_%H-%M').log" #Name your log
EMAIL="Your Email" #EDITTHIS

# Capture the date and time of script execution
EXEC_DATE=$(date +'%Y-%m-%d %H:%M')

# Create the log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Start of the script
echo "Start of the rsync script execution" >> "$LOG_FILE"

# Execute the rsync command
if rsync -avz --include="$INCLUDE" --exclude='*' -e "ssh -i $SSH_KEY" "$SRC" "$DEST" >> "$LOG_FILE" 2>&1; then
    RSYNC_STATUS="OK"
    echo "Rsync synchronization completed successfully." >> "$LOG_FILE"
else
    RSYNC_STATUS="KO"
    echo "Rsync synchronization failed." >> "$LOG_FILE"
fi

# Display a message after rsync execution
echo "End of rsync script execution" >> "$LOG_FILE"

# Delete log files older than 7 days
if find "$LOG_DIR" -type f -name "rsync_db_*.log" -mtime +7 -exec rm {} \; >> "$LOG_FILE" 2>&1; then
    FIND_STATUS="OK"
    echo "Old log files deleted." >> "$LOG_FILE"
else
    FIND_STATUS="KO"
    echo "Failed to delete old log files." >> "$LOG_FILE"
fi

# Display a message after deleting old logs
echo "End of old log files deletion" >> "$LOG_FILE"

# Email body
MAIL_BODY="Summary of the rsync script execution on $EXEC_DATE:

- Rsync synchronization: $RSYNC_STATUS
- Deletion of old logs: $FIND_STATUS
- Log file created: $LOG_FILE

Execution details:
$(cat "$LOG_FILE")"

# Send the email
echo "$MAIL_BODY" | mail -s "Database Synchronization" "$EMAIL"
```
