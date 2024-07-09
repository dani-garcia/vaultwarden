# Database Export Script

## Exporting the Database with a Script

On the machine that will receive the database, create an SSH connection using SSH keys. Then, create a script file that will:
- Copy the database
- Create a log file of the execution of this command
- Delete old log files
- Send a summary email to one or more email addresses.

You need to configure a mail server on your receiving machine and install the "crontab" tool if it is not already installed.

## Explanation of the script

### Prerequisites:

- *Install crontab service if it is not running yet*
- *Install the ackage for sending mail, which can be done easily with mailutils*

**Variables**

```bash
# Variables
SRC="user@ip of database source:/your/file/for/data/base" #EDITTHIS
DEST="/destinyourmachine" #EDITTHIS
INCLUDE="db*"
SSH_KEY="/file/ssh/key" #EDITTHIS
LOG_DIR="/file/log/" #EDITTHIS
LOG_FILE="$LOG_DIR/rsync_db_$(date +'%Y-%m-%d_%H-%M').log" #Name your log
EMAIL="Your Email" #EDITTHIS
```

We declare all our variables:

```bash
SRC: The source, the machine from which we will retrieve our databases.
DEST: The destination, the location where we copy the databases on the receiving machine (the machine that runs the script).
INCLUDE / EXCLUDE: I only want the files that start with "db".
SSH_KEY: Our SSH key to avoid having to enter a password for the connection.
LOG_DIR: The location where I want my log files.
LOG_FILE: Its name with the current date.
EMAIL: The email that will receive the logs.
```

*Execute the rsync command*

```bash
if rsync -avz --include="$INCLUDE" --exclude='*' -e "ssh -i $SSH_KEY" "$SRC" "$DEST" >> "$LOG_FILE" 2>&1; then
    RSYNC_STATUS="OK"
    echo "Rsync synchronization completed successfully." >> "$LOG_FILE"
else
    RSYNC_STATUS="KO"
    echo "Rsync synchronization failed." >> "$LOG_FILE"
fi
```

The rsync command for copying the databases, with logging to a file if the command result is OK or KO.

Delete log files older than 7 days

```bash
if find "$LOG_DIR" -type f -name "rsync_db_*.log" -mtime +7 -exec rm {} \; >> "$LOG_FILE" 2>&1; then
    FIND_STATUS="OK"
    echo "Old log files deleted." >> "$LOG_FILE"
else
    FIND_STATUS="KO"
    echo "Failed to delete old log files." >> "$LOG_FILE"
fi

# Display a message after deleting old logs
echo "End of old log files deletion" >> "$LOG_FILE"
Delete log files older than 7 days with logging to a file.
```

Email body

```bash
Copier le code
MAIL_BODY="Summary of the rsync script execution on $EXEC_DATE:

- Rsync synchronization: $RSYNC_STATUS
- Deletion of old logs: $FIND_STATUS
- Log file created: $LOG_FILE

Execution details:
$(cat "$LOG_FILE")"

# Send the email
echo "$MAIL_BODY" | mail -s "Database Synchronization" "$EMAIL
```

Send a summary email to the addresses entered in the variables.

The script is executed every day at 2:00 AM. The execution is managed by crontab with the command **crontab -e** using this line:

```bash
0 2 * * * /usr/local/bin/rsync_db.sh
```
