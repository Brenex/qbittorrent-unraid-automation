# qbittorrent-unraid-automation

## Table of Contents

- [Overview](https://gemini.google.com/app/#overview "null")
- [Features](https://gemini.google.com/app/#features "null")
- [Prerequisites](https://gemini.google.com/app/#prerequisites "null")
- [Installation](https://gemini.google.com/app/#installation "null")
	- [Dependencies](https://gemini.google.com/app/#dependencies "null")
	- [Environment Variables (.env)](https://gemini.google.com/app/#environment-variables-env "null")
- [Usage](https://gemini.google.com/app/#usage "null")
	- [Command-Line Arguments](https://gemini.google.com/app/#command-line-arguments "null")
	- [Example Usage](https://gemini.google.com/app/#example-usage "null")
- [Logging](https://gemini.google.com/app/#logging "null")
- [Discord Notifications](https://gemini.google.com/app/#discord-notifications "null")
- [Troubleshooting](https://gemini.google.com/app/#troubleshooting "null")

## Overview

This Python script automates two critical maintenance tasks for users running qBittorrent on an Unraid server: removing unregistered torrents and managing the Unraid mover process. It is designed to streamline media server management by ensuring data integrity and optimizing storage utilization, providing comprehensive logging and rich Discord notifications.

## Features

1. **Unregistered Torrent Removal:**
	- Connects to the qBittorrent Web UI to retrieve torrent information.
	- Identifies and deletes torrents that report an 'unregistered torrent' status from their trackers, removing both the torrent entry and its associated files from the system.
	- Logs other instances of failing tracker issues for monitoring, and sends a system notification to Unraid for these.
	- Generates a detailed log report of deleted torrents and other tracker issues.
2. **Unraid Mover Automation:**
	- Scans the Unraid cache drive to identify files that are part of active qBittorrent torrents.
	- Temporarily pauses these identified torrents in qBittorrent to prevent issues during data movement.
	- Executes the Unraid mover (`/usr/local/sbin/mover`) to transfer files from the cache drive to the array.
	- Resumes the paused torrents once the mover operation is complete.
	- Includes logic to strip FUSE filesystem mount points for accurate path comparison and allows specific cache folders (e.g., `appdata`) to be ignored during the scan.
3. **Comprehensive Logging & Notifications:**
	- Maintains detailed logs of its operations to both console output and timestamped log files.
	- Implements log file retention, automatically cleaning up old logs.
	- Sends rich Discord notifications at the start and end of the script execution, including timestamps and duration.
	- Provides a summary Discord notification after all main tasks (torrent removal and mover) are complete, detailing actions taken, status of operations, and attaching the main script log file.
	- Configuration for qBittorrent connection details and Discord webhook URL is loaded from a `.env` file, supporting secure and flexible deployment.

## Prerequisites

- **Python 3.x:** The script requires Python 3.
- **qBittorrent:** A running qBittorrent instance with Web UI enabled.
- **Unraid OS:** The script is specifically designed for Unraid servers, utilizing the `/usr/local/sbin/mover` and `/usr/local/emhttp/plugins/dynamix/scripts/notify` commands.
- **Discord Webhook (Optional):** For Discord notifications.

## Installation

### Dependencies

Install the required Python packages using `pip`:

```
pip install -r requirements.txt
```

The `requirements.txt` file should contain:

```
requests
qbittorrentapi
python-dotenv
```

### Environment Variables (.env)

For secure and flexible configuration, the script loads sensitive information from a `.env` file. Create a file named `.env` in the same directory as the script and populate it with your details:

```
# qBittorrent Web UI Access
QB_HOST=http://your_qbittorrent_ip:port # e.g., http://192.168.1.100:8080 or http://unraid:8080
QB_USER=your_qb_username
QB_PASSWORD=your_qb_password

# Discord Notifications (Optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
```

**Note:** Ensure `QB_HOST` includes the `http://` or `https://` schema. The script will attempt to prepend `http://` if missing, but it's best practice to include it explicitly.

## Usage

Run the script from your Unraid server's terminal or via a scheduled task (e.g., User Scripts plugin).

```
python3 /path/to/your/script/qbittorrent-unraid-automation.py --cache-mount /mnt/cache --user-share-mount /mnt/user
```

### Command-Line Arguments

The script supports the following command-line arguments:

- `--host <URL>`: qBittorrent host including port (e.g., `http://localhost:8080`). Defaults to `QB_HOST` from `.env`.
- `-u <USERNAME>`, `--user <USERNAME>`: qBittorrent username. Defaults to `QB_USER` from `.env`.
- `-p <PASSWORD>`, `--password <PASSWORD>`: qBittorrent password. Defaults to `QB_PASSWORD` from `.env`.
- `--cache-mount <PATH>`: **(Required)** Cache mount point in Unraid (e.g., `/mnt/cache`). Used to scan for files. This path will be stripped during comparison.
- `--user-share-mount <PATH>`: **(Required)** User share mount point in Unraid (e.g., `/mnt/user`). This path will be stripped from torrent file paths for comparison.
- `--status-filter <STATUS_LIST>`: Comma-separated list of qBittorrent statuses to filter torrents for mover operations. E.g., `'downloading,seeding,completed'`. Use `'all'` to check all torrents. Default: `'uploading,queuedUP,stalledUP,stalledDL,completed'`.
- `--ignore-cache-folders <PATH_LIST>`: Comma-separated list of absolute paths on the cache drive to ignore during scanning. E.g., `'/mnt/cache/appdata,/mnt/cache/system'`. Default: `""` (empty).
- `--discord-webhook-url <URL>`: Discord webhook URL for notifications. Overrides the value from the `.env` file. Defaults to `DISCORD_WEBHOOK_URL` from `.env`.

### Example Usage

To run the script with default credentials from `.env` and specific mount points:

```
python3 /mnt/user/scripts/qbittorrent-unraid-automation/qbittorrent-unraid-automation.py \
    --cache-mount /mnt/cache \
    --user-share-mount /mnt/user
```

To run with overridden qBittorrent credentials and ignore a specific appdata folder:

```
python3 /mnt/user/scripts/qbittorrent-unraid-automation/qbittorrent-unraid-automation.py \
    --host http://192.168.1.50:8080 \
    -u myuser -p mysecurepassword \
    --cache-mount /mnt/cache \
    --user-share-mount /mnt/user \
    --ignore-cache-folders /mnt/cache/appdata/plex
```

## Logging

The script logs its operations to both standard output (console) and a timestamped log file within a `logs/` subdirectory relative to the script's location.

Log files are automatically cleaned up, with files older than `LOG_RETENTION_DAYS` (default 7 days) being removed.

## Discord Notifications

The script sends rich embed notifications to a specified Discord webhook URL for key events:

- **Script Start:** A blue informational embed indicating the script has begun, including the start time.
- **Overall Report:** A comprehensive summary embed after both torrent removal and mover tasks are complete.
	- **Green:** Indicates overall success or no issues found.
	- **Orange:** Indicates minor issues (e.g., unregistered torrents deleted or other tracker issues found) but no critical failures.
	- **Red:** Indicates critical errors or failures during either the torrent removal or mover process.
	- This embed will include a summary of deleted torrents, other tracker issues, mover status, and mover `stderr` output if available. The main script log file will be attached.
- **Script End:** A blue informational embed indicating the script has finished, including the end time and total duration.

## Troubleshooting

- **`InvalidSchema: No connection adapters were found for '...'`**: This means the qBittorrent host URL is missing `http://` or `https://`. Ensure your `QB_HOST` in `.env` or `--host` argument includes the full schema.
- **`requests.exceptions.HTTPError: 401 Client Error: Unauthorized`**: Your qBittorrent username or password is incorrect. Verify your `QB_USER` and `QB_PASSWORD` in `.env` or your command-line arguments.
- **`qbittorrentapi.exceptions.LoginFailed` / `APIConnectionError`**: The script could not connect or log in to qBittorrent. Check the host URL, port, network connectivity, and qBittorrent Web UI status.
- **`Mover command failed with exit code 1`**: The Unraid mover command itself encountered an error.
	- **SSH into your Unraid server** and manually run `/usr/local/sbin/mover start` to see the exact error message.
	- Check your Unraid system logs for more details.
	- Ensure your Unraid array is healthy and there's sufficient disk space.
	- Confirm the mover isn't already running.
- **`FileNotFoundError: notify`**: The Unraid system notification script (`/usr/local/emhttp/plugins/dynamix/scripts/notify`) was not found. This path is standard for Unraid; verify your Unraid installation or script's execution environment.
- **Discord notifications not appearing**:
	- Double-check your `DISCORD_WEBHOOK_URL` in `.env` or as a command-line argument for correctness.
	- Ensure the Discord channel where the webhook is configured has appropriate permissions.
	- Check the script's logs for any `Discord HTTP Error` messages.
