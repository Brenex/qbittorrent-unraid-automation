#!/usr/bin/env python3
"""
This script automates maintenance tasks for qBittorrent and Unraid, enhancing media server management.

It performs the following key functions:

1.  **Unregistered Torrent Removal:**
    * Connects to the qBittorrent Web UI to retrieve torrent information.
    * Identifies and deletes torrents that report an 'unregistered torrent' status from their trackers,
        removing both the torrent entry and its associated files from the system.
    * Logs other instances of failing tracker issues for monitoring, and sends a system notification
        to Unraid for these.
    * Generates a detailed log report of deleted torrents and other tracker issues.

2.  **Unraid Mover Automation:**
    * Scans the Unraid cache drive to identify files that are part of active qBittorrent torrents.
    * Temporarily pauses these identified torrents in qBittorrent to prevent issues during data movement.
    * Executes the Unraid mover (`/usr/local/sbin/mover`) to transfer files from the cache drive to the array.
    * Resumes the paused torrents once the mover operation is complete.
    * Includes logic to strip FUSE filesystem mount points for accurate path comparison and allows
        specific cache folders (e.g., appdata) to be ignored during the scan.

3.  **Comprehensive Logging & Notifications:**
    * Maintains detailed logs of its operations to both console output and timestamped log files.
    * Implements log file retention, automatically cleaning up old logs.
    * Sends rich Discord notifications at the start and end of the script execution, including timestamps and duration.
    * Provides a summary Discord notification after all main tasks (torrent removal and mover) are complete,
        detailing actions taken, status of operations, and attaching the main script log file.
    * Configuration for qBittorrent connection details and Discord webhook URL is loaded from a `.env` file,
        supporting secure and flexible deployment.

**Usage:**
Run the script with required arguments for Unraid mount points. Configuration (qBittorrent credentials,
Discord webhook) can be provided via a `.env` file or command-line arguments.

Example:
    python3 qbittorrent-unraid-automation.py --cache-mount /mnt/cache --user-share-mount /mnt/user

"""

# Standard library imports
import argparse  # For parsing command-line arguments
import json  # For working with JSON data
import logging  # For logging messages
import os  # For interacting with the operating system
import subprocess  # For running subprocess commands
import sys  # For accessing system-specific parameters
import time  # For time-related functions
from datetime import datetime, timedelta  # For working with dates and times

# Third-party imports
import requests  # For making HTTP requests
from dotenv import load_dotenv  # For loading environment variables from a .env file

# --- CONFIGURATION START ---
# Load environment variables from .env file
load_dotenv()

# Define log retention for the script's own log files
LOG_RETENTION_DAYS = 7

# For normal operation, set LOG_LEVEL to logging.INFO.
# For detailed debugging, set to logging.DEBUG.
LOG_LEVEL = logging.INFO  # Setting to INFO for typical production use. Change to DEBUG for detailed troubleshooting.

# Default qBittorrent connection details (can be overridden by command-line arguments or environment variables)
# Prioritize environment variables, then command-line defaults
DEFAULT_QB_HOST = os.getenv('QB_HOST', 'http://localhost:8080')
DEFAULT_QB_USER = os.getenv('QB_USER', 'admin')
DEFAULT_QB_PASSWORD = os.getenv('QB_PASSWORD', 'adminadmin') # Consider using a more secure method like a secrets management system for production

# Discord Webhook URL for notifications (optional, prioritized from environment)
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', '') # Replace with your Discord webhook URL if desired, or leave empty to disable

# Initialize requests session for HTTP calls (used by the unregistered torrent part)
session = requests.Session()
# --- CONFIGURATION END ---


# --- LOGGING CONFIGURATION START ---
# Create a logger instance
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

# Create a formatter for log messages
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

# Console handler (outputs to stdout)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)  # Console output less verbose (INFO and above)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def get_logs_dir():
    """Returns the path to the logs directory, creating it if it doesn't exist."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(script_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir


def get_current_run_log_file_path():
    """Generates a timestamped log file path for the current script run."""
    logs_dir = get_logs_dir()
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return os.path.join(logs_dir, f'qbittorrent-automation_{timestamp}.log') # Unified log file name


def get_unregistered_log_file_path():
    """Generates a unique file path for the unregistered torrent log."""
    logs_dir = get_logs_dir()
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return os.path.join(logs_dir, f'deleted_unregistered_torrents_{timestamp}.log')


# Get the log file path for the current run
current_script_log_file_path = get_current_run_log_file_path()

# File handler (outputs to a file)
try:
    file_handler = logging.FileHandler(current_script_log_file_path)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info(f"Logging current run to: {current_script_log_file_path}")
except Exception as e:
    logger.error(f"Failed to set up file logger at {current_script_log_file_path}: {e}")
    logger.warning("Continuing with console-only logging due to file logging error.")


def cleanup_old_logs():
    """Deletes log files older than LOG_RETENTION_DAYS."""
    logs_dir = get_logs_dir()
    cutoff_time = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)

    logger.info(f"Cleaning up old logs in '{logs_dir}' older than {LOG_RETENTION_DAYS} days.")

    for filename in os.listdir(logs_dir):
        # Target files starting with 'qbittorrent-automation_' or 'deleted_unregistered_torrents_' and ending with '.log'
        if (filename.startswith("qbittorrent-automation_") or filename.startswith("deleted_unregistered_torrents_")) \
                and filename.endswith(".log"):
            file_path = os.path.join(logs_dir, filename)
            try:
                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                if file_time < cutoff_time:
                    os.remove(file_path)
                    logger.info(f"Removed old log file: {filename}")
            except OSError as e:
                logger.error(f"Failed to delete old log file {filename}: {e}", exc_info=True)
            except Exception as e:
                logger.error(f"An unexpected error occurred while processing log file {filename}: {e}", exc_info=True)


# --- LOGGING CONFIGURATION END ---


# --- qBittorrent API Setup (for mover part) ---
try:
    from qbittorrentapi import APIConnectionError, Client, LoginFailed
except ModuleNotFoundError:
    logger.error(
        'Requirements Error: qbittorrent-api not installed. Please install using the command "pip install qbittorrent-api"'
    )
    sys.exit(1)


# --- Unregistered Torrent Removal Functions ---
def login_qbittorrent(host, username, password) -> bool:
    """
    Attempts to log into the qBittorrent Web UI using requests.Session.

    Args:
        host (str): qBittorrent host URL.
        username (str): qBittorrent username.
        password (str): qBittorrent password.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    logger.info("Attempting to log into qBittorrent for unregistered torrent check...")
    try:
        resp = session.post(f'{host}/api/v2/auth/login', data={'username': username, 'password': password})
        if resp.text == 'Ok.':
            logger.info("Successfully logged in to qBittorrent (requests session).")
            return True
        elif resp.text == 'Fails.':
            logger.error("Login failed: Invalid username or password.")
            return False
        else:
            logger.error(f"Login failed: Unexpected response from qBittorrent API: '{resp.text}'.")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Network or connection error during qBittorrent login: {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during qBittorrent login: {e}", exc_info=True)
        return False


def logout_qbittorrent(host):
    """
    Logs out of the qBittorrent Web UI using requests.Session.
    """
    logger.info("Attempting to log out of qBittorrent (requests session)...")
    try:
        session.get(f'{host}/api/v2/auth/logout')
        logger.info("Successfully logged out of qBittorrent (requests session).")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Network error during logout: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during logout: {e}")


def delete_torrent_by_hash(qb_host: str, torrent_hash: str, torrent_name: str) -> bool:
    """
    Deletes a specified torrent and its associated files from qBittorrent using requests.Session.

    Args:
        qb_host (str): The qBittorrent host URL.
        torrent_hash (str): The hash of the torrent to delete.
        torrent_name (str): The name of the torrent (for logging purposes).

    Returns:
        bool: True if the torrent was successfully deleted, False otherwise.
    """
    logger.info(f"Attempting to delete torrent: '{torrent_name}' (Hash: {torrent_hash})")
    try:
        resp = session.post(
            f'{qb_host}/api/v2/torrents/delete',
            data={'hashes': torrent_hash, 'deleteFiles': 'true'}
        )
        if resp.status_code == 200:
            logger.info(f"Successfully deleted torrent: '{torrent_name}'")
            return True
        else:
            logger.error(f"Failed to delete torrent: '{torrent_name}' | HTTP Status: {resp.status_code} | Response: {resp.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error when deleting torrent '{torrent_name}': {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while deleting torrent '{torrent_name}': {e}", exc_info=True)
        return False


def send_discord_notification_embed(
    webhook_url: str,
    title: str,
    description: str,
    color: int,
    fields: list = None,
    log_file_path: str = None
):
    """
    Sends a rich Discord embed notification, optionally with a log file attachment.

    Args:
        webhook_url (str): The Discord webhook URL.
        title (str): The title of the embed.
        description (str): The main description of the embed.
        color (int): The color of the embed sidebar (e.g., 0x00FF00 for green).
        fields (list, optional): A list of field dictionaries for the embed. Defaults to None.
        log_file_path (str, optional): Path to a log file to attach. Defaults to None.
    """
    if not webhook_url:
        logger.warning("Discord webhook URL is not configured. Skipping Discord notification.")
        return

    payload = {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.now().isoomat(),
                "fields": fields if fields else [],
                "footer": {
                    "text": "qBittorrent Unraid Automation Script"
                }
            }
        ]
    }
    
    files = {}
    if log_file_path and os.path.exists(log_file_path):
        try:
            files = {
                'file': (os.path.basename(log_file_path), open(log_file_path, 'rb'), 'text/plain')
            }
        except Exception as e:
            logger.error(f"Failed to open log file for Discord upload: {e}")
            log_file_path = None # Don't try to send file if opening failed

    logger.info(f"Attempting to send Discord notification to: {webhook_url}")
    try:
        if files:
            # When sending files, the payload must be sent as a separate 'payload_json' part
            # and the 'Content-Type' is handled by requests with 'multipart/form-data'
            response = requests.post(webhook_url, data={"payload_json": json.dumps(payload)}, files=files)
        else:
            response = requests.post(webhook_url, json=payload)

        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        logger.info("Successfully sent Discord notification.")
    except requests.exceptions.HTTPError as errh:
        logger.error(f"Discord HTTP Error: {errh} - {errh.response.text}")
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Discord Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        logger.error(f"Discord Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        logger.error(f"Discord Request Error: {err}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending Discord notification: {e}", exc_info=True)
    finally:
        if 'file' in files and files['file'] and files['file'][1] and not files['file'][1].closed: # Check if file was opened and is not closed before trying to close
            files['file'][1].close() # Ensure file handle is closed


def find_and_delete_unregistered_torrents_task(qb_host: str, discord_webhook: str) -> dict:
    """
    Fetches torrent information from qBittorrent, identifies torrents with
    'unregistered torrent' tracker status messages, deletes them, and
    notifies about other failing tracker issues.
    Generates a detailed log report.
    Returns a dictionary of summary statistics.
    """
    logger.info("Starting scan for unregistered and failing torrents...")
    deleted_count = 0
    notified_issues_count = 0
    system_notification_sent = False
    
    try:
        torrents_response = session.get(f'{qb_host}/api/v2/torrents/info')
        torrents_response.raise_for_status()
        torrents = torrents_response.json()
    except requests.exceptions.RequestException as e:
        logger.critical(f"Failed to retrieve torrent info from qBittorrent: {e}")
        return {"deleted": 0, "notified_issues": 0, "system_notif_sent": False, "report_path": None}
    except Exception as e:
        logger.critical(f"An unexpected error occurred while fetching torrents: {e}", exc_info=True)
        return {"deleted": 0, "notified_issues": 0, "system_notif_sent": False, "report_path": None}

    torrents.sort(key=lambda t: t['name'].lower())

    deleted_entries = []
    notified_entries = []
    report_file = get_unregistered_log_file_path()

    for torrent in torrents:
        torrent_hash = torrent['hash']
        torrent_name = torrent['name']
        logger.debug(f"Processing torrent: '{torrent_name}' (Hash: {torrent_hash})")

        try:
            tracker_resp = session.get(f'{qb_host}/api/v2/torrents/trackers', params={'hash': torrent_hash})
            tracker_resp.raise_for_status()
            trackers = tracker_resp.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to get trackers for '{torrent_name}': {e}")
            continue
        except Exception as e:
            logger.warning(f"An unexpected error occurred getting trackers for '{torrent_name}': {e}", exc_info=True)
            continue

        for tracker in trackers:
            if tracker.get('status') != 4:
                logger.debug(f"Tracker '{tracker.get('url', 'N/A')}' for '{torrent_name}' has status {tracker.get('status')}, skipping.")
                continue

            msg = tracker.get('msg', '').strip()
            msg_lower = msg.lower()
            tracker_url = tracker.get('url', 'N/A')

            formatted_info = (
                f"Torrent: {torrent_name}\n"
                f"Tracker: {tracker_url}\n"
                f"Status Msg: {msg}\n"
                f"{'-'*60}"
            )

            ignored_messages = [
                'tracker is down', 'timed out', 'stream truncated',
                'service unavailable', 'connection refused'
            ]

            if any(term in msg_lower for term in ignored_messages):
                logger.debug(f"Ignoring transient tracker issue for '{torrent_name}': {msg}")
                continue

            if 'unregistered torrent' in msg_lower:
                logger.warning(f"Detected 'unregistered torrent' for '{torrent_name}'. Attempting deletion.")
                if delete_torrent_by_hash(qb_host, torrent_hash, torrent_name):
                    deleted_entries.append(formatted_info)
                    deleted_count += 1
                else:
                    logger.error(f"Failed to delete '{torrent_name}', but it was marked as unregistered.")
            else:
                logger.warning(f"Detected failing tracker issue for '{torrent_name}': {msg}")
                if not system_notification_sent:
                    logger.info(f"Sending system notification for failing tracker issue (only once per run).")
                    try:
                        subprocess.run(
                            [
                                '/usr/local/emhttp/plugins/dynamix/scripts/notify',
                                '-s', 'qBittorrent Tracker Issue Detected',
                                '-d', 'A torrent was found with a failing tracker. Please check the script logs for details.',
                                '-i', 'warning'
                            ],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        logger.info(f"System notification sent successfully.")
                        system_notification_sent = True
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to run notify script: {e.stderr}")
                        notified_entries.append(f"Notification failed for '{torrent_name}': {e.stderr}")
                    except FileNotFoundError:
                        logger.error(f"Notify script '/usr/local/emhttp/plugins/dynamix/scripts/notify' not found. Is Unraid installed or path correct?")
                        notified_entries.append(f"Notification script not found for '{torrent_name}'.")
                    except Exception as e:
                        logger.error(f"An unexpected error occurred while running notify script: {e}", exc_info=True)
                        notified_entries.append(f"Notification failed for '{torrent_name}': {e}")
                else:
                    logger.debug(f"System notification already sent. Logging additional failing tracker issue for '{torrent_name}'.")
                notified_entries.append(formatted_info)
                notified_issues_count += 1

    logger.info(f"Writing report to: {report_file}")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Torrent Tracker Status Report — {datetime.now().isoformat()}\n\n")
        if deleted_entries:
            f.write("=== Deleted Torrents (unregistered) ===\n\n")
            f.write("\n".join(deleted_entries))
            f.write("\n\n")
        if notified_entries:
            f.write("=== Notified Issues (status=4, other messages) ===\n\n")
            f.write("\n".join(notified_entries))
            f.write("\n")
        if not deleted_entries and not notified_entries:
            f.write("No torrents met deletion or notification criteria.\n")
            logger.info("No torrents met deletion or notification criteria in this run.")

    logger.info("Unregistered torrent check completed.")
    return {
        "deleted": deleted_count,
        "notified_issues": notified_issues_count,
        "system_notif_sent": system_notification_sent,
        "report_path": report_file
    }


# --- Mover Script Functions ---
def strip_prefix(path, prefix):
    """Strips a given prefix from a path if it starts with that prefix."""
    norm_path = os.path.normpath(path)
    norm_prefix = os.path.normpath(prefix)

    if not norm_path.startswith(norm_prefix):
        return norm_path

    if len(norm_path) == len(norm_prefix):
        return ''

    if norm_path[len(norm_prefix)] == os.sep:
        return norm_path[len(norm_prefix) + 1:]

    return norm_path[len(norm_prefix):]


def get_all_cache_files_relative(cache_mount_path, ignore_folders):
    """
    Recursively scans the cache mount path and returns a set of all relative file paths found.
    Paths are normalized and stripped of the cache_mount_path prefix.
    Folders listed in ignore_folders will be skipped.
    """
    logger.info(f"Scanning cache mount: {cache_mount_path} and stripping prefix.")
    if ignore_folders:
        logger.info(f"Ignoring the following cache folders: {', '.join(ignore_folders)}")
        normalized_ignore_folders_with_sep = [os.path.normpath(f) + os.sep if not os.path.normpath(f).endswith(os.sep) else os.path.normpath(f) for f in ignore_folders]
    else:
        normalized_ignore_folders_with_sep = []

    cache_files_relative = set()

    normalized_cache_mount = os.path.normpath(cache_mount_path)
    if not normalized_cache_mount.endswith(os.sep):
        normalized_cache_mount += os.sep

    if not os.path.isdir(cache_mount_path):
        logger.error(f"Error: Cache mount path '{cache_mount_path}' does not exist or is not a directory.")
        return cache_files_relative

    for root, dirnames, files in os.walk(cache_mount_path):
        current_normalized_root = os.path.normpath(root)
        should_skip_root = False
        for ignored_folder_prefix in normalized_ignore_folders_with_sep:
            if current_normalized_root == ignored_folder_prefix.rstrip(os.sep) or \
               current_normalized_root.startswith(ignored_folder_prefix):
                logger.debug(f"Skipping directory '{root}' because it's in an ignored path '{ignored_folder_prefix.rstrip(os.sep)}'.")
                should_skip_root = True
                break

        if should_skip_root:
            dirnames[:] = []
            continue

        dirs_to_remove = []
        for dname in dirnames:
            full_subdir_path = os.path.normpath(os.path.join(root, dname))
            for ignored_folder_prefix in normalized_ignore_folders_with_sep:
                if full_subdir_path == ignored_folder_prefix.rstrip(os.sep) or \
                   full_subdir_path.startswith(ignored_folder_prefix):
                    logger.info(f"Skipping subdirectory '{full_subdir_path}' as it is an ignored cache folder.")
                    dirs_to_remove.append(dname)
                    break

        for d in dirs_to_remove:
            if d in dirnames:
                dirnames.remove(d)

        for file in files:
            full_path = os.path.normpath(os.path.join(root, file))
            relative_path = strip_prefix(full_path, normalized_cache_mount)
            logger.debug(f"CACHE SCAN: Full path: '{full_path}', Stripped: '{relative_path}'")
            cache_files_relative.add(relative_path)

    logger.info(f"Found {len(cache_files_relative)} relative file paths on the cache drive.")
    return cache_files_relative


def find_torrents_with_cache_files(client, torrent_list, cache_files_set_relative, user_share_mount_path):
    """
    Identifies torrents that have at least one file residing on the cache drive
    by comparing relative paths.
    """
    torrents_to_pause = []

    normalized_user_share_mount = os.path.normpath(user_share_mount_path)
    if not normalized_user_share_mount.endswith(os.sep):
        normalized_user_share_mount += os.sep

    logger.info(f"Checking {len(torrent_list)} torrents for files on cache.")

    for torrent in torrent_list:
        torrent_has_file_on_cache = False

        if not torrent.hash or not isinstance(torrent.hash, str):
            logger.debug(f"Skipping torrent '{torrent.name}' due to invalid or missing hash: {torrent.hash}")
            continue

        try:
            torrent_files_details = client.torrents_files(torrent_hash=torrent.hash)

            if not torrent_files_details:
                logger.debug(f"No file details retrieved for torrent '{torrent.name}' (hash: {torrent.hash}). Skipping torrent file check.")
                continue

            logger.debug(f"TORRENT CHECK: Processing torrent '{torrent.name}' (save_path: '{torrent.save_path}')")

            for file_detail in torrent_files_details:
                absolute_file_path = os.path.normpath(os.path.join(torrent.save_path, file_detail.name))
                relative_file_path_from_torrent = strip_prefix(absolute_file_path, normalized_user_share_mount)

                logger.debug(f"TORRENT FILE: '{file_detail.name}' -> Absolute: '{absolute_file_path}', Stripped: '{relative_file_path_from_torrent}'")

                if relative_file_path_from_torrent in cache_files_set_relative:
                    logger.info(f"MATCH FOUND: Torrent '{torrent.name}' has file '{file_detail.name}' on cache (relative path: '{relative_file_path_from_torrent}')")
                    torrent_has_file_on_cache = True
                    break

        except Exception as e:
            logger.warning(f"Failed to retrieve file details for torrent '{torrent.name}' (hash: {torrent.hash}): {e}", exc_info=True)
            continue

        if torrent_has_file_on_cache:
            torrents_to_pause.append(torrent)
            logger.debug(f"Appended torrent '{torrent.name}' (hash: {torrent.hash}) to torrents_to_pause. Current count: {len(torrents_to_pause)}")

    logger.debug(f"find_torrents_with_cache_files returning with {len(torrents_to_pause)} torrents to pause.")
    return torrents_to_pause


def stop_start_torrents(torrent_list, pause=True):
    """Pauses or resumes a list of torrents."""
    action = "Pausing" if pause else "Resuming"
    for torrent in torrent_list:
        logger.info(f"{action}: {torrent.name}")
        try:
            if pause:
                torrent.pause()
            else:
                torrent.resume()
        except Exception as e:
            logger.error(f"Failed to {action.lower()} torrent '{torrent.name}': {e}", exc_info=True)


def run_mover_task(args) -> dict:
    """
    Executes the Unraid mover process.
    Returns a dictionary of mover execution statistics.
    """
    logger.info("Starting mover script operations.")
    mover_status = "Skipped"
    # Removed mover_output_stdout as per user request
    mover_output_stderr = ""
    paused_torrents_count = 0

    # Step 1: Build the database of all files on the cache drive (relative paths), now respecting ignore list
    all_cache_files_relative = get_all_cache_files_relative(args.cache_mount, args.ignore_cache_folders_list)
    if not all_cache_files_relative:
        logger.warning("No files found on the cache drive (or all relevant paths were ignored). Skipping mover operation.")
        return {
            "status": mover_status,
            # Removed "output_stdout": mover_output_stdout,
            "output_stderr": mover_output_stderr,
            "paused_count": paused_torrents_count
        }

    # Connect to qBittorrent API for mover part
    # We attempt connection here even if the first login succeeded, because this is a new Client instance.
    try:
        qb_client = Client(host=args.host, username=args.user, password=args.password)
        qb_client.auth_log_in()
        logger.info("Successfully connected to qBittorrent API for mover operations.")
    except LoginFailed:
        logger.error("Qbittorrent Error: Failed to login for mover. Invalid username/password.", exc_info=True)
        mover_status = "Login Failed"
        return {
            "status": mover_status,
            # Removed "output_stdout": mover_output_stdout,
            "output_stderr": mover_output_stderr,
            "paused_count": paused_torrents_count
        }
    except APIConnectionError as e:
        logger.error(f"Qbittorrent Error: Unable to connect to the client at {args.host} for mover: {e}", exc_info=True)
        mover_status = "Connection Failed"
        return {
            "status": mover_status,
            # Removed "output_stdout": mover_output_stdout,
            "output_stderr": mover_output_stderr,
            "paused_count": paused_torrents_count
        }
    except Exception as e:
        logger.error(f"An unexpected error occurred during qBittorrent connection for mover: {e}", exc_info=True)
        mover_status = "Connection Error"
        return {
            "status": mover_status,
            # Removed "output_stdout": mover_output_stdout,
            "output_stderr": mover_output_stderr,
            "paused_count": paused_torrents_count
        }


    # Step 2: Get torrents from qBittorrent based on status filter
    status_filters_list = [s.strip() for s in args.status_filter.split(',') if s.strip()]

    initial_torrent_list = []
    if "all" in [s.lower() for s in status_filters_list]:
        logger.info("Fetching all torrents from qBittorrent (status filter 'all' specified).")
        initial_torrent_list = qb_client.torrents.info()
    else:
        status_filter_string = ",".join(status_filters_list)
        logger.info(f"Fetching torrents with statuses: '{status_filter_string}'")
        initial_torrent_list = qb_client.torrents.info(status_filter=status_filter_string)

    logger.info(f"Found {len(initial_torrent_list)} torrents matching status filter(s) and will be checked against cache files.")

    # Step 3: Find torrents that have files on the cache drive using relative paths
    torrents_to_pause = find_torrents_with_cache_files(qb_client, initial_torrent_list, all_cache_files_relative, args.user_share_mount)

    logger.debug(f"Main function received {len(torrents_to_pause)} torrents to pause from find_torrents_with_cache_files.")

    if not torrents_to_pause:
        logger.info("No torrents found with files on the cache drive. Nothing to pause or move.")
        mover_status = "No Torrents to Move"
        return {
            "status": mover_status,
            # Removed "output_stdout": mover_output_stdout,
            "output_stderr": mover_output_stderr,
            "paused_count": paused_torrents_count
        }

    # Step 4: Pause identified torrents
    paused_torrents_count = len(torrents_to_pause)
    logger.info(f"Pausing [{paused_torrents_count}] torrents with files on the cache drive.")
    stop_start_torrents(torrents_to_pause, True)
    time.sleep(5)

    # Step 5: Start Unraid mover
    mover_command = "/usr/local/sbin/mover" # Always use the default mover command
    logger.info(f"Starting mover using command: {mover_command} start")
    try:
        mover_process = subprocess.run([mover_command, "start"], check=True, capture_output=True, text=True)
        # Removed mover_output_stdout assignment
        mover_output_stderr = mover_process.stderr.strip()

        # Removed stdout logging
        if mover_output_stderr:
            logger.warning(f"Mover output (stderr):\n{mover_output_stderr}")
        
        mover_status = "Success"
        logger.info("Mover has finished its operation.")
    except subprocess.CalledProcessError as e:
        # Removed mover_output_stdout assignment
        mover_output_stderr = e.stderr.strip()
        mover_status = f"Failed (Exit Code: {e.returncode})"
        logger.error(f"Mover command failed with exit code {e.returncode}:")
        # Removed stdout error logging
        if mover_output_stderr:
            logger.error(f"Mover output (stderr):\n{mover_output_stderr}")
        logger.critical("Mover failed to run. Torrents will still be resumed.")
    except FileNotFoundError:
        mover_status = "Mover Not Found"
        logger.error(f"Mover command '{mover_command}' not found. Is Unraid installed or path correct?")
        logger.critical("Mover command not found. Torrents will still be resumed.")
    except Exception as e:
        mover_status = "Mover Error"
        logger.error(f"An unexpected error occurred while running the mover: {e}", exc_info=True)
        logger.critical("An unexpected error occurred during mover execution. Torrents will still be resumed.")


    # Step 6: Resume paused torrents
    logger.info(f"Resuming [{paused_torrents_count}] torrents that were paused for cache movement.")
    stop_start_torrents(torrents_to_pause, False)
    logger.info("Mover script operations completed.")
    
    return {
        "status": mover_status,
        # Removed "output_stdout": mover_output_stdout,
        "output_stderr": mover_output_stderr,
        "paused_count": paused_torrents_count
    }


if __name__ == "__main__":
    script_start_time = datetime.now() # Capture script start time

    parser = argparse.ArgumentParser(
        prog="Qbit Automation",
        description="First removes unregistered torrents, then pauses torrents with files on cache, runs Unraid mover, and resumes. Handles FUSE paths."
    )
    parser.add_argument("--host", help="qbittorrent host including port", default=DEFAULT_QB_HOST)
    parser.add_argument("-u", "--user", help="qbittorrent user", default=DEFAULT_QB_USER)
    parser.add_argument("-p", "--password", help="qbittorrent password", default=DEFAULT_QB_PASSWORD)
    parser.add_argument(
        "--cache-mount",
        help="Cache mount point in Unraid (e.g., /mnt/cache). Used to scan for files. This path will be stripped.",
        required=True,
    )
    parser.add_argument(
        "--user-share-mount",
        help="User share mount point in Unraid (e.g., /mnt/user). This path will be stripped from torrent file paths for comparison.",
        required=True,
    )
    parser.add_argument(
        "--status-filter",
        help="Define a comma-separated list of statuses to limit which torrents to check for cache files."
             " E.g., 'downloading,seeding,completed'. Use 'all' to check all torrents.",
        default="uploading, queuedUP, stalledUP, stalledDL, completed",
    )
    parser.add_argument(
        "--ignore-cache-folders",
        help="Comma-separated list of absolute paths on the cache drive to ignore during scanning. "
             "E.g., '/mnt/cache/appdata,/mnt/cache/system'",
        default="",
    )
    parser.add_argument(
        "--discord-webhook-url",
        help=f"Discord webhook URL for notifications (overrides default from .env or hardcoded: {DISCORD_WEBHOOK_URL}).",
        default=DISCORD_WEBHOOK_URL,
    )

    args = parser.parse_args()

    # Prepend http:// if missing from the host argument
    if not args.host.startswith('http://') and not args.host.startswith('https://'):
        logger.info(f"Adding 'http://' to host as no schema was specified: {args.host}")
        args.host = f'http://{args.host}'

    # Process ignore_cache_folders argument for mover part
    args.ignore_cache_folders_list = []
    if args.ignore_cache_folders:
        args.ignore_cache_folders_list = [f.strip() for f in args.ignore_cache_folders.split(',') if f.strip()]

    # --- Main Script Execution Flow ---
    cleanup_old_logs() # Clean up logs at the start of each run

    # Send script started notification
    if args.discord_webhook_url:
        send_discord_notification_embed(
            webhook_url=args.discord_webhook_url,
            title="qBittorrent Unraid Automation Script Started",
            description=f"Script execution commenced at: {script_start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            color=0x3498DB # Blue color for informational start
        )

    overall_status_message = ""
    notification_color = 0x00FF00 # Green for success

    # 1. Run the unregistered torrent removal part first
    logger.info("--- Starting Unregistered Torrent Removal ---")
    
    # Attempt login for the first task
    logged_in_for_unregistered_check = False
    try:
        logged_in_for_unregistered_check = login_qbittorrent(args.host, args.user, args.password)
        if logged_in_for_unregistered_check:
            unregistered_summary = find_and_delete_unregistered_torrents_task(args.host, args.discord_webhook_url)
            overall_status_message += (
                f"**Unregistered Torrent Removal:**\n"
                f"- Deleted: {unregistered_summary['deleted']} torrents\n"
                f"- Other Tracker Issues: {unregistered_summary['notified_issues']} torrents\n"
            )
            if unregistered_summary["deleted"] > 0 or unregistered_summary["notified_issues"] > 0:
                if notification_color != 0xFF0000: # Don't override a critical error red
                    notification_color = 0xFFA500 # Orange for warnings/minor issues
        else:
            overall_status_message += "**Unregistered Torrent Removal:** Skipped due to qBittorrent login failure. Please check qBittorrent credentials or connectivity.\n"
            notification_color = 0xFF0000 # Red for critical errors (login failure)
            # No need to call find_and_delete_unregistered_torrents_task if login failed
    except Exception as e:
        logger.critical(f"Critical error during unregistered torrent removal: {e}", exc_info=True)
        overall_status_message += f"**Unregistered Torrent Removal:** Failed with critical error: {e}\n"
        notification_color = 0xFF0000 # Red for critical errors
    finally:
        # Only try to logout if we successfully logged in
        # This is already handled inside login_qbittorrent by session.post and session.get
        # The session.get(f'{host}/api/v2/auth/logout') is called in logout_qbittorrent which logs out the requests session
        pass
    logger.info("--- Finished Unregistered Torrent Removal ---")
    
    # Add a small delay between the two main operations if desired, e.g., to allow qBittorrent to settle
    time.sleep(10) 

    # 2. Run the mover script part ONLY IF the initial login was successful
    if logged_in_for_unregistered_check:
        logger.info("--- Starting qBittorrent Mover ---")
        mover_summary = {}
        try:
            mover_summary = run_mover_task(args)
            overall_status_message += (
                f"\n**Unraid Mover:**\n"
                f"- Status: {mover_summary['status']}\n"
                f"- Paused Torrents: {mover_summary['paused_count']}\n"
            )
            if mover_summary['status'] not in ["Success", "No Torrents to Move", "Skipped"]:
                notification_color = 0xFF0000 # Red if mover failed or had issues
            elif mover_summary['status'] == "Success" and notification_color != 0xFF0000:
                # Keep original color if it was orange from torrent removal, otherwise set green
                if mover_summary['paused_count'] > 0:
                    notification_color = 0x00FF00
                elif unregistered_summary["deleted"] == 0 and unregistered_summary["notified_issues"] == 0:
                    notification_color = 0x00FF00 # All good, green

            if mover_summary['output_stderr']:
                overall_status_message += f"**Mover Output (stderr):**\n```\n{mover_summary['output_stderr'][:1000]}...\n```\n"

        except Exception as e:
            logger.critical(f"Critical error during qBittorrent Mover process: {e}", exc_info=True)
            overall_status_message += f"**Unraid Mover:** Failed with critical error: {e}\n"
            notification_color = 0xFF0000 # Red for critical errors
        logger.info("--- Finished qBittorrent Mover ---")
    else:
        logger.info("--- Skipping qBittorrent Mover due to prior login failure ---")
        overall_status_message += "\n**Unraid Mover:** Skipped due to previous qBittorrent login failure.\n"


    logger.info("All automation tasks completed.")

    # Send final Discord notification with aggregated summary
    if args.discord_webhook_url:
        embed_title = "qBittorrent Unraid Automation Report"
        send_discord_notification_embed(
            webhook_url=args.discord_webhook_url,
            title=embed_title,
            description=overall_status_message,
            color=notification_color,
            log_file_path=current_script_log_file_path # Attach the main script log
        )
    else:
        logger.info("No Discord webhook URL provided. Skipping final Discord notification.")

    script_end_time = datetime.now() # Capture script end time
    script_duration = script_end_time - script_start_time

    # Send script finished notification
    if args.discord_webhook_url:
        send_discord_notification_embed(
            webhook_url=args.discord_webhook_url,
            title="qBittorrent Unraid Automation Script Finished",
            description=(
                f"Script execution completed at: {script_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Duration: {script_duration}"
            ),
            color=0x3498DB # Blue color for informational end
        )
