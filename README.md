# qBittorrent and Unraid maintenance

Run the Python scripts on the **Unraid host**, where they can see the mounted pools and invoke the installed Mover. qBittorrent can stay in its existing Docker container. The scripts communicate with its WebUI over HTTP(S).

## Install

Extract this package into a new directory. Keep all its Python files together. Use Python 3.10 or later on Linux.

```bash
cd /mnt/user/scripts/qbittorrent-unraid-automation
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
(umask 077 && cp -n .env.example .env)
chmod 600 .env
```

Set `QB_HOST`, `QB_USER`, and `QB_PASSWORD` in `.env`. The scripts load the file relative to their own location. Environment variables already set by a scheduled job take precedence. Use the full interpreter and script paths in Unraid User Scripts so the working directory does not matter. If you reuse the previous installation directory, review old log and report files for credentials, and remove the old credential-bearing `remove.py` from the deployment. Rotate the previously embedded password and tracker passkey if they were live.

## Audit and prune

```bash
.venv/bin/python qbittorrent-unraid-automation.py audit
.venv/bin/python qbittorrent-unraid-automation.py prune
.venv/bin/python qbittorrent-unraid-automation.py prune --apply
```

- `audit` is the default. It reports tracker issues and records observations locally. `prune` without `--apply` previews the confirmed candidates. Both may send notifications if configured.
- Before pruning, set `TRACKER_REJECTIONS_JSON` in `.env` using the actual tracker hostname and exact torrent-level rejection messages. Matching ignores case and outer whitespace. Confirm that each configured phrase means **the torrent hash is unregistered** on that tracker. Account, passkey, timeout, and generic server errors are unsuitable. The example is intentionally inactive.
- Every real tracker must explicitly reject the torrent. A healthy, unknown, unreachable, updating, or unconfigured tracker blocks removal. A failed scan clears its accumulated evidence. The same evidence must be observed on separate successful runs at least one hour apart by default, with a seven-day maximum history. qBittorrent may return cached tracker status. Use `--confirmation-hours` to set an interval longer than the normal announce interval if needed.
- `prune --apply` rechecks each candidate immediately before removing its torrent entry. Add `--delete-files` only when you also want qBittorrent to delete the download payload. If another torrent or application references the exact same pathname, that reference may lose access to the file. Payload deletion is delegated to qBittorrent.
- A failed or ambiguous deletion exits with an error. An attempted candidate must build fresh confirmation history before automatic removal can be tried again.

## Mover

Preview first. The example assumes Docker maps host `/mnt/user/data` to container `/data`, and the relevant pool is mounted at `/mnt/cache`.

```bash
.venv/bin/python qbittorrent-unraid-automation.py mover --dry-run \
  --cache-mount /mnt/cache --qb-path-map /data=/mnt/user/data

.venv/bin/python qbittorrent-unraid-automation.py mover \
  --cache-mount /mnt/cache --qb-path-map /data=/mnt/user/data
```

- Substitute your actual Docker bind mount. Repeat `--qb-path-map` for additional mappings. If qBittorrent already reports `/mnt/user/…` paths, omit that mapping. Repeat `--cache-mount` for every mounted pool Mover may access for qBittorrent shares. If qBittorrent uses a different location for incomplete downloads, map that path too.
- The script looks up each running torrent's files, checks for corresponding files on the configured pools, and stops matching torrents. It verifies the stopped state before launching Mover, then verifies that Mover is idle before restoring the torrents it stopped. Already-stopped torrents are left alone. `--status-filter` is applied locally and defaults to `all`. A matching cache torrent outside a narrower filter blocks the run. `--ignore-cache-folders` affects the torrent scan only. Mover follows the share settings in Unraid.
- The default uses `/usr/local/sbin/mover status` and `/usr/local/sbin/mover start`. Run the dry run to verify the installed Mover's status interface. If your release or plugin reports status differently, supply `--mover-status-command /absolute/path/to/helper`. The executable must return **0** for idle, **1** for active, and **2 or higher** if it cannot tell. It must cover the actual move, including any background workers. If needed, set `--mover-command` to a compatible executable that accepts `start`. The script exits before launching if the preflight status is unrecognized.
- Schedule this as the sole Mover launcher for the relevant pools, and avoid simultaneous manual changes to torrent state. The lock coordinates these scripts when they share the same `--state-dir`. It cannot lock Unraid's own scheduler, the qBittorrent UI, or another deployment with a different state directory. Other applications can still hold files open. Mover completion indicates that the command finished and the mover is idle. Check Unraid's system log to determine which files moved.
- If the job is interrupted or cannot verify completion, check Unraid and run recovery. It uses the same status command and state directory as the original run.

```bash
.venv/bin/python qbittorrent-unraid-automation.py mover --recover
```

The recovery record survives a killed process. Keep the state directory on persistent storage. If a timeout or external interruption left the Mover status unclear, verify the actual Mover has stopped before running recovery.

## Scheduling and notifications

- Run audit and Mover as separate jobs. Use separate Healthchecks ping URLs via each job's environment or `--healthchecks-url`. An unsuccessful operation exits nonzero and sends `/fail` when configured. A duplicate invocation exits nonzero without replacing the running job's health signal. A notification delivery failure is logged separately.
- Logs are retained for seven days under `logs/`. Tracker failure reports contain torrent names, tracker hostnames, and status codes. Discord attachments are off by default. Set `DISCORD_ATTACH_LOG=true` to include the sanitized log in the final notification. The attachment still includes torrent names.
- Set `DISCORD_WEBHOOK_URL` for optional start and result messages. Tracker scan warnings also generate at most one Unraid notification per run.

## References

- [qBittorrent WebUI API](https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-5.0))
- [qBittorrent Web API changelog](https://github.com/qbittorrent/qBittorrent/blob/master/WebAPI_Changelog.md)
- [Unraid cache pools and Mover](https://docs.unraid.net/unraid-os/using-unraid-to/manage-storage/cache-pools/)
