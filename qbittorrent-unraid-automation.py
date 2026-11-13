#!/usr/bin/env python3
"""Run tracker auditing, confirmed pruning, or cache-aware Unraid Mover."""

import json
import math
import os
import subprocess
import time

from qbt_common import (LOG, OperationError, WebAPI, install_signal_handler, notify_http,
                        run_lock, setup_logs, setup_parser)
from qbt_mover import run_mover
from qbt_prune import scan


def parse_args():
    parser = setup_parser(__doc__)
    parser.add_argument("mode", nargs="?", default="audit", choices=("audit", "prune", "mover"))
    parser.add_argument("--apply", action="store_true", help="Apply confirmed removals in prune mode.")
    parser.add_argument("--delete-files", action="store_true", help="Also delete payloads. Requires prune --apply.")
    parser.add_argument("--confirmation-hours", type=float, default=1.0,
                        help="Minimum separation between qualifying scans, in hours. Default: 1.")
    parser.add_argument("--cache-mount", action="append", default=[],
                        help="Mounted Unraid pool to scan. Repeat for multiple relevant pools.")
    parser.add_argument("--user-share-mount", default="/mnt/user", help="Host Unraid user-share root.")
    parser.add_argument("--qb-path-map", action="append", default=[],
                        help="Repeatable CONTAINER_PATH=HOST_PATH translation.")
    parser.add_argument("--ignore-cache-folders", default="", help="Comma-separated host pool directories to skip.")
    parser.add_argument("--status-filter", default="all", help="Comma-separated torrent states or groups, applied locally.")
    parser.add_argument("--mover-command", default="/usr/local/sbin/mover", help="Path to the installed Mover executable.")
    parser.add_argument("--mover-status-command", help="Optional executable that exits 0 for idle or 1 for active.")
    parser.add_argument("--mover-timeout", type=int, default=21600, help="Seconds allowed per launch or idle wait.")
    parser.add_argument("--state-timeout", type=int, default=60, help="Seconds to wait for qBittorrent state changes.")
    mover_options = parser.add_mutually_exclusive_group()
    mover_options.add_argument("--dry-run", action="store_true", help="Report the Mover plan without starting it.")
    mover_options.add_argument("--recover", action="store_true", help="Restore torrents from a previous interrupted Mover run.")
    parser.add_argument("--discord-webhook-url", default=os.getenv("DISCORD_WEBHOOK_URL"),
                        help="Override the configured Discord webhook.")
    parser.add_argument("--healthchecks-url", default=os.getenv("HEALTHCHECKS_URL"),
                        help="Override the configured Healthchecks ping URL.")
    args = parser.parse_args()
    if (args.apply and args.mode != "prune") or (args.delete_files and not args.apply):
        parser.error("--apply requires prune, and --delete-files requires prune --apply.")
    if not math.isfinite(args.confirmation_hours) or not 0 < args.confirmation_hours < 168:
        parser.error("--confirmation-hours must be greater than 0 and less than 168.")
    if args.mode == "mover":
        if not args.recover and not args.cache_mount:
            parser.error("mover requires at least one --cache-mount.")
        if args.state_timeout < 1 or args.mover_timeout < 5:
            parser.error("Mover and torrent state timeouts must be at least 5 and 1 seconds respectively.")
    elif args.cache_mount or args.dry_run or args.recover or args.qb_path_map:
        parser.error("Specify the mover mode before using Mover options.")
    return args


def discord(args, title, description, color, log_path=None):
    if not args.discord_webhook_url:
        return
    payload = {"embeds": [{"title": title, "description": description, "color": color}],
               "allowed_mentions": {"parse": []}}
    if log_path and os.getenv("DISCORD_ATTACH_LOG", "").casefold() == "true":
        try:
            with log_path.open("rb") as stream:
                notify_http("POST", args.discord_webhook_url, "Discord",
                            data={"payload_json": json.dumps(payload)},
                            files={"files[0]": (log_path.name, stream, "text/plain")})
            return
        except OSError:
            LOG.warning("Could not open the log for Discord.")
    notify_http("POST", args.discord_webhook_url, "Discord", json=payload)


def main():
    args = parse_args()
    install_signal_handler()
    log_path = setup_logs(args.mode, (args.password, args.discord_webhook_url, args.healthchecks_url))
    try:
        with run_lock(args.state_dir):
            started = time.monotonic()
            health = (args.healthchecks_url or "").rstrip("/")
            if health:
                notify_http("GET", health + "/start", "Healthchecks start")
            discord(args, f"qBittorrent {args.mode} started", "Maintenance job started.", 0x3498DB)
            code = 1
            summary = "Maintenance job failed. Review the local log."
            try:
                if args.apply and (args.state_dir / "mover-recovery.json").exists():
                    raise OperationError("Complete pending Mover recovery before applying pruning.")
                with WebAPI(args) as api:
                    summary = run_mover(api, args) if args.mode == "mover" else scan(api, args)
                LOG.info("%s", summary)
                code = 0
            except KeyboardInterrupt:
                LOG.error("Job interrupted.")
                code = 130
            except OperationError as exc:
                LOG.error("%s", exc)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                LOG.error("Job failed (%s).", type(exc).__name__)
            finally:
                if health:
                    notify_http("GET", health + ("/fail" if code else ""), "Healthchecks result")
                discord(args, f"qBittorrent {args.mode} finished",
                        f"{summary}\nDuration: {time.monotonic() - started:.1f} s.",
                        0xFF0000 if code else 0x00AA55, log_path)
            return code
    except OperationError as exc:
        # A duplicate invocation must not overwrite the active run's health signal.
        LOG.error("%s", exc)
        return 1
    except OSError as exc:
        LOG.error("Could not access the job state (%s).", type(exc).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
