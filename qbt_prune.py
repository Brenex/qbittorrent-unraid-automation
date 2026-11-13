"""Audit tracker failures and optionally remove confirmed torrents."""

import hashlib
import json
import math
import os
import re
import subprocess
import time

from qbt_common import LOG, OperationError, read_state, tracker_host, write_state

EXPIRY = 7 * 86400
NOTIFY = "/usr/local/emhttp/plugins/dynamix/scripts/notify"
PSEUDO_TRACKERS = {"** [DHT] **", "** [PeX] **", "** [LSD] **"}


def rejection_rules():
    try:
        rules = json.loads(os.getenv("TRACKER_REJECTIONS_JSON", "{}"))
        if not isinstance(rules, dict):
            raise ValueError
        for host, messages in rules.items():
            if (not re.fullmatch(r"[a-z0-9.-]+", host) or not isinstance(messages, list)
                    or not messages or any(not isinstance(m, str) or not m.strip() for m in messages)):
                raise ValueError
        return {host: {m.strip().casefold() for m in messages} for host, messages in rules.items()}
    except ValueError:
        raise OperationError("TRACKER_REJECTIONS_JSON must map lowercase tracker hostnames to lists of exact messages.") from None


def classify(trackers, rules):
    """Return a fingerprint only when every real tracker explicitly rejects the torrent."""
    evidence = set()
    failures = set()
    eligible = True
    for row in trackers:
        url = row.get("url")
        if isinstance(url, str) and url in PSEUDO_TRACKERS:
            continue
        if not isinstance(url, str) or not (host := tracker_host(url)):
            raise OperationError("qBittorrent returned an invalid tracker URL.")
        status = row.get("status")
        message = row.get("msg")
        if type(status) is not int or not isinstance(message, str):
            raise OperationError("qBittorrent returned incomplete tracker status data.")
        if status in (4, 5, 6):
            failures.add((host, status))
        message = message.strip().casefold()
        accepted = rules.get(host, set())
        endpoints = row.get("endpoints", [])
        # Some qBittorrent versions expose the underlying announces separately.
        if not isinstance(endpoints, list) or any(not isinstance(e, dict) for e in endpoints):
            raise OperationError("qBittorrent returned invalid tracker endpoint data.")
        if (status not in (4, 5) or row.get("updating") is True or message not in accepted
                or any(e.get("status") not in (4, 5) or e.get("updating") is not False
                       or not isinstance(e.get("msg"), str)
                       or e["msg"].strip().casefold() not in accepted for e in endpoints)):
            eligible = False
        else:
            evidence.add((url, message))
    fingerprint = None
    if eligible and evidence:
        fingerprint = hashlib.sha256(json.dumps(sorted(evidence)).encode()).hexdigest()
    return fingerprint, failures


def notify_tracker_issues(count):
    try:
        subprocess.run([NOTIFY, "-s", "qBittorrent tracker issues",
                        "-d", f"{count} torrent(s) reported tracker errors. Review the automation log.",
                        "-i", "warning"], check=True, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        LOG.warning("Unraid notification failed (%s).", type(exc).__name__)


def scan(api, args):
    rules = rejection_rules()
    if args.apply and not rules:
        raise OperationError("Configure TRACKER_REJECTIONS_JSON before applying pruning.")
    path = args.state_dir / "tracker-observations.json"
    stored = read_state(path, {})
    if not isinstance(stored, dict):
        raise OperationError("Invalid tracker-observations.json. Inspect it before continuing.")
    previous = stored.get("observations", {}) if stored.get("client") == api.base else {}
    if not isinstance(previous, dict):
        raise OperationError("Invalid tracker observations. Inspect the state file.")
    now = time.time()
    observations = {}
    candidates = {}
    issues = 0
    try:
        for key, torrent in sorted(api.torrents().items(), key=lambda pair: str(pair[1].get("name", "")).casefold()):
            name = torrent.get("name", key)
            fingerprint, failures = classify(api.trackers(key), rules)
            if failures:
                issues += 1
                for host, status in sorted(failures):
                    LOG.warning("%s [%s] tracker %s status %s", name, key, host, status)
            if not fingerprint:
                continue
            old = previous.get(key, {})
            first = old.get("first_seen") if isinstance(old, dict) else None
            if (not isinstance(old, dict) or old.get("fingerprint") != fingerprint
                    or type(first) not in (int, float) or not math.isfinite(first)
                    or not 0 <= now - first <= EXPIRY):
                first = now
            observations[key] = {"first_seen": first, "fingerprint": fingerprint}
            if now - first >= args.confirmation_hours * 3600:
                candidates[key] = (name, fingerprint)
                LOG.info("Confirmed rejection for %s [%s].", name, key)
            else:
                LOG.info("Recorded rejection for %s [%s]. Waiting for repeat observation.", name, key)
    except (Exception, KeyboardInterrupt):
        # A failed scan must never qualify as consecutive evidence.
        write_state(path, {"client": api.base, "observations": {}})
        raise

    def persist():
        write_state(path, {"client": api.base, "observations": observations})

    persist()
    if issues:
        notify_tracker_issues(issues)

    removed = 0
    if args.apply:
        for key, (name, fingerprint) in candidates.items():
            # Consume the confirmation before mutation so a timeout cannot cause
            # the next run to retry a deletion from the same observations.
            del observations[key]
            persist()
            latest, _ = classify(api.trackers(key), rules)
            if latest != fingerprint:
                LOG.warning("Skipping %s [%s] because its tracker evidence changed.", name, key)
                continue
            api.mutate("delete", hashes=key, deleteFiles=str(args.delete_files).lower())
            deadline = time.monotonic() + 15
            while api.torrents((key,)):
                if time.monotonic() >= deadline:
                    raise OperationError(f"Removal of {key} could not be verified.")
                time.sleep(1)
            removed += 1
            LOG.info("Removed %s [%s], payload deletion requested=%s.", name, key, args.delete_files)
    return f"{issues} torrent(s) with tracker issues, {len(candidates)} confirmed, {removed} removed."
