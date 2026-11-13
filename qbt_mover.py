"""Coordinate torrent state with the Unraid host's Mover."""

from pathlib import Path, PurePosixPath
import os
import stat
import subprocess
import time

from qbt_common import HASH, LOG, OperationError, read_state, write_state

STOPPED = {"pausedUP", "pausedDL", "stoppedUP", "stoppedDL"}
FORCED = {"forcedUP", "forcedDL", "forcedMetaDL"}
AMBIGUOUS = {"error", "missingFiles"}
STATE_GROUPS = {
    "completed": {"uploading", "stalledUP", "queuedUP", "forcedUP", "checkingUP"},
    "seeding": {"uploading", "stalledUP", "queuedUP", "forcedUP"},
    "downloading": {"downloading", "stalledDL", "queuedDL", "forcedDL", "metaDL", "forcedMetaDL"},
}


def absolute(value):
    if not isinstance(value, (str, Path)):
        raise OperationError("Expected an absolute filesystem path.")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise OperationError("Expected an absolute filesystem path without parent traversal.")
    return path


def relative_share(path, share, mappings, pools):
    path = absolute(path)
    for source, destination in mappings:
        if path.is_relative_to(source):
            path = destination / path.relative_to(source)
            break
    for root in (share, *pools):
        if path.is_relative_to(root):
            return path.relative_to(root)
    raise OperationError("A qBittorrent path could not be mapped. Check --qb-path-map.")


def cache_match(pool, relative, ignored):
    path = pool / relative
    if any(path.is_relative_to(folder) for folder in ignored):
        return False
    for candidate in (path, path.with_name(path.name + ".!qB")):
        try:
            # Reject symlinked payloads and parents rather than inspecting a
            # different filesystem than the configured cache pool.
            resolved = candidate.resolve(strict=True)
            if resolved != candidate or not stat.S_ISREG(resolved.stat().st_mode):
                raise OperationError("Unexpected symlink or non-regular file on a cache payload path.")
            return True
        except (FileNotFoundError, NotADirectoryError):
            continue
    return False


def uses_final_location(torrent):
    progress = torrent.get("progress")
    remaining = torrent.get("amount_left")
    if (type(progress) not in (int, float) or progress != 1
            or type(remaining) is not int or remaining != 0):
        return False
    try:
        save_path = absolute(torrent.get("save_path"))
        content_path = absolute(torrent.get("content_path"))
    except OperationError:
        return False
    return content_path != save_path and content_path.is_relative_to(save_path)


def torrent_paths(api, key, torrent, share, mappings, pools, temp_path):
    files = api.list("torrents/files", hash=key)
    bases = {relative_share(torrent.get("save_path"), share, mappings, pools)}
    if not uses_final_location(torrent):
        temporary = torrent.get("download_path", temp_path)
        if temporary:
            bases.add(relative_share(temporary, share, mappings, pools))
    if not files:
        raise OperationError(f"Cannot establish file locations for torrent {key}.")
    for row in files:
        name = row.get("name")
        if not isinstance(name, str) or "\x00" in name:
            raise OperationError(f"Invalid file name for torrent {key}.")
        file_path = PurePosixPath(name)
        if file_path.is_absolute() or ".." in file_path.parts or not file_path.parts:
            raise OperationError(f"Invalid relative file path for torrent {key}.")
        for base in bases:
            yield base / file_path


def mover_plan(api, args):
    pools = tuple(absolute(p) for p in args.cache_mount)
    for pool in pools:
        if pool.is_symlink() or not os.path.ismount(pool):
            raise OperationError(f"Cache pool is not mounted: {pool}")
    share = absolute(args.user_share_mount)
    if not share.is_dir():
        raise OperationError(f"User share mount is unavailable: {share}")
    ignored = tuple(absolute(p.strip()) for p in args.ignore_cache_folders.split(",") if p.strip())
    if any(not any(folder.is_relative_to(pool) for pool in pools) for folder in ignored):
        raise OperationError("Ignored cache folders must be inside a configured pool.")
    mappings = []
    for mapping in args.qb_path_map:
        source, separator, destination = mapping.partition("=")
        if not separator:
            raise OperationError("--qb-path-map expects CONTAINER_PATH=HOST_PATH.")
        entry = absolute(source), absolute(destination)
        if any(existing[0] == entry[0] for existing in mappings):
            raise OperationError("Duplicate --qb-path-map source.")
        mappings.append(entry)
    mappings.sort(key=lambda item: -len(item[0].parts))
    filters = set()
    for value in args.status_filter.split(","):
        value = value.strip()
        filters.update(STATE_GROUPS.get(value, {value}))

    planned = []
    torrents = api.torrents()
    temp_path = None
    if any("download_path" not in row and row.get("state") not in STOPPED
           and not uses_final_location(row) for row in torrents.values()):
        preferences = api.get_json("app/preferences")
        if not isinstance(preferences, dict) or type(preferences.get("temp_path_enabled")) is not bool:
            raise OperationError("Could not determine the qBittorrent incomplete-download path settings.")
        if preferences["temp_path_enabled"]:
            temp_path = absolute(preferences.get("temp_path"))
    for key, torrent in torrents.items():
        state = torrent_state(torrent, key)
        if state in STOPPED:
            continue
        if state == "moving":
            raise OperationError(f"Torrent {key} is already moving inside qBittorrent.")
        paths = torrent_paths(api, key, torrent, share, mappings, pools, temp_path)
        if any(cache_match(pool, path, ignored) for path in paths for pool in pools):
            if state in AMBIGUOUS:
                raise OperationError(f"Cache torrent {key} is in an error state. Inspect it before running Mover.")
            if "all" not in filters and state not in filters:
                raise OperationError(f"Cache torrent {key} is excluded by --status-filter. Aborting Mover.")
            LOG.info("Cache match: %s [%s].", torrent.get("name", key), key)
            planned.append(key)
    return planned


def torrent_state(torrent, key):
    state = torrent.get("state")
    if not isinstance(state, str) or state in ("", "unknown"):
        raise OperationError(f"Torrent {key} has no recognized state.")
    return state


def mover_busy(args):
    cmd = [args.mover_status_command] if args.mover_status_command else [args.mover_command, "status"]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=15)
    if args.mover_status_command and result.returncode in (0, 1):
        return result.returncode == 1
    if not args.mover_status_command and result.returncode in (0, 1):
        status = (result.stdout + "\n" + result.stderr).strip().casefold()
        if status in {"mover: not running", "mover is not running", "mover: idle"}:
            return False
        if status in {"mover: running", "mover: is running", "mover: already running", "mover is running"}:
            return True
    raise OperationError("Mover status is unrecognized. Check the installed command or configure a status helper.")


def wait_idle(args):
    deadline = time.monotonic() + args.mover_timeout
    idle_since = None
    while time.monotonic() < deadline:
        now = time.monotonic()
        if mover_busy(args):
            idle_since = None
        elif idle_since is None:
            idle_since = now
        elif now - idle_since >= 3:
            return
        time.sleep(1)
    raise OperationError("Mover did not reach verified idle before the deadline.")


def wait_states(api, keys, predicate, timeout):
    deadline = time.monotonic() + timeout
    while True:
        current = api.torrents(keys)
        if current.keys() == set(keys) and all(predicate(key, torrent_state(row, key)) for key, row in current.items()):
            return
        if time.monotonic() >= deadline:
            raise OperationError("Could not verify the requested qBittorrent state before the deadline.")
        time.sleep(1)


def recover(api, args, path, journal, pending=()):
    if mover_busy(args):
        raise OperationError("Mover is active. Torrents will stay stopped until recovery can verify idle.")
    entries = journal["torrents"]
    if not entries:
        path.unlink(missing_ok=True)
        return
    current = api.torrents(tuple(entries))
    failed = []
    for key, force in list(entries.items()):
        try:
            state = torrent_state(current[key], key) if key in current else None
            if state is not None and state not in STOPPED and key in pending:
                failed.append(key)
                continue
            if state in STOPPED:
                api.start(key, force)
                wait_states(api, (key,), lambda _, state: state not in STOPPED and
                            (not force or state in FORCED), args.state_timeout)
                LOG.info("Restored %s.", key)
            del entries[key]
            write_state(path, journal)
        except OperationError as exc:
            failed.append(key)
            LOG.error("Could not restore %s: %s", key, exc)
    if failed:
        raise OperationError(f"Recovery incomplete for {len(failed)} torrent(s). Retry mover --recover.")
    path.unlink(missing_ok=True)


def run_mover(api, args):
    path = args.state_dir / "mover-recovery.json"
    old = read_state(path, None)
    if old is not None:
        if (not isinstance(old, dict) or old.get("client") != api.base
                or not isinstance(old.get("torrents"), dict)
                or any(not HASH.fullmatch(key) or type(force) is not bool
                       for key, force in old["torrents"].items())):
            raise OperationError("The Mover recovery record is invalid or belongs to a different WebUI.")
        if not args.recover:
            raise OperationError("An earlier run needs recovery. Run mover --recover first.")
        wait_idle(args)
        recover(api, args, path, old)
        return "Prior Mover run recovered."
    if args.recover:
        return "No pending Mover recovery."
    if mover_busy(args):
        raise OperationError("Mover is already active.")
    planned = mover_plan(api, args)
    if args.dry_run:
        return f"Dry run. Would stop up to {len(planned)} torrent(s) and start Mover."
    journal = {"client": api.base, "torrents": {}}
    entries = journal["torrents"]
    launch_uncertain = False
    pending = set()
    stopped = 0
    try:
        for key in planned:
            # Re-read immediately before the stop request to avoid taking
            # ownership of torrents the user stopped during the scan.
            current = api.torrents((key,))
            if key not in current:
                raise OperationError(f"Torrent {key} disappeared after planning.")
            state = torrent_state(current[key], key)
            if state in STOPPED:
                continue
            if state == "moving" or state in AMBIGUOUS:
                raise OperationError(f"Torrent {key} changed to an unsafe state after planning.")
            entries[key] = current[key].get("force_start") is True or state in FORCED
            write_state(path, journal)
            pending.add(key)
            api.stop(key)
        if entries:
            wait_states(api, tuple(entries), lambda _, state: state in STOPPED, args.state_timeout)
        pending.clear()
        stopped = len(entries)
        if mover_busy(args):
            raise OperationError("Another Mover started during torrent preparation.")
        LOG.info("Starting Unraid Mover with %s torrent(s) verified stopped.", stopped)
        launch_uncertain = True
        result = subprocess.run([args.mover_command, "start"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=args.mover_timeout)
        wait_idle(args)
        launch_uncertain = False
        if result.returncode:
            raise OperationError(f"Mover exited with status {result.returncode}. Check Unraid's system log.")
    finally:
        if entries:
            if launch_uncertain:
                LOG.error("Mover completion is uncertain. Torrents remain in the recovery record. Run mover --recover after checking Unraid.")
            else:
                recover(api, args, path, journal, pending)
    return f"Mover completed. Restored {stopped} torrent(s)."
