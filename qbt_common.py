"""Shared Web API, state, and logging for the two command-line tools."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import signal
import tempfile
from datetime import datetime
import time
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
TIMEOUT = (5, 15)
LOG = logging.getLogger("qbt-unraid")
HASH = re.compile(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\Z")


class OperationError(Exception):
    """Failure with a message safe for logs and notifications."""


def url_parts(value):
    try:
        parts = urlsplit(value)
        _ = parts.port
        return parts
    except ValueError:
        raise OperationError("Invalid URL configuration or tracker response.") from None


def tracker_host(url):
    return url_parts(url).hostname or ""


def setup_parser(description):
    load_dotenv(BASE / ".env")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", default=os.getenv("QB_HOST", "http://localhost:8080"))
    parser.add_argument("-u", "--user", default=os.getenv("QB_USER", "admin"))
    parser.add_argument("-p", "--password", default=os.getenv("QB_PASSWORD"),
                        help="Prefer QB_PASSWORD in .env to keep credentials off the command line.")
    parser.add_argument("--state-dir", type=Path, default=os.getenv("QBT_STATE_DIR", str(BASE / "state")),
                        help="Use the same absolute path for all scheduled jobs targeting this client.")
    return parser


def setup_logs(mode, secrets=()):
    log_dir = BASE / "logs"
    log_dir.mkdir(mode=0o700, exist_ok=True)
    for old in log_dir.glob("qbittorrent-automation_*.log"):
        if old.is_file() and time.time() - old.stat().st_mtime > 7 * 86400:
            old.unlink(missing_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    log_path = log_dir / f"qbittorrent-automation_{mode}_{stamp}.log"
    LOG.setLevel(logging.INFO)
    LOG.propagate = False

    class Redact(logging.Formatter):
        def format(self, record):
            line = super().format(record)
            line = re.sub(r"\b(?:https?|udp)://[^\s'\x22<>]+", "[redacted URL]", line, flags=re.I)
            for secret in secrets:
                if secret:
                    line = line.replace(secret, "[redacted]")
            return re.sub(r"[\x00-\x1f\x7f]", " ", line)

    formatter = Redact("%(asctime)s %(levelname)s %(message)s")
    for handler in (logging.StreamHandler(), logging.FileHandler(log_path, encoding="utf-8")):
        handler.setFormatter(formatter)
        LOG.addHandler(handler)
    return log_path


def install_signal_handler():
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)


@contextmanager
def run_lock(state_dir):
    if not state_dir.is_absolute():
        raise OperationError("The state directory must be an absolute path.")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir / "run.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OperationError("Another job holds the run lock.") from None
        yield


def read_state(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (ValueError, UnicodeError):
        raise OperationError(f"Invalid state file {path.name}. Inspect it before continuing.") from None


def write_state(path, data):
    # Publish a complete record before issuing any corresponding API mutation.
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dir_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        Path(temp).unlink(missing_ok=True)


class WebAPI:
    def __init__(self, args):
        if not args.password:
            raise OperationError("Set QB_PASSWORD in .env.")
        host = args.host.strip()
        if "://" not in host:
            host = "http://" + host
        parts = url_parts(host)
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.query or parts.fragment):
            raise OperationError("QB_HOST must be an HTTP(S) WebUI URL without credentials, query, or fragment.")
        self.base = host.rstrip("/")
        self.user = args.user
        self.password = args.password
        self.session = requests.Session()
        self.session.headers["Referer"] = self.base + "/"

    def __enter__(self):
        try:
            self._login()
            version = self.request("GET", "app/webapiVersion").text.strip()
            if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
                raise OperationError("qBittorrent returned an invalid Web API version.")
            self.version = tuple(int(part) for part in (version + ".0").split(".")[:3])
            LOG.info("Connected to qBittorrent Web API %s.", version)
            return self
        except BaseException:
            self.session.close()
            raise

    def __exit__(self, *_exc):
        try:
            self.request("POST", "auth/logout")
        except OperationError:
            LOG.warning("qBittorrent logout failed.")
        finally:
            self.session.close()

    def _login(self):
        response = self.request("POST", "auth/login",
                                data={"username": self.user, "password": self.password})
        if response.status_code != 204 and response.text.strip() != "Ok.":
            raise OperationError("qBittorrent login was rejected.")

    def request(self, method, endpoint, **kwargs):
        for attempt in range(2):
            try:
                response = self.session.request(method, f"{self.base}/api/v2/{endpoint}",
                                                timeout=TIMEOUT, allow_redirects=False, **kwargs)
            except requests.RequestException as exc:
                # A transport failure may follow a successful mutation. Leave
                # recovery to the journal instead of replaying an uncertain request.
                raise OperationError(f"{endpoint}: {type(exc).__name__}.") from None
            if (response.status_code in (401, 403) and attempt == 0
                    and not endpoint.startswith("auth/")):
                LOG.warning("qBittorrent rejected the API session (HTTP %s); reauthenticating and retrying once.",
                            response.status_code)
                response.close()
                self.session.cookies.clear()
                self._login()
                continue
            if response.status_code not in (200, 204):
                raise OperationError(f"{endpoint}: HTTP {response.status_code}.")
            return response

    def get_json(self, endpoint, **params):
        try:
            return self.request("GET", endpoint, params=params).json()
        except ValueError:
            raise OperationError(f"{endpoint}: expected JSON.") from None

    def list(self, endpoint, **params):
        rows = self.get_json(endpoint, **params)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise OperationError(f"{endpoint}: expected a list of objects.")
        return rows

    def torrents(self, hashes=()):
        if len(hashes) > 80:
            result = {}
            for offset in range(0, len(hashes), 80):
                result.update(self.torrents(hashes[offset:offset + 80]))
            return result
        params = {"hashes": "|".join(hashes)} if hashes else {}
        result = {}
        for row in self.list("torrents/info", **params):
            key = row.get("hash")
            if not isinstance(key, str) or not HASH.fullmatch(key) or key in result:
                raise OperationError("qBittorrent returned an invalid or duplicate torrent hash.")
            result[key] = row
        if hashes and not result.keys() <= set(hashes):
            raise OperationError("qBittorrent returned unexpected hashes in a filtered response.")
        return result

    def trackers(self, key):
        return self.list("torrents/trackers", hash=key)

    def mutate(self, method, **data):
        response = self.request("POST", f"torrents/{method}", data=data)
        if response.status_code == 200 and response.text.strip() not in ("", "Ok."):
            raise OperationError(f"torrents/{method}: unexpected response body.")

    def stop(self, key):
        self.mutate("stop" if self.version >= (2, 11, 0) else "pause", hashes=key)

    def start(self, key, force):
        if force:
            self.mutate("setForceStart", hashes=key, value="true")
        else:
            self.mutate("start" if self.version >= (2, 11, 0) else "resume", hashes=key)

    def edit_tracker(self, key, original, replacement):
        old_param = "url" if self.version >= (2, 13, 0) else "origUrl"
        self.mutate("editTracker", hash=key, newUrl=replacement, **{old_param: original})


def notify_http(method, url, label, **kwargs):
    try:
        response = requests.request(method, url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
        if not 200 <= response.status_code < 300:
            LOG.warning("%s returned HTTP %s.", label, response.status_code)
    except (requests.RequestException, ValueError) as exc:
        LOG.warning("%s failed (%s).", label, type(exc).__name__)
