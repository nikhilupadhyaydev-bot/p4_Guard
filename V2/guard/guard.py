#!/usr/bin/env python3
"""
Guard — file integrity monitoring for a directory tree.

Guard watches a folder, works out what actually changed, decides how much that
change matters, and writes it to an append-only log you can query later.

It is a small version of the idea behind Tripwire, AIDE and OSSEC: you do not
just want to know that a file event happened, you want to know whether the
*contents* changed, whether the change is suspicious, and whether anything was
tampered with while the monitor was switched off.


HOW TO READ THIS FILE
─────────────────────
It is one file on purpose, laid out in the order the data flows. Each numbered
section is self-contained, and you can read it straight down:

    1. Settings          what to watch, what to skip, how sensitive to be
    2. Fingerprints      reducing a file to size + hash + entropy + mode
    3. Storage           the SQLite schema and every query in one place
    4. Judgement         deciding how serious a change is
    5. Burst detection   spotting mass rewrites (the ransomware signature)
    6. The watcher       raw OS events in, verified changes out
    7. Terminal output   what you see while it runs
    8. Dashboard         a local web page showing the live log
    9. Commands          the command line

The single most important idea lives in section 6. The operating system tells
us a file "was modified" constantly — every save, every touch, every metadata
poke, often several times for one edit. Guard treats that notification as a
*hint*, not as a fact. It re-reads the file, hashes it, and compares against
what it stored last time. Only a genuine difference becomes an event. That one
decision is the difference between a useful audit log and an unreadable one.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
import queue
import sqlite3
import stat
import sys
import threading
import time
import webbrowser
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

__version__ = "2.0.0"
APP_NAME = "Guard"


# ═════════════════════════════════════════════════════════════════════════════
#  1.  Settings
# ═════════════════════════════════════════════════════════════════════════════

# Four levels, ordered. Everything downstream sorts and filters by these.
INFO = "info"
NOTICE = "notice"
WARNING = "warning"
CRITICAL = "critical"

SEVERITY_RANK = {INFO: 0, NOTICE: 1, WARNING: 2, CRITICAL: 3}

# Paths matching these are never even looked at. Two reasons to be generous
# here: editors and build tools churn through temporary files constantly, and
# — importantly — Guard's own database lives inside whatever you are watching
# often enough that failing to skip it creates an endless feedback loop, where
# writing an event causes an event.
DEFAULT_IGNORE = [
    "guard.db", "guard.db-wal", "guard.db-shm",
    ".git", ".hg", ".svn",
    "__pycache__", "*.pyc", "*.pyo",
    "node_modules", ".venv", "venv", "env",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox",
    ".idea", ".vscode", ".DS_Store", "Thumbs.db",
    "*.swp", "*.swx", "*~", "~$*",          # vim and Office lock files
    "*.tmp", "*.temp", "*.part", "*.crdownload",
]

# A change to any of these is treated as critical no matter what it is. These
# are the files an attacker edits to keep access or to steal credentials.
SENSITIVE_GLOBS = [
    "*/.ssh/*", "*/authorized_keys", "*/known_hosts",
    "*/.aws/credentials", "*/.kube/config", "*/.docker/config.json",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks",
    "*/.env", "*/.env.*", "*/.netrc", "*/.npmrc", "*/.pypirc",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
    "*/crontab", "*/cron.d/*",
]

# Anything that can be executed. New or modified binaries deserve a closer look.
EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".msi", ".com", ".scr",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".jar",
}

# Formats that are already compressed or encrypted, so high randomness in them
# is normal and says nothing. Copying a folder of photos is not an incident.
ALREADY_COMPRESSED = {
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif",
    ".mp3", ".mp4", ".mkv", ".mov", ".avi", ".flac", ".ogg", ".webm",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt",
    ".whl", ".jar", ".apk", ".woff", ".woff2",
}

# Configuration files sit between "boring" and "alarming".
CONFIG_SUFFIXES = {
    ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml",
    ".toml", ".xml", ".plist", ".properties", ".htaccess",
}


@dataclass
class Settings:
    """Everything tunable, in one object passed down to the parts that need it."""

    root: Path
    """The directory being watched."""

    db_path: Path = Path("guard.db")

    quiet_period: float = 0.4
    """
    Seconds of silence before a path is examined.

    Saving a file in most editors produces a flurry of events: write a temp
    file, rename it over the original, update the timestamp. Waiting for the
    flurry to stop before hashing means one save produces one event.
    """

    max_hash_bytes: int = 256 * 1024 * 1024
    """Files larger than this are tracked by size and timestamp only — hashing
    a 4 GB video on every touch would stall the watcher for no real benefit."""

    entropy_sample: int = 256 * 1024
    """How much of a file to read when measuring randomness. The first quarter
    of a megabyte is plenty to tell encrypted data from text."""

    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE))
    sensitive: list[str] = field(default_factory=lambda: list(SENSITIVE_GLOBS))

    burst_threshold: int = 20
    """Distinct files rewritten inside the burst window before Guard shouts."""

    burst_window: float = 30.0
    entropy_floor: float = 7.2
    """Shannon entropy, in bits per byte, above which content looks encrypted
    or compressed. Plain text sits near 4.5; random bytes approach 8.0."""

    def is_ignored(self, path: Path) -> bool:
        """True if this path should be skipped entirely.

        A pattern matches if it matches the whole path relative to the root, or
        any single component of it — so ``.git`` skips the whole ``.git`` tree
        rather than only a file literally named ``.git``.
        """
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            relative = path

        text = relative.as_posix()
        for pattern in self.ignore:
            if fnmatch(text, pattern):
                return True
            if any(fnmatch(part, pattern) for part in relative.parts):
                return True
        return False

    def is_sensitive(self, path: Path) -> bool:
        text = path.as_posix()
        return any(fnmatch(text, pattern) for pattern in self.sensitive)


# ═════════════════════════════════════════════════════════════════════════════
#  2.  Fingerprints
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class Fingerprint:
    """What a file looked like at one moment.

    Comparing two of these is how Guard decides whether anything real happened.
    """

    size: int
    sha256: str
    mode: int
    """Permission bits, so a file quietly becoming executable is visible."""
    mtime: float
    entropy: float
    """Bits of randomness per byte, 0.0 to 8.0."""

    @property
    def short_hash(self) -> str:
        return self.sha256[:12] if self.sha256 else "—"

    @property
    def is_executable(self) -> bool:
        return bool(self.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    @property
    def permissions(self) -> str:
        """Permission bits as ``rw-r--r--``."""
        return stat.filemode(self.mode)[1:]


def shannon_entropy(data: bytes) -> float:
    """Average information per byte, in bits.

    The formula is ``-Σ p·log₂(p)`` over how often each byte value appears.
    A file of all zeroes scores 0. English prose scores about 4.5. Compressed
    or encrypted data is close to the 8.0 ceiling, because every byte value is
    equally likely.

    That last property is the useful one: when a text document's entropy jumps
    from 4 to 7.9, something encrypted it.
    """
    if not data:
        return 0.0

    total = len(data)
    entropy = -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(data).values()
    )
    # A file of one repeated byte gives log₂(1) = 0, and negating it produces
    # -0.0. Mathematically identical, but it looks wrong in a report.
    return entropy if entropy else 0.0


def fingerprint(path: Path, settings: Settings) -> Fingerprint | None:
    """Measure a file. Returns ``None`` if it is gone or unreadable.

    Returning ``None`` rather than raising keeps the caller simple: a file that
    vanished between the OS notification and this read is an ordinary event,
    not an error.
    """
    try:
        info = path.stat()
    except (OSError, ValueError):
        return None

    if not stat.S_ISREG(info.st_mode):
        return None  # directories, sockets and symlinks are not hashed

    digest = ""
    entropy = 0.0

    if info.st_size <= settings.max_hash_bytes:
        hasher = hashlib.sha256()
        sample = bytearray()
        try:
            with path.open("rb") as handle:
                # Read in chunks so memory use stays flat regardless of size.
                while chunk := handle.read(64 * 1024):
                    hasher.update(chunk)
                    if len(sample) < settings.entropy_sample:
                        sample.extend(chunk[: settings.entropy_sample - len(sample)])
        except OSError:
            return None  # locked by another process, or permission denied
        digest = hasher.hexdigest()
        entropy = shannon_entropy(bytes(sample))

    return Fingerprint(
        size=info.st_size,
        sha256=digest,
        mode=stat.S_IMODE(info.st_mode),
        mtime=info.st_mtime,
        entropy=entropy,
    )


# ═════════════════════════════════════════════════════════════════════════════
#  3.  Storage
# ═════════════════════════════════════════════════════════════════════════════

SCHEMA = """
-- The current known state of every tracked file. One row per path.
CREATE TABLE IF NOT EXISTS files (
    path       TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    mode       INTEGER NOT NULL,
    mtime      REAL    NOT NULL,
    entropy    REAL    NOT NULL,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL
);

-- Append-only history. Nothing here is ever updated or deleted, which is what
-- makes it usable as evidence.
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    path        TEXT NOT NULL,
    action      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    old_hash    TEXT,
    new_hash    TEXT,
    size_before INTEGER,
    size_after  INTEGER,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_path     ON events(path);

-- Small key/value bag for things like when the baseline was taken.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    """Every SQL statement in the project lives in this class.

    Guard runs three threads that touch the database: the watchdog observer,
    the processing loop, and the dashboard's web server. SQLite connections are
    not safe to share across threads by default, so this class holds one
    connection opened with ``check_same_thread=False`` and puts a lock around
    every use of it. A lock is slightly slower than one connection per thread,
    and much easier to be sure is correct.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Write-ahead logging lets the dashboard read while the watcher writes.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ---------------------------------------------------------------- files

    def get_file(self, path: str) -> Fingerprint | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT size, sha256, mode, mtime, entropy FROM files WHERE path = ?",
                (path,),
            ).fetchone()
        if row is None:
            return None
        return Fingerprint(row["size"], row["sha256"], row["mode"], row["mtime"], row["entropy"])

    def put_file(self, path: str, print_: Fingerprint) -> None:
        now = _timestamp()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO files (path, size, sha256, mode, mtime, entropy, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    size=excluded.size, sha256=excluded.sha256, mode=excluded.mode,
                    mtime=excluded.mtime, entropy=excluded.entropy, last_seen=excluded.last_seen
                """,
                (path, print_.size, print_.sha256, print_.mode, print_.mtime, print_.entropy, now, now),
            )
            self._conn.commit()

    def drop_file(self, path: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM files WHERE path = ?", (path,))
            self._conn.commit()

    def tracked_files(self) -> dict[str, Fingerprint]:
        """Every known file, for the offline audit to compare against."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT path, size, sha256, mode, mtime, entropy FROM files"
            ).fetchall()
        return {
            row["path"]: Fingerprint(
                row["size"], row["sha256"], row["mode"], row["mtime"], row["entropy"]
            )
            for row in rows
        }

    def file_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    # --------------------------------------------------------------- events

    def add_event(self, change: Change) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO events
                    (ts, path, action, severity, reason, old_hash, new_hash,
                     size_before, size_after, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    change.ts, change.path, change.action, change.severity, change.reason,
                    change.before.sha256 if change.before else None,
                    change.after.sha256 if change.after else None,
                    change.before.size if change.before else None,
                    change.after.size if change.after else None,
                    change.detail,
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid or 0)

    def events_since(self, event_id: int, limit: int = 200) -> list[dict]:
        """Everything newer than ``event_id``. The dashboard polls with this."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (event_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_events(
        self, limit: int = 50, severity: str | None = None, path_like: str | None = None
    ) -> list[dict]:
        clauses, params = [], []
        if severity:
            allowed = [s for s, rank in SEVERITY_RANK.items() if rank >= SEVERITY_RANK[severity]]
            clauses.append(f"severity IN ({','.join('?' * len(allowed))})")
            params.extend(allowed)
        if path_like:
            clauses.append("path LIKE ?")
            params.append(f"%{path_like}%")

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def severity_counts(self, since: str | None = None) -> dict[str, int]:
        query = "SELECT severity, COUNT(*) AS n FROM events"
        params: list = []
        if since:
            query += " WHERE ts >= ?"
            params.append(since)
        query += " GROUP BY severity"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()

        counts = dict.fromkeys(SEVERITY_RANK, 0)
        for row in rows:
            counts[row["severity"]] = row["n"]
        return counts

    def busiest_paths(self, limit: int = 6, since: str | None = None) -> list[dict]:
        # Folder-wide alerts carry the root as their path, which is not a file
        # and would sit at the top of this list meaning nothing.
        query = "SELECT path, COUNT(*) AS n FROM events WHERE action != 'alert'"
        params: list = []
        if since:
            query += " AND ts >= ?"
            params.append(since)
        query += " GROUP BY path ORDER BY n DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [{"path": row["path"], "count": row["n"]} for row in rows]

    def latest_event_id(self) -> int:
        """Highest id on record. The dashboard uses it to start near the end
        of a long log rather than replaying it from the beginning."""
        with self._lock:
            row = self._conn.execute("SELECT COALESCE(MAX(id), 0) AS id FROM events").fetchone()
        return int(row["id"])

    def total_events(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ----------------------------------------------------------------- meta

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _timestamp() -> str:
    """UTC, ISO 8601, to the second. Sorts lexicographically, which is handy."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ═════════════════════════════════════════════════════════════════════════════
#  4.  Judgement
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class Change:
    """A verified change: something really did happen to this file."""

    ts: str
    path: str
    action: str
    """created, modified, deleted, moved, or permissions."""
    severity: str
    reason: str
    """Why this severity, in plain words, for the log and the dashboard."""
    before: Fingerprint | None = None
    after: Fingerprint | None = None
    detail: str | None = None
    """Extra context, such as a move destination."""

    @property
    def size_delta(self) -> int:
        after = self.after.size if self.after else 0
        before = self.before.size if self.before else 0
        return after - before

    def as_dict(self) -> dict:
        return {
            "ts": self.ts,
            "path": self.path,
            "action": self.action,
            "severity": self.severity,
            "reason": self.reason,
            "old_hash": self.before.sha256 if self.before else None,
            "new_hash": self.after.sha256 if self.after else None,
            "size_before": self.before.size if self.before else None,
            "size_after": self.after.size if self.after else None,
            "detail": self.detail,
        }


def judge(
    action: str,
    path: Path,
    before: Fingerprint | None,
    after: Fingerprint | None,
    settings: Settings,
) -> tuple[str, str]:
    """Decide how serious a change is, and say why.

    Rules run from most to least serious and the first match wins, so the order
    of these blocks *is* the policy. Each returns the severity together with a
    sentence explaining it, because an alert you cannot interpret is not much
    better than no alert.
    """
    suffix = path.suffix.lower()

    # ── critical ───────────────────────────────────────────────────────────
    if settings.is_sensitive(path):
        return CRITICAL, f"{action} under a path holding credentials or access control"

    # A file that was not executable and now is. This is how a dropped payload
    # or a hijacked script becomes runnable.
    if before and after and not before.is_executable and after.is_executable:
        return CRITICAL, f"permissions changed to executable ({before.permissions} → {after.permissions})"

    # Content that was readable and is now indistinguishable from random bytes.
    # Compression does this legitimately; so does encryption.
    if (
        before and after
        and before.entropy > 0
        and before.entropy < 6.0
        and after.entropy >= settings.entropy_floor
    ):
        return CRITICAL, (
            f"contents became unreadable — randomness rose from "
            f"{before.entropy:.1f} to {after.entropy:.1f} bits per byte"
        )

    # ── warning ────────────────────────────────────────────────────────────
    if suffix in EXECUTABLE_SUFFIXES:
        return WARNING, f"{action} an executable file"

    if action == "deleted":
        return WARNING, "file removed"

    if before and after and before.mode != after.mode:
        return WARNING, f"permissions changed ({before.permissions} → {after.permissions})"

    # A file losing almost all of its content is worth flagging: truncation is
    # both a common bug and a common way to destroy evidence.
    if before and after and before.size > 1024 and after.size < before.size * 0.1:
        return WARNING, f"shrank from {human_size(before.size)} to {human_size(after.size)}"

    # ── notice ─────────────────────────────────────────────────────────────
    if suffix in CONFIG_SUFFIXES:
        return NOTICE, f"{action} a configuration file"

    if action == "moved":
        return NOTICE, "file moved or renamed"

    if action == "created":
        return NOTICE, "new file"

    # ── everything else ────────────────────────────────────────────────────
    return INFO, "contents changed"


def human_size(count: int | None) -> str:
    if count is None:
        return "—"
    size = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# ═════════════════════════════════════════════════════════════════════════════
#  5.  Burst detection
# ═════════════════════════════════════════════════════════════════════════════


class BurstDetector:
    """Watches for a lot of files being encrypted at once.

    One file becoming unreadable is unremarkable. Two hundred files becoming
    unreadable in thirty seconds is ransomware. Neither the per-file rules in
    section 4 nor a human reading one log line at a time can see that shape —
    it only exists across events, so it needs its own memory.

    The one judgement that matters here is what counts as suspicious enough to
    put in that memory. Counting *every* busy file and then asking what
    fraction looked encrypted turned out to be wrong twice over: a compile or a
    checkout writes hundreds of files and drowns the signal, and the fraction
    test does no real work anyway, because build output is ordinary readable
    text that never looks encrypted in the first place.

    So only one thing is counted: a file that was readable and now is not.
    That is the encryption signature, it excludes builds by construction, and
    it cannot be diluted by whatever else happened to be going on.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._recent: deque[tuple[float, str]] = deque()  # (when, path)
        self._last_alert: float | None = None
        """When the last alert fired, on the monotonic clock.

        ``None`` rather than ``0.0``: ``time.monotonic()`` counts from system
        boot on Linux, so zero is a real timestamp during the first minute of
        uptime. Using it as a "never happened" marker made the cooldown
        suppress the very first alert.
        """
        self._cooldown = 60.0
        """Do not re-alert for a minute; one warning is a signal, sixty is noise."""

    def _looks_encrypted(self, change: Change) -> bool:
        """Did this file go from readable to unreadable?"""
        if change.after is None or change.after.entropy < self.settings.entropy_floor:
            return False

        # Archives and media are already near-random. Copying a folder of them
        # around is not an incident, so they never enter the count.
        if Path(change.path).suffix.lower() in ALREADY_COMPRESSED:
            return False

        # No previous version means a new file. High-entropy new files still
        # count — plenty of ransomware writes ciphertext beside the original
        # and deletes it afterwards.
        if change.before is None:
            return True

        return change.before.entropy < 6.0

    def observe(self, change: Change) -> str | None:
        """Feed in a change. Returns an alert message if the pattern fires."""
        if change.action not in ("modified", "created", "moved"):
            return None
        if not self._looks_encrypted(change):
            return None

        now = time.monotonic()
        self._recent.append((now, change.path))

        # Forget anything older than the window.
        cutoff = now - self.settings.burst_window
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

        affected = {path for _, path in self._recent}
        if len(affected) < self.settings.burst_threshold:
            return None

        if self._last_alert is not None and now - self._last_alert < self._cooldown:
            return None
        self._last_alert = now

        return (
            f"{len(affected)} files became unreadable within "
            f"{self.settings.burst_window:.0f} seconds — this is what ransomware "
            f"encrypting a folder looks like"
        )

    def reset(self) -> None:
        self._recent.clear()
        self._last_alert = None


# ═════════════════════════════════════════════════════════════════════════════
#  6.  The watcher
# ═════════════════════════════════════════════════════════════════════════════


class _EventBridge(FileSystemEventHandler):
    """Hands raw watchdog callbacks to a queue and does nothing else.

    These callbacks fire on watchdog's own thread. Doing real work here — a
    stat, a hash, a database write — would block the thread that is supposed to
    be draining OS notifications, and notifications that are not drained fast
    enough get dropped. So this class stays trivial on purpose.
    """

    def __init__(self, sink: queue.Queue) -> None:
        self.sink = sink

    def on_created(self, event):
        if not event.is_directory:
            self.sink.put((str(event.src_path), "created", None))

    def on_modified(self, event):
        if not event.is_directory:
            self.sink.put((str(event.src_path), "modified", None))

    def on_deleted(self, event):
        if not event.is_directory:
            self.sink.put((str(event.src_path), "deleted", None))

    def on_moved(self, event):
        if not event.is_directory:
            self.sink.put((str(event.src_path), "moved", str(event.dest_path)))


@dataclass
class _Pending:
    """A path we have been told about, waiting for the noise to settle."""

    hint: str
    last_seen: float
    destination: str | None = None


class Guard:
    """Ties everything together: watch, verify, judge, record, announce."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.burst = BurstDetector(settings)

        self._incoming: queue.Queue = queue.Queue()
        self._pending: dict[str, _Pending] = {}
        self._stop = threading.Event()
        # self._observer: Observer | None = None
        self._worker: threading.Thread | None = None

        self.listeners: list[Callable[[Change], None]] = []
        """Called for every confirmed change. The terminal printer and the
        dashboard both subscribe here rather than being wired in directly."""

        self.started_at = time.time()
        self.events_seen = 0

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self._observer = Observer()
        self._observer.schedule(_EventBridge(self._incoming), str(self.settings.root), recursive=True)
        self._observer.start()

        self._worker = threading.Thread(target=self._run, name="guard-worker", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=3)
        if self._worker is not None:
            self._worker.join(timeout=3)
        self.db.close()

    # ----------------------------------------------------------- processing

    def _run(self) -> None:
        """The debounce loop.

        Collect notifications as they arrive, and examine a path only once it
        has been quiet for ``quiet_period``. One file save can produce five
        notifications; this turns them back into one.
        """
        while not self._stop.is_set():
            try:
                path, hint, destination = self._incoming.get(timeout=0.1)
                self._remember(path, hint, destination)
            except queue.Empty:
                pass
            self._flush_settled()

    def _remember(self, path: str, hint: str, destination: str | None) -> None:
        if self.settings.is_ignored(Path(path)):
            return
        existing = self._pending.get(path)
        # Keep the earliest hint — if we saw "created" then "modified", the
        # file is new. Verification decides the real answer anyway.
        self._pending[path] = _Pending(
            hint=existing.hint if existing else hint,
            last_seen=time.monotonic(),
            destination=destination or (existing.destination if existing else None),
        )

    def _flush_settled(self) -> None:
        now = time.monotonic()
        ready = [
            path for path, pending in self._pending.items()
            if now - pending.last_seen >= self.settings.quiet_period
        ]
        for path in ready:
            pending = self._pending.pop(path)
            change = self.examine(path, pending.hint, pending.destination)
            if change is not None:
                self._publish(change)

    def examine(self, path: str, hint: str = "modified", destination: str | None = None) -> Change | None:
        """Work out what actually changed about one file.

        Returns ``None`` when nothing did — which is most of the time, and is
        the whole point. The ``hint`` from the operating system is only used to
        label moves; everything else is settled by comparing fingerprints.
        """
        target = Path(path)
        if self.settings.is_ignored(target):
            return None

        stored = self.db.get_file(path)
        current = fingerprint(target, self.settings)

        # Renames arrive with both ends, so record the move and re-point the
        # stored row at the new location.
        if hint == "moved" and destination:
            return self._handle_move(path, destination, stored)

        if current is None and stored is None:
            # A temporary file that appeared and vanished before we looked. It
            # never existed as far as the log is concerned.
            return None

        if current is None:
            action = "deleted"
        elif stored is None:
            action = "created"
        elif stored.sha256 == current.sha256:
            # ─────────────────────────────────────────────────────────────
            #  The noise filter. Same bytes as last time, so the operating
            #  system's "modified" was about metadata, not content. Unless
            #  the permissions moved, there is nothing to report.
            # ─────────────────────────────────────────────────────────────
            if stored.mode == current.mode:
                self.db.put_file(path, current)  # refresh mtime quietly
                return None
            action = "permissions"
        else:
            action = "modified"

        severity, reason = judge(action, target, stored, current, self.settings)
        change = Change(
            ts=_timestamp(), path=path, action=action,
            severity=severity, reason=reason, before=stored, after=current,
        )

        if current is None:
            self.db.drop_file(path)
        else:
            self.db.put_file(path, current)
        return change

    def _handle_move(self, source: str, destination: str, stored: Fingerprint | None) -> Change | None:
        if self.settings.is_ignored(Path(destination)):
            self.db.drop_file(source)
            return None

        current = fingerprint(Path(destination), self.settings)
        if current is None:
            return None

        severity, reason = judge("moved", Path(destination), stored, current, self.settings)
        self.db.drop_file(source)
        self.db.put_file(destination, current)

        return Change(
            ts=_timestamp(), path=source, action="moved",
            severity=severity, reason=reason, before=stored, after=current,
            detail=destination,
        )

    def _publish(self, change: Change) -> None:
        """Record a change, check it against the burst detector, tell listeners."""
        self.db.add_event(change)
        self.events_seen += 1
        for listener in self.listeners:
            listener(change)

        alert = self.burst.observe(change)
        if alert:
            burst_change = Change(
                ts=_timestamp(), path=str(self.settings.root),
                action="alert", severity=CRITICAL, reason=alert,
            )
            self.db.add_event(burst_change)
            for listener in self.listeners:
                listener(burst_change)

    # -------------------------------------------------------------- offline

    def walk(self):
        """Yield every file under the root that is not ignored."""
        for directory, subdirectories, filenames in os.walk(self.settings.root):
            here = Path(directory)
            # Pruning in place stops os.walk descending into ignored trees at
            # all, which matters when node_modules has 40,000 files in it.
            subdirectories[:] = [
                name for name in subdirectories if not self.settings.is_ignored(here / name)
            ]
            for name in filenames:
                candidate = here / name
                if not self.settings.is_ignored(candidate):
                    yield candidate

    def baseline(self, on_progress: Callable[[int, Path], None] | None = None) -> int:
        """Fingerprint the whole tree and store it as the known-good state."""
        count = 0
        for candidate in self.walk():
            measured = fingerprint(candidate, self.settings)
            if measured is None:
                continue
            self.db.put_file(str(candidate), measured)
            count += 1
            if on_progress is not None:
                on_progress(count, candidate)

        self.db.set_meta("baseline_taken", _timestamp())
        self.db.set_meta("baseline_root", str(self.settings.root))
        self.db.set_meta("baseline_count", str(count))
        return count

    def audit(self) -> dict[str, list]:
        """Compare the tree on disk now against the stored baseline.

        This is what catches tampering that happened while Guard was not
        running — the gap a live watcher cannot cover on its own.
        """
        stored = self.db.tracked_files()
        added, changed, removed = [], [], []

        for candidate in self.walk():
            path = str(candidate)
            current = fingerprint(candidate, self.settings)
            if current is None:
                continue

            known = stored.pop(path, None)
            if known is None:
                added.append((path, current))
            # Different bytes, or the same bytes with different permissions —
            # both count as tampering.
            elif known.sha256 != current.sha256 or known.mode != current.mode:
                changed.append((path, known, current))

        # Whatever is left in `stored` was on record but is no longer on disk.
        removed = sorted(stored.items())
        return {"added": added, "changed": changed, "removed": removed}


# ═════════════════════════════════════════════════════════════════════════════
#  7.  Terminal output
# ═════════════════════════════════════════════════════════════════════════════

_COLOURS = {INFO: "37", NOTICE: "36", WARNING: "33", CRITICAL: "1;31"}
_SYMBOLS = {INFO: "·", NOTICE: "+", WARNING: "!", CRITICAL: "✕"}
_USE_COLOUR = sys.stdout.isatty()


def shorten(path: str, root: Path | None) -> str:
    """Drop the watched folder off the front of a path, for display only.

    The log always stores absolute paths — an audit trail that says
    ``src/auth.py`` without saying which ``src`` is not much of an audit trail.
    Screens are narrow, so the display shortens them.
    """
    if root is None:
        return path
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return path


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def dim(text: str) -> str:
    return paint(text, "2")


def format_change(change: Change, root: Path | None = None) -> str:
    """One change as one line of terminal output."""
    clock = change.ts[11:19]  # just HH:MM:SS; the date is in the log
    symbol = paint(_SYMBOLS[change.severity], _COLOURS[change.severity])

    display = shorten(change.path, root)

    line = f"{dim(clock)}  {symbol} {change.action:<11} {display}"

    extras = []
    if change.detail:
        extras.append(f"→ {shorten(change.detail, root)}")
    if change.action == "modified" and change.size_delta:
        sign = "+" if change.size_delta > 0 else "−"
        extras.append(f"{sign}{human_size(abs(change.size_delta))}")
    if change.after and change.after.short_hash != "—":
        extras.append(change.after.short_hash)
    if extras:
        line += dim("   " + "  ".join(extras))

    if change.severity in (WARNING, CRITICAL):
        line += "\n" + " " * 13 + paint(change.reason, _COLOURS[change.severity])

    return line


# ═════════════════════════════════════════════════════════════════════════════
#  8.  Dashboard
# ═════════════════════════════════════════════════════════════════════════════

DASHBOARD_FILE = Path(__file__).with_name("dashboard.html")


class _DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard page and the two JSON endpoints behind it.

    The page asks for anything newer than the last event id it has seen, once a
    second. A cursor like that is simpler than a streaming connection and it
    recovers from a closed laptop lid or a dropped connection without any
    reconnect logic: whatever id it holds is still valid later.
    """

    guard: Guard  # injected in serve_dashboard before the server starts

    def do_GET(self) -> None:
        route = urlparse(self.path)
        query = parse_qs(route.query)

        if route.path in ("/", "/index.html"):
            self._send_page()
        elif route.path == "/api/events":
            since = int(query.get("since", ["0"])[0])
            self._send_json({"events": self.guard.db.events_since(since)})
        elif route.path == "/api/summary":
            self._send_json(self._summary())
        else:
            self.send_error(404)

    def _summary(self) -> dict:
        guard = self.guard
        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        return {
            "root": str(guard.settings.root),
            "tracked": guard.db.file_count(),
            "total_events": guard.db.total_events(),
            "latest_id": guard.db.latest_event_id(),
            "uptime": int(time.time() - guard.started_at),
            "severity": guard.db.severity_counts(since=day_ago),
            "busiest": guard.db.busiest_paths(since=day_ago),
            "baseline": guard.db.get_meta("baseline_taken"),
        }

    def _send_page(self) -> None:
        try:
            body = DASHBOARD_FILE.read_bytes()
        except OSError:
            self.send_error(500, "dashboard.html is missing from the Guard folder")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        """Silence the default request logging; it would drown the event log."""


def serve_dashboard(guard: Guard, host: str, port: int) -> ThreadingHTTPServer:
    """Start the dashboard on a background thread and return the server."""
    _DashboardHandler.guard = guard
    server = ThreadingHTTPServer((host, port), _DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, name="guard-dashboard", daemon=True)
    thread.start()
    return server


# ═════════════════════════════════════════════════════════════════════════════
#  9.  Commands
# ═════════════════════════════════════════════════════════════════════════════


def banner() -> None:
    print()
    print(f"  {paint(APP_NAME, '1')} {dim(__version__)}")
    print(dim("  File integrity monitoring"))
    print(dim("  " + "─" * 54))
    print()


def settings_from(args: argparse.Namespace) -> Settings:
    root = Path(args.directory).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"  {root} is not a directory.")

    settings = Settings(root=root, db_path=Path(args.database).expanduser())
    if getattr(args, "ignore", None):
        settings.ignore.extend(args.ignore)
    if getattr(args, "quiet_period", None):
        settings.quiet_period = args.quiet_period
    return settings


def cmd_watch(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)

    minimum = SEVERITY_RANK[args.min_severity]
    guard.listeners.append(
        lambda change: (
            print(format_change(change, settings.root))
            if SEVERITY_RANK[change.severity] >= minimum
            else None
        )
    )

    if guard.db.file_count() == 0:
        print(dim("  No baseline yet — taking one first so changes can be compared."))
        count = guard.baseline()
        print(dim(f"  Fingerprinted {count:,} files.\n"))

    server = None
    if args.dashboard:
        server = serve_dashboard(guard, args.host, args.port)
        url = f"http://{args.host}:{args.port}"
        print(f"  Dashboard on {paint(url, '4')}")
        if not args.no_browser:
            webbrowser.open(url)

    guard.start()
    print(f"  Watching {paint(str(settings.root), '1')}")
    print(dim(f"  Tracking {guard.db.file_count():,} files. Press Ctrl+C to stop.\n"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n  Stopped after {guard.events_seen} recorded changes.")
    finally:
        if server is not None:
            server.shutdown()
        guard.stop()
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    print(f"  Fingerprinting {settings.root}\n")

    def progress(count: int, path: Path) -> None:
        if count % 50 == 0:
            print(f"\r  {count:,} files…", end="", flush=True)

    started = time.monotonic()
    count = guard.baseline(on_progress=progress)
    elapsed = time.monotonic() - started

    print(f"\r  {paint(f'{count:,} files', '1')} fingerprinted in {elapsed:.1f}s.")
    print(dim(f"  Baseline saved to {settings.db_path}. Run 'guard audit' to compare later."))
    guard.stop()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)

    if guard.db.file_count() == 0:
        print("  No baseline to compare against. Run 'guard baseline' first.")
        guard.stop()
        return 1

    taken = guard.db.get_meta("baseline_taken")
    print(f"  Comparing {settings.root} against the baseline{dim(' from ' + taken) if taken else ''}\n")

    result = guard.audit()
    total = sum(len(group) for group in result.values())

    for path, current in result["added"]:
        print(f"  {paint('+', _COLOURS[NOTICE])} added     {shorten(path, settings.root)}"
              f"{dim('  ' + human_size(current.size))}")

    for path, known, current in result["changed"]:
        note = (
            f"{known.permissions} → {current.permissions}"
            if known.sha256 == current.sha256
            else f"{known.short_hash} → {current.short_hash}"
        )
        print(f"  {paint('~', _COLOURS[WARNING])} changed   {shorten(path, settings.root)}{dim('  ' + note)}")

    for path, known in result["removed"]:
        print(f"  {paint('−', _COLOURS[WARNING])} removed   {shorten(path, settings.root)}"
              f"{dim('  was ' + human_size(known.size))}")

    print()
    if total == 0:
        print(f"  {paint('Clean.', _COLOURS[NOTICE])} Nothing has changed since the baseline.")
        guard.stop()
        return 0

    print(
        f"  {len(result['added'])} added, {len(result['changed'])} changed, "
        f"{len(result['removed'])} removed."
    )
    guard.stop()
    return 1  # non-zero so CI and cron jobs notice


def cmd_history(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)

    rows = guard.db.recent_events(
        limit=args.limit,
        severity=args.min_severity if args.min_severity != INFO else None,
        path_like=args.path,
    )
    if not rows:
        print("  Nothing recorded yet.")
        guard.stop()
        return 0

    for row in reversed(rows):
        change = Change(
            ts=row["ts"], path=row["path"], action=row["action"],
            severity=row["severity"], reason=row["reason"], detail=row["detail"],
        )
        print(f"  {dim(row['ts'][:10])} {format_change(change, settings.root)}")

    print(dim(f"\n  {len(rows)} of {guard.db.total_events():,} recorded events."))
    guard.stop()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    guard = Guard(settings)
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")

    print(f"  Watching   {settings.root}")
    print(f"  Tracking   {guard.db.file_count():,} files")
    print(f"  Recorded   {guard.db.total_events():,} events")
    taken = guard.db.get_meta("baseline_taken")
    print(f"  Baseline   {taken or 'never taken'}\n")

    counts = guard.db.severity_counts(since=day_ago)
    print(dim("  Last 24 hours"))
    for level in (CRITICAL, WARNING, NOTICE, INFO):
        bar = "█" * min(40, counts[level])
        print(f"    {level:<9} {counts[level]:>5}  {paint(bar, _COLOURS[level])}")

    busiest = guard.db.busiest_paths(since=day_ago)
    if busiest:
        print(dim("\n  Busiest paths"))
        for entry in busiest:
            print(f"    {entry['count']:>4}  {shorten(entry['path'], settings.root)}")

    guard.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guard",
        description=f"{APP_NAME} — file integrity monitoring for a directory tree.",
        epilog="Start with:  guard watch ./my-folder --dashboard",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def shared(subparser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        subparser.add_argument("directory", help="the folder to monitor")
        subparser.add_argument("-d", "--database", default="guard.db", help="where to keep the log")
        subparser.add_argument(
            "-i", "--ignore", action="append", metavar="PATTERN",
            help="extra pattern to skip; repeatable, e.g. -i '*.log'",
        )
        return subparser

    watch = shared(commands.add_parser("watch", help="monitor the folder and record changes"))
    watch.add_argument("--dashboard", action="store_true", help="also serve the live web dashboard")
    watch.add_argument("--host", default="127.0.0.1")
    watch.add_argument("--port", type=int, default=8420)
    watch.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    watch.add_argument(
        "-m", "--min-severity", default=INFO, choices=list(SEVERITY_RANK),
        help="hide anything below this level from the terminal",
    )
    watch.add_argument(
        "-q", "--quiet-period", type=float, default=0.4,
        help="seconds of silence before a file is examined (default 0.4)",
    )
    watch.set_defaults(func=cmd_watch)

    base = shared(commands.add_parser("baseline", help="record the current state as known-good"))
    base.set_defaults(func=cmd_baseline)

    audit = shared(commands.add_parser("audit", help="compare the folder against the baseline"))
    audit.set_defaults(func=cmd_audit)

    history = shared(commands.add_parser("history", help="show recorded events"))
    history.add_argument("-n", "--limit", type=int, default=40)
    history.add_argument("-p", "--path", help="only paths containing this text")
    history.add_argument("-m", "--min-severity", default=INFO, choices=list(SEVERITY_RANK))
    history.set_defaults(func=cmd_history)

    stats = shared(commands.add_parser("stats", help="summarise what has been recorded"))
    stats.set_defaults(func=cmd_stats)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    banner()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  Stopped.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
