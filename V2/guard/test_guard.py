"""
Tests for Guard.

These exercise the parts that are easy to get quietly wrong: the noise filter,
the severity rules, the ransomware heuristic and the offline audit. None of
them touch the network, and only two of them start a real watchdog observer —
the rest drive ``Guard.examine`` directly, which is the same code path the
watcher uses once the debounce timer has expired, minus the waiting.
"""

from __future__ import annotations

import os
import stat
import time

import pytest

from guard import (
    CRITICAL,
    INFO,
    NOTICE,
    WARNING,
    BurstDetector,
    Change,
    Database,
    Fingerprint,
    Guard,
    Settings,
    fingerprint,
    human_size,
    judge,
    shannon_entropy,
)

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def workspace(tmp_path):
    """An empty folder to watch, with the database kept outside it."""
    root = tmp_path / "project"
    root.mkdir()
    return root


@pytest.fixture
def settings(workspace, tmp_path):
    return Settings(root=workspace, db_path=tmp_path / "guard.db", quiet_period=0.1)


@pytest.fixture
def guard(settings):
    instance = Guard(settings)
    yield instance
    instance.stop()


def write(path, text="hello world, this is ordinary readable text\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --------------------------------------------------------------------------- #
# Entropy
# --------------------------------------------------------------------------- #


class TestEntropy:
    def test_empty_input(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_repeated_byte_is_zero_not_negative_zero(self):
        # Negating a sum of zeroes gives -0.0, which is mathematically fine and
        # looks like a bug in a report.
        result = shannon_entropy(b"\x00" * 1000)
        assert result == 0.0
        assert str(result) == "0.0"

    def test_two_equally_common_bytes_give_one_bit(self):
        assert shannon_entropy(b"ab" * 500) == pytest.approx(1.0)

    def test_every_byte_value_once_gives_the_maximum(self):
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_prose_sits_well_below_random_data(self):
        prose = shannon_entropy(b"the quick brown fox jumps over the lazy dog " * 40)
        noise = shannon_entropy(os.urandom(8192))
        assert prose < 5.0
        assert noise > 7.5
        # The gap between these two is the entire basis of the ransomware check.
        assert noise - prose > 2.5


# --------------------------------------------------------------------------- #
# Fingerprints
# --------------------------------------------------------------------------- #


class TestFingerprint:
    def test_missing_file_gives_none_rather_than_raising(self, workspace, settings):
        assert fingerprint(workspace / "nope.txt", settings) is None

    def test_directory_is_not_fingerprinted(self, workspace, settings):
        (workspace / "sub").mkdir()
        assert fingerprint(workspace / "sub", settings) is None

    def test_identical_content_gives_identical_hash(self, workspace, settings):
        a = write(workspace / "a.txt", "same")
        b = write(workspace / "b.txt", "same")
        assert fingerprint(a, settings).sha256 == fingerprint(b, settings).sha256

    def test_hash_changes_with_content(self, workspace, settings):
        path = write(workspace / "a.txt", "before")
        first = fingerprint(path, settings)
        path.write_text("after")
        assert fingerprint(path, settings).sha256 != first.sha256

    def test_oversized_files_are_tracked_without_hashing(self, workspace, settings):
        settings.max_hash_bytes = 10
        path = write(workspace / "big.bin", "x" * 500)
        measured = fingerprint(path, settings)
        assert measured.size == 500
        assert measured.sha256 == ""  # recorded, but not read end to end

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no execute bit")
    def test_execute_bit_is_visible(self, workspace, settings):
        path = write(workspace / "run.sh", "#!/bin/sh\n")
        assert fingerprint(path, settings).is_executable is False
        os.chmod(path, 0o755)
        assert fingerprint(path, settings).is_executable is True


# --------------------------------------------------------------------------- #
# Ignore rules
# --------------------------------------------------------------------------- #


class TestIgnoreRules:
    @pytest.mark.parametrize(
        "relative",
        [".git/config", "__pycache__/x.pyc", "node_modules/pkg/index.js",
         "src/.git/HEAD", "notes.txt.swp", "~$report.docx", "build.tmp"],
    )
    def test_default_patterns_are_skipped(self, settings, relative):
        assert settings.is_ignored(settings.root / relative) is True

    @pytest.mark.parametrize("relative", ["src/app.py", "README.md", "config/settings.yaml"])
    def test_ordinary_files_are_not_skipped(self, settings, relative):
        assert settings.is_ignored(settings.root / relative) is False

    def test_guard_skips_its_own_database(self, settings):
        # Without this Guard records its own writes, which produce more writes.
        assert settings.is_ignored(settings.root / "guard.db") is True
        assert settings.is_ignored(settings.root / "guard.db-wal") is True

    def test_a_pattern_matches_any_component_of_the_path(self, settings):
        settings.ignore.append("secrets")
        assert settings.is_ignored(settings.root / "a" / "secrets" / "b" / "c.txt") is True

    @pytest.mark.parametrize(
        "relative", [".ssh/id_rsa", "deploy.pem", ".env", ".aws/credentials"]
    )
    def test_sensitive_paths_are_recognised(self, settings, relative):
        assert settings.is_sensitive(settings.root / relative) is True

    def test_ordinary_paths_are_not_sensitive(self, settings):
        assert settings.is_sensitive(settings.root / "src" / "main.py") is False


# --------------------------------------------------------------------------- #
# Severity rules
# --------------------------------------------------------------------------- #


def make_print(size=100, sha="a" * 64, mode=0o644, entropy=4.2):
    return Fingerprint(size=size, sha256=sha, mode=mode, mtime=1.0, entropy=entropy)


class TestJudgement:
    def test_credentials_outrank_everything(self, settings):
        severity, reason = judge("modified", settings.root / ".ssh" / "authorized_keys",
                                 make_print(), make_print(sha="b" * 64), settings)
        assert severity == CRITICAL
        assert "credentials" in reason

    def test_gaining_the_execute_bit_is_critical(self, settings):
        before = make_print(mode=0o644)
        after = make_print(mode=0o755, sha="b" * 64)
        severity, reason = judge("modified", settings.root / "note.txt", before, after, settings)
        assert severity == CRITICAL
        assert "executable" in reason

    def test_content_turning_random_is_critical(self, settings):
        before = make_print(entropy=4.1)
        after = make_print(sha="b" * 64, entropy=7.9)
        severity, reason = judge("modified", settings.root / "report.docx.locked",
                                 before, after, settings)
        assert severity == CRITICAL
        assert "unreadable" in reason

    def test_binaries_are_warnings(self, settings):
        severity, _ = judge("modified", settings.root / "tool.exe",
                            make_print(), make_print(sha="b" * 64), settings)
        assert severity == WARNING

    def test_deletion_is_a_warning(self, settings):
        severity, _ = judge("deleted", settings.root / "notes.txt", make_print(), None, settings)
        assert severity == WARNING

    def test_truncation_is_a_warning(self, settings):
        severity, reason = judge("modified", settings.root / "notes.txt",
                                 make_print(size=50_000), make_print(size=12, sha="b" * 64),
                                 settings)
        assert severity == WARNING
        assert "shrank" in reason

    def test_config_files_are_a_notice(self, settings):
        severity, _ = judge("modified", settings.root / "app.yaml",
                            make_print(), make_print(sha="b" * 64), settings)
        assert severity == NOTICE

    def test_an_ordinary_edit_is_just_information(self, settings):
        severity, _ = judge("modified", settings.root / "notes.txt",
                            make_print(), make_print(sha="b" * 64), settings)
        assert severity == INFO

    def test_compressing_an_already_random_file_is_not_flagged(self, settings):
        # Both ends already look random, so there is no jump to report.
        severity, _ = judge("modified", settings.root / "notes.txt",
                            make_print(entropy=7.8), make_print(sha="b" * 64, entropy=7.9),
                            settings)
        assert severity == INFO


# --------------------------------------------------------------------------- #
# The noise filter — the reason this tool is usable
# --------------------------------------------------------------------------- #


class TestNoiseFilter:
    def test_a_new_file_is_reported(self, guard, workspace):
        path = write(workspace / "notes.txt")
        change = guard.examine(str(path))
        assert change is not None
        assert change.action == "created"

    def test_examining_an_unchanged_file_reports_nothing(self, guard, workspace):
        path = write(workspace / "notes.txt")
        guard.examine(str(path))
        assert guard.examine(str(path)) is None

    def test_touching_a_file_reports_nothing(self, guard, workspace):
        """The case that makes a naive watcher unusable.

        Editors, backup tools and build systems update timestamps constantly.
        The operating system calls that a modification; Guard compares the
        bytes and sees that nothing happened.
        """
        path = write(workspace / "notes.txt")
        guard.examine(str(path))
        os.utime(path, (time.time() + 500, time.time() + 500))
        assert guard.examine(str(path)) is None

    def test_rewriting_identical_content_reports_nothing(self, guard, workspace):
        path = write(workspace / "notes.txt", "same bytes")
        guard.examine(str(path))
        path.write_text("same bytes")  # save with no edits
        assert guard.examine(str(path)) is None

    def test_a_real_edit_is_reported(self, guard, workspace):
        path = write(workspace / "notes.txt", "before")
        guard.examine(str(path))
        path.write_text("after")
        change = guard.examine(str(path))
        assert change is not None
        assert change.action == "modified"

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no execute bit")
    def test_permission_change_alone_is_still_reported(self, guard, workspace):
        """Same bytes, so the hash matches — but this one must not be dropped."""
        path = write(workspace / "run.sh")
        guard.examine(str(path))
        os.chmod(path, 0o755)
        change = guard.examine(str(path))
        assert change is not None
        assert change.action == "permissions"
        assert change.severity == CRITICAL

    def test_deletion_is_reported_and_forgets_the_file(self, guard, workspace):
        path = write(workspace / "notes.txt")
        guard.examine(str(path))
        path.unlink()
        change = guard.examine(str(path))
        assert change.action == "deleted"
        assert guard.db.get_file(str(path)) is None

    def test_a_temporary_file_that_never_existed_is_not_logged(self, guard, workspace):
        # Created and removed between the notification and our look at it.
        assert guard.examine(str(workspace / "vanished.tmp")) is None

    def test_ignored_files_are_never_examined(self, guard, workspace):
        path = write(workspace / ".git" / "HEAD", "ref: refs/heads/main")
        assert guard.examine(str(path)) is None

    def test_a_move_is_reported_once_and_repoints_the_record(self, guard, workspace):
        source = write(workspace / "old.txt")
        guard.examine(str(source))
        destination = workspace / "new.txt"
        source.rename(destination)

        change = guard.examine(str(source), hint="moved", destination=str(destination))
        assert change.action == "moved"
        assert change.detail == str(destination)
        assert guard.db.get_file(str(source)) is None
        assert guard.db.get_file(str(destination)) is not None


# --------------------------------------------------------------------------- #
# Burst detection
# --------------------------------------------------------------------------- #


def scrambled_change(path, before_entropy=4.2, after_entropy=7.9):
    return Change(
        ts="2026-01-01T00:00:00+00:00", path=path, action="modified",
        severity=CRITICAL, reason="",
        before=make_print(entropy=before_entropy),
        after=make_print(sha="b" * 64, entropy=after_entropy),
    )


class TestBurstDetector:
    @pytest.fixture
    def detector(self, settings):
        settings.burst_threshold = 5
        return BurstDetector(settings)

    def test_stays_quiet_below_the_threshold(self, detector):
        for i in range(4):
            assert detector.observe(scrambled_change(f"/f{i}")) is None

    def test_fires_once_the_threshold_is_crossed(self, detector):
        alert = None
        for i in range(5):
            alert = detector.observe(scrambled_change(f"/f{i}")) or alert
        assert alert is not None
        assert "ransomware" in alert

    def test_the_same_file_repeatedly_is_not_a_burst(self, detector):
        for _ in range(20):
            assert detector.observe(scrambled_change("/only-one")) is None

    def test_a_build_writing_many_readable_files_is_ignored(self, detector):
        """Volume alone must not be enough, or every compile raises an alarm."""
        for i in range(40):
            change = scrambled_change(f"/build/out{i}.js", before_entropy=4.0, after_entropy=4.6)
            assert detector.observe(change) is None

    def test_bulk_copying_media_is_ignored(self, detector):
        # Photos and archives are already near-random; that says nothing.
        for i in range(40):
            change = scrambled_change(f"/photos/img{i}.jpg", before_entropy=7.8)
            assert detector.observe(change) is None

    def test_ordinary_activity_beforehand_cannot_mask_a_sweep(self, detector):
        """The bug this test exists for.

        An earlier version counted every busy file and asked what fraction
        looked encrypted. A handful of innocent edits just before an attack
        pushed the fraction under the bar and the alert never fired.
        """
        for i in range(30):
            detector.observe(scrambled_change(f"/normal{i}.txt", after_entropy=4.4))

        alert = None
        for i in range(5):
            alert = detector.observe(scrambled_change(f"/victim{i}.txt")) or alert
        assert alert is not None

    def test_the_first_alert_is_never_swallowed_by_the_cooldown(self, settings):
        """``time.monotonic()`` counts from boot, so 0.0 is a real timestamp.

        Using it as a "never alerted" marker suppressed the very first alert
        during the first minute of system uptime.
        """
        settings.burst_threshold = 3
        detector = BurstDetector(settings)
        assert detector._last_alert is None

        alert = None
        for i in range(3):
            alert = detector.observe(scrambled_change(f"/f{i}")) or alert
        assert alert is not None

    def test_it_does_not_repeat_itself(self, detector):
        for i in range(5):
            detector.observe(scrambled_change(f"/f{i}"))
        # Still under attack, but one alert is the signal; sixty is noise.
        for i in range(5, 40):
            assert detector.observe(scrambled_change(f"/f{i}")) is None


# --------------------------------------------------------------------------- #
# Baseline and offline audit
# --------------------------------------------------------------------------- #


class TestAudit:
    def test_baseline_covers_the_tree_and_skips_ignored_folders(self, guard, workspace):
        write(workspace / "a.txt")
        write(workspace / "src" / "b.py")
        write(workspace / ".git" / "config")
        write(workspace / "node_modules" / "pkg" / "index.js")

        assert guard.baseline() == 2
        assert guard.db.get_meta("baseline_taken") is not None

    def test_a_clean_tree_audits_clean(self, guard, workspace):
        write(workspace / "a.txt")
        guard.baseline()
        result = guard.audit()
        assert result == {"added": [], "changed": [], "removed": []}

    def test_audit_finds_changes_made_while_guard_was_not_running(self, guard, workspace):
        """The gap a live watcher cannot cover on its own."""
        write(workspace / "keep.txt")
        write(workspace / "edit.txt", "original")
        write(workspace / "gone.txt")
        guard.baseline()

        (workspace / "edit.txt").write_text("tampered")
        (workspace / "gone.txt").unlink()
        write(workspace / "planted.sh", "#!/bin/sh\n")

        result = guard.audit()
        assert [p for p, _ in result["added"]] == [str(workspace / "planted.sh")]
        assert [p for p, _, _ in result["changed"]] == [str(workspace / "edit.txt")]
        assert [p for p, _ in result["removed"]] == [str(workspace / "gone.txt")]

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no execute bit")
    def test_audit_notices_a_permission_change_with_identical_content(self, guard, workspace):
        path = write(workspace / "run.sh")
        guard.baseline()
        os.chmod(path, 0o755)

        changed = guard.audit()["changed"]
        assert len(changed) == 1
        _, before, after = changed[0]
        assert before.sha256 == after.sha256  # same bytes
        assert stat.S_IMODE(before.mode) != stat.S_IMODE(after.mode)


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #


class TestDatabase:
    @pytest.fixture
    def db(self, tmp_path):
        instance = Database(tmp_path / "test.db")
        yield instance
        instance.close()

    def test_round_trip(self, db):
        db.put_file("/a.txt", make_print())
        stored = db.get_file("/a.txt")
        assert stored.sha256 == "a" * 64
        assert stored.size == 100

    def test_unknown_path_reads_as_none(self, db):
        assert db.get_file("/nope") is None

    def test_writing_the_same_path_twice_updates_rather_than_duplicates(self, db):
        db.put_file("/a.txt", make_print(size=1))
        db.put_file("/a.txt", make_print(size=2))
        assert db.file_count() == 1
        assert db.get_file("/a.txt").size == 2

    def test_events_are_returned_in_order_after_a_cursor(self, db):
        for i in range(5):
            db.add_event(Change(ts=f"2026-01-0{i + 1}", path=f"/f{i}", action="modified",
                                severity=INFO, reason=""))
        first_two = db.events_since(0, limit=2)
        assert [e["path"] for e in first_two] == ["/f0", "/f1"]
        assert [e["path"] for e in db.events_since(first_two[-1]["id"])] == ["/f2", "/f3", "/f4"]

    def test_latest_event_id_on_an_empty_log_is_zero(self, db):
        assert db.latest_event_id() == 0

    def test_severity_counts_cover_every_level(self, db):
        db.add_event(Change(ts="2026-01-01", path="/a", action="modified",
                            severity=CRITICAL, reason=""))
        counts = db.severity_counts()
        assert counts[CRITICAL] == 1
        assert counts[INFO] == 0  # present, not missing

    def test_alerts_are_kept_out_of_the_busiest_paths_list(self, db):
        db.add_event(Change(ts="2026-01-01", path="/root", action="alert",
                            severity=CRITICAL, reason="burst"))
        db.add_event(Change(ts="2026-01-01", path="/real.txt", action="modified",
                            severity=INFO, reason=""))
        assert [entry["path"] for entry in db.busiest_paths()] == ["/real.txt"]


# --------------------------------------------------------------------------- #
# The live watcher, end to end
# --------------------------------------------------------------------------- #


class TestLiveWatcher:
    """Two tests that start a real watchdog observer.

    Kept few and generous with timing, because filesystem notifications are
    inherently racy — the logic they cover is tested directly elsewhere.
    """

    def wait_for(self, predicate, timeout=6.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.1)
        return False

    def test_a_real_edit_flows_through_to_a_listener(self, guard, workspace):
        seen = []
        guard.listeners.append(seen.append)
        guard.start()
        time.sleep(0.4)  # let the observer settle before touching anything

        write(workspace / "notes.txt", "hello")
        assert self.wait_for(lambda: any(c.path.endswith("notes.txt") for c in seen))

    def test_one_save_produces_one_event(self, guard, workspace):
        """Debouncing, end to end.

        Writing a file usually emits several notifications. If they were not
        coalesced this would record three or four events for one save.
        """
        path = write(workspace / "notes.txt", "one")
        guard.examine(str(path))

        seen = []
        guard.listeners.append(seen.append)
        guard.start()
        time.sleep(0.4)

        path.write_text("two")
        assert self.wait_for(lambda: len(seen) >= 1)
        time.sleep(1.0)  # give any stragglers a chance to arrive
        assert len([c for c in seen if c.path == str(path)]) == 1


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #


class TestFormatting:
    @pytest.mark.parametrize(
        "value,expected",
        [(0, "0 B"), (999, "999 B"), (1024, "1.0 KB"), (1536, "1.5 KB"),
         (1048576, "1.0 MB"), (None, "—")],
    )
    def test_human_size(self, value, expected):
        assert human_size(value) == expected
