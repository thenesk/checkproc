"""Tests for checkproc.py — one or more tests per CLI argument."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import psutil
import pytest
import requests

import checkproc


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

FAKE_EXE = "/usr/bin/fakecmd"
FAKE_HASH = "ab" * 32  # 64-char hex string

VT_CLEAN = {
    "data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "undetected": 70, "harmless": 0,
        "suspicious": 0, "timeout": 0, "failure": 0,
        "confirmed-timeout": 0, "type-unsupported": 0,
    }}}
}

def make_vt_response(status_code=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or VT_CLEAN
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
    return resp


def seed_db(conn, path, sha256, signed=False, authority=None,
            vt_malicious=0, vt_total=70, hours_ago=0):
    """Insert a row into the test database with controllable age."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    conn.execute(
        """INSERT INTO executables
           (path, sha256, signed, signature_authority,
            vt_malicious, vt_total, first_seen, last_seen, last_checked)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (path, sha256, int(signed), authority, vt_malicious, vt_total,
         ts, ts, ts),
    )
    conn.commit()


@pytest.fixture
def tmp_keyfile(tmp_path):
    kf = tmp_path / ".vtkey"
    kf.write_text("test-api-key-1234\n")
    return str(kf)


@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / ".checkproc.sqlite")
    conn = checkproc.db_open(db_path)
    yield db_path, conn
    conn.close()


@pytest.fixture
def fake_unsigned_exe(tmp_path):
    """Create a real file so sha256_of_file works on it."""
    exe = tmp_path / "unsigned_binary"
    exe.write_bytes(b"fake executable content")
    return str(exe)


def run_main(argv, monkeypatch):
    """Run checkproc.main() with the given argv, catching SystemExit."""
    monkeypatch.setattr("sys.argv", ["checkproc"] + argv)
    with pytest.raises(SystemExit) as exc_info:
        checkproc.main()
    return exc_info.value.code


# ---------------------------------------------------------------------------
# --keyfile
# ---------------------------------------------------------------------------

class TestKeyfile:
    def test_reads_custom_keyfile(self, tmp_keyfile):
        key = checkproc.get_api_key(tmp_keyfile)
        assert key == "test-api-key-1234"

    def test_missing_keyfile_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            checkproc.get_api_key(str(tmp_path / "nonexistent"))

    def test_empty_keyfile_exits(self, tmp_path):
        kf = tmp_path / ".vtkey"
        kf.write_text("  \n")
        with pytest.raises(SystemExit):
            checkproc.get_api_key(str(kf))

    def test_keyfile_not_needed_when_all_signed(
        self, tmp_path, fake_unsigned_exe, monkeypatch
    ):
        """API key file shouldn't be required when all binaries are signed."""
        db_path = str(tmp_path / "test.sqlite")
        bad_keyfile = str(tmp_path / "nonexistent_key")

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "signed")]
        })
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("signed", "Apple Root CA"))
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)

        code = run_main(["--keyfile", bad_keyfile, "--db", db_path], monkeypatch)
        assert code == 0


# ---------------------------------------------------------------------------
# --check-signed
# ---------------------------------------------------------------------------

class TestCheckSigned:
    def test_signed_skipped_by_default(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "signed_app")]
        })
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("signed", "Apple Root CA"))
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        mock_vt = MagicMock()
        monkeypatch.setattr("checkproc.query_virustotal", mock_vt)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db",
        ], monkeypatch)
        assert code == 0
        mock_vt.assert_not_called()

    def test_check_signed_queries_vt(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "signed_app")]
        })
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("signed", "Apple Root CA"))
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--check-signed",
        ], monkeypatch)
        assert code == 0


# ---------------------------------------------------------------------------
# --db
# ---------------------------------------------------------------------------

class TestDb:
    def test_custom_db_path(self, tmp_path, tmp_keyfile, fake_unsigned_exe, monkeypatch):
        db_path = str(tmp_path / "custom.sqlite")
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path,
        ], monkeypatch)
        assert code == 0
        assert os.path.exists(db_path)

        # Verify the row was written
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM executables").fetchone()
        assert row["sha256"] == FAKE_HASH
        assert row["vt_malicious"] == 0
        conn.close()


# ---------------------------------------------------------------------------
# --no-db
# ---------------------------------------------------------------------------

class TestNoDb:
    def test_no_db_skips_database(
        self, tmp_path, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        db_path = str(tmp_path / "should_not_exist.sqlite")
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--db", db_path,
        ], monkeypatch)
        assert code == 0
        assert not os.path.exists(db_path)


# ---------------------------------------------------------------------------
# --read-only
# ---------------------------------------------------------------------------

class TestReadOnly:
    def test_read_only_uses_cache(self, tmp_db, tmp_keyfile, monkeypatch):
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        mock_vt = MagicMock()
        monkeypatch.setattr("checkproc.query_virustotal", mock_vt)
        mock_sig = MagicMock()
        monkeypatch.setattr("checkproc.verify_signature", mock_sig)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--read-only",
        ], monkeypatch)
        assert code == 0
        mock_vt.assert_not_called()
        mock_sig.assert_not_called()

    def test_read_only_does_not_write(self, tmp_db, tmp_keyfile, monkeypatch):
        db_path, conn = tmp_db
        # No seed — cache miss, should do a check but not write

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--read-only",
        ], monkeypatch)
        assert code == 0
        row = conn.execute("SELECT * FROM executables").fetchone()
        assert row is None

    def test_read_only_missing_db_warns(self, tmp_path, tmp_keyfile, monkeypatch, capsys):
        db_path = str(tmp_path / "nonexistent.sqlite")
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {})
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--read-only",
        ], monkeypatch)
        assert code == 0
        assert "Database not found" in capsys.readouterr().err
        assert not os.path.exists(db_path)


# ---------------------------------------------------------------------------
# --write-only
# ---------------------------------------------------------------------------

class TestWriteOnly:
    def test_write_only_ignores_cache(self, tmp_db, tmp_keyfile, monkeypatch):
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (3, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--write-only",
        ], monkeypatch)
        assert code == 1  # flagged

        row = conn.execute("SELECT * FROM executables").fetchone()
        assert row["vt_malicious"] == 3


# ---------------------------------------------------------------------------
# --network-only
# ---------------------------------------------------------------------------

class TestNetworkOnly:
    def test_filters_to_network_pids(self, tmp_keyfile, monkeypatch, fake_unsigned_exe):
        net_exe = fake_unsigned_exe
        local_exe = "/usr/bin/local_only"

        def fake_collect(network_only=False, **kw):
            if network_only:
                return {net_exe: [(100, "networked")]}
            return {
                net_exe: [(100, "networked")],
                local_exe: [(200, "local")],
            }

        monkeypatch.setattr("checkproc.collect_processes", fake_collect)
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        vt_paths = []
        def fake_vt(*a, **kw):
            vt_paths.append(a[0])  # sha256 — same for all, so track call count
            return (0, 70)
        monkeypatch.setattr("checkproc.query_virustotal", fake_vt)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--network-only",
        ], monkeypatch)
        assert code == 0
        assert len(vt_paths) == 1, "Only the network-connected binary should be checked"


# ---------------------------------------------------------------------------
# --pid
# ---------------------------------------------------------------------------

class TestPid:
    def test_filters_by_pid(self, tmp_keyfile, fake_unsigned_exe, monkeypatch):
        def fake_collect(filter_pids=None, **kw):
            if filter_pids and 100 in filter_pids:
                return {fake_unsigned_exe: [(100, "target")]}
            return {}

        monkeypatch.setattr("checkproc.collect_processes", fake_collect)
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--pid", "100",
        ], monkeypatch)
        assert code == 0

    def test_warns_on_missing_pid(self, tmp_keyfile, monkeypatch, capsys):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {})

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--pid", "99999",
        ], monkeypatch)
        assert code == 0
        assert "PID 99999 not found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# --path
# ---------------------------------------------------------------------------

class TestPath:
    def test_filters_by_path(self, tmp_keyfile, fake_unsigned_exe, monkeypatch):
        real = os.path.realpath(fake_unsigned_exe)

        def fake_collect(filter_paths=None, **kw):
            if filter_paths and real in filter_paths:
                return {fake_unsigned_exe: [(100, "target")]}
            return {}

        monkeypatch.setattr("checkproc.collect_processes", fake_collect)
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--path", fake_unsigned_exe,
        ], monkeypatch)
        assert code == 0

    def test_scans_non_running_path(self, tmp_keyfile, fake_unsigned_exe, monkeypatch):
        """--path should scan files even if no process is running them."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {})
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        vt_called = []
        def fake_vt(*a, **kw):
            vt_called.append(a[0])
            return (0, 70)
        monkeypatch.setattr("checkproc.query_virustotal", fake_vt)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--path", fake_unsigned_exe,
        ], monkeypatch)
        assert code == 0
        assert len(vt_called) == 1, "VT should be called for the non-running binary"

    def test_warns_on_missing_path(self, tmp_keyfile, monkeypatch, capsys):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {})

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db",
            "--path", "/nonexistent/binary",
        ], monkeypatch)
        assert code == 0
        assert "Path not found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# --timeout
# ---------------------------------------------------------------------------

class TestTimeout:
    def test_timeout_passed_to_requests(self, monkeypatch):
        mock_get = MagicMock(return_value=make_vt_response(200, VT_CLEAN))
        monkeypatch.setattr("requests.get", mock_get)

        result = checkproc.query_virustotal(FAKE_HASH, "key", timeout=10)
        assert result == (0, 70)
        _, kwargs = mock_get.call_args
        assert kwargs["timeout"] == 10

    def test_default_timeout_is_30(self):
        assert checkproc.DEFAULT_HTTP_TIMEOUT == 30

    def test_timeout_exception_retries_and_gives_up(self, monkeypatch):
        mock_get = MagicMock(side_effect=requests.exceptions.Timeout())
        monkeypatch.setattr("requests.get", mock_get)

        result = checkproc.query_virustotal(FAKE_HASH, "key", timeout=1)
        assert result is None
        assert mock_get.call_count == checkproc.MAX_VT_RETRIES


# ---------------------------------------------------------------------------
# --rate-limit
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_rate_limit_controls_delay(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        """--rate-limit should set the delay between VT requests."""
        sleep_args = []
        monkeypatch.setattr("time.sleep", lambda s: sleep_args.append(s))
        # Two executables so the rate limit delay fires between them
        exe2 = fake_unsigned_exe + "2"
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app1")],
            exe2: [(200, "app2")],
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--rate-limit", "7",
        ], monkeypatch)
        assert code == 0
        assert 7 in sleep_args


# ---------------------------------------------------------------------------
# --max-age
# ---------------------------------------------------------------------------

class TestMaxAge:
    def test_fresh_entry_is_cached(self, tmp_db, tmp_keyfile, monkeypatch):
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70,
                hours_ago=1)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        mock_vt = MagicMock()
        monkeypatch.setattr("checkproc.query_virustotal", mock_vt)
        mock_sig = MagicMock()
        monkeypatch.setattr("checkproc.verify_signature", mock_sig)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--max-age", "24",
        ], monkeypatch)
        assert code == 0
        mock_vt.assert_not_called()

    def test_stale_entry_is_rechecked(self, tmp_db, tmp_keyfile, monkeypatch):
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70,
                hours_ago=48)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--max-age", "24",
        ], monkeypatch)
        assert code == 0

        # Verify last_checked was updated
        row = conn.execute("SELECT * FROM executables").fetchone()
        last_checked = datetime.fromisoformat(row["last_checked"])
        age = datetime.now(timezone.utc) - last_checked
        assert age.total_seconds() < 60  # just updated

    def test_max_age_checks_last_checked_not_last_seen(self, tmp_db, tmp_keyfile, monkeypatch):
        """Ensure --max-age compares against last_checked, not last_seen."""
        db_path, conn = tmp_db
        # Insert with last_checked 48h ago, but we'll touch last_seen to now
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70,
                hours_ago=48)
        checkproc.db_touch_last_seen(conn, FAKE_EXE, FAKE_HASH)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--max-age", "24",
        ], monkeypatch)
        assert code == 0

        # It should have been rechecked despite last_seen being fresh
        row = conn.execute("SELECT * FROM executables").fetchone()
        last_checked = datetime.fromisoformat(row["last_checked"])
        age = datetime.now(timezone.utc) - last_checked
        assert age.total_seconds() < 60


# ---------------------------------------------------------------------------
# --force
# ---------------------------------------------------------------------------

class TestForce:
    def test_force_ignores_cache(self, tmp_db, tmp_keyfile, monkeypatch):
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        vt_called = []
        def fake_vt(*a, **kw):
            vt_called.append(True)
            return (0, 70)
        monkeypatch.setattr("checkproc.query_virustotal", fake_vt)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--force",
        ], monkeypatch)
        assert code == 0
        assert len(vt_called) == 1


# ---------------------------------------------------------------------------
# -q / --quiet
# ---------------------------------------------------------------------------

class TestQuiet:
    def test_quiet_suppresses_normal_output(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "-q",
        ], monkeypatch)
        assert code == 0
        assert capsys.readouterr().out == ""

    def test_quiet_still_shows_detections(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "malware")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (5, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--quiet",
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "flagged as malicious" in out
        assert fake_unsigned_exe in out


# ---------------------------------------------------------------------------
# Exit code
# ---------------------------------------------------------------------------

class TestExitCode:
    def test_exit_0_when_clean(self, tmp_keyfile, fake_unsigned_exe, monkeypatch):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main(["--keyfile", tmp_keyfile, "--no-db"], monkeypatch)
        assert code == 0

    def test_exit_1_when_flagged(self, tmp_keyfile, fake_unsigned_exe, monkeypatch):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "malware")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (5, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main(["--keyfile", tmp_keyfile, "--no-db"], monkeypatch)
        assert code == 1


# ---------------------------------------------------------------------------
# query_virustotal edge cases
# ---------------------------------------------------------------------------

class TestQueryVirustotal:
    def test_404_returns_none(self, monkeypatch):
        monkeypatch.setattr("requests.get",
                            MagicMock(return_value=make_vt_response(404)))
        assert checkproc.query_virustotal(FAKE_HASH, "key") is None

    def test_rate_limit_retries(self, monkeypatch):
        responses = [make_vt_response(429)] + [make_vt_response(200, VT_CLEAN)]
        mock_get = MagicMock(side_effect=responses)
        monkeypatch.setattr("requests.get", mock_get)
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = checkproc.query_virustotal(FAKE_HASH, "key")
        assert result == (0, 70)
        assert mock_get.call_count == 2

    def test_connection_error_retries_and_gives_up(self, monkeypatch):
        mock_get = MagicMock(side_effect=requests.exceptions.ConnectionError())
        monkeypatch.setattr("requests.get", mock_get)

        result = checkproc.query_virustotal(FAKE_HASH, "key")
        assert result is None
        assert mock_get.call_count == checkproc.MAX_VT_RETRIES


# ---------------------------------------------------------------------------
# submit_to_virustotal
# ---------------------------------------------------------------------------

class TestSubmitToVirustotal:
    def test_successful_upload(self, fake_unsigned_exe, monkeypatch):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": {"id": "analysis-123"}}
        resp.raise_for_status = MagicMock()
        monkeypatch.setattr("requests.post", MagicMock(return_value=resp))

        result = checkproc.submit_to_virustotal(fake_unsigned_exe, "key")
        assert result == "analysis-123"

    def test_file_too_large(self, tmp_path, monkeypatch):
        big_file = tmp_path / "big"
        big_file.write_bytes(b"\0")
        monkeypatch.setattr("os.path.getsize",
                            lambda p: 33 * 1024 * 1024)

        result = checkproc.submit_to_virustotal(str(big_file), "key")
        assert result is None

    def test_connection_error(self, fake_unsigned_exe, monkeypatch):
        monkeypatch.setattr("requests.post",
                            MagicMock(side_effect=requests.exceptions.ConnectionError()))
        result = checkproc.submit_to_virustotal(fake_unsigned_exe, "key")
        assert result is None

    def test_http_error(self, fake_unsigned_exe, monkeypatch):
        resp = MagicMock()
        resp.status_code = 403
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
        monkeypatch.setattr("requests.post", MagicMock(return_value=resp))

        result = checkproc.submit_to_virustotal(fake_unsigned_exe, "key")
        assert result is None


# ---------------------------------------------------------------------------
# --submit
# ---------------------------------------------------------------------------

class TestSubmit:
    def _setup(self, monkeypatch, fake_unsigned_exe, tmp_keyfile):
        """Common setup: one unsigned exe, VT returns 404."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: None)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)
        monkeypatch.setattr("time.sleep", lambda s: None)

    def test_submit_prompts_and_uploads_on_yes(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        self._setup(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        monkeypatch.setattr("checkproc.confirm_upload", lambda p, y: True)
        upload_mock = MagicMock(return_value="analysis-123")
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--submit",
        ], monkeypatch)
        assert code == 0
        upload_mock.assert_called_once()

    def test_submit_skips_on_no(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        self._setup(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        monkeypatch.setattr("checkproc.confirm_upload", lambda p, y: False)
        upload_mock = MagicMock()
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--submit",
        ], monkeypatch)
        assert code == 0
        upload_mock.assert_not_called()

    def test_no_upload_without_submit_flag(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        self._setup(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        upload_mock = MagicMock()
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db",
        ], monkeypatch)
        assert code == 0
        upload_mock.assert_not_called()


# ---------------------------------------------------------------------------
# --yes
# ---------------------------------------------------------------------------

class TestYes:
    def test_yes_uploads_without_prompting(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: None)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)
        monkeypatch.setattr("time.sleep", lambda s: None)

        upload_mock = MagicMock(return_value="analysis-456")
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)
        # input() should NOT be called — if it is, raise to fail the test
        monkeypatch.setattr("builtins.input",
                            lambda prompt: (_ for _ in ()).throw(AssertionError("input() called")))

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--yes",
        ], monkeypatch)
        assert code == 0
        upload_mock.assert_called_once()

    def test_yes_implies_submit(self):
        import sys
        orig = sys.argv
        try:
            sys.argv = ["checkproc", "--yes", "--no-db"]
            args = checkproc.parse_args()
            assert args.submit is True
        finally:
            sys.argv = orig


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------

class TestSummary:
    def test_shows_unsigned_and_detections(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "mal")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (3, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        run_main(["--keyfile", tmp_keyfile, "--no-db"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 unsigned" in out
        assert "1 detection(s)" in out

    def test_shows_signed_strict_skipped(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("signed", "Apple Root CA"))

        run_main(["--keyfile", tmp_keyfile, "--no-db"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 signed (strict), skipped" in out

    def test_shows_non_strict_count(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("non-strict", "Software Signing"))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        run_main(["--keyfile", tmp_keyfile, "--no-db"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 signed (non-strict)" in out

    def test_shows_cached_count_and_force_hint(
        self, tmp_db, tmp_keyfile, monkeypatch, capsys
    ):
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, vt_malicious=0, vt_total=70)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)

        run_main(["--keyfile", tmp_keyfile, "--db", db_path], monkeypatch)
        out = capsys.readouterr().out
        assert "1 result(s) from cache" in out
        assert "--force" in out

    def test_shows_unknown_count_and_submit_hint(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: None)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        run_main(["--keyfile", tmp_keyfile, "--no-db"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 not in VirusTotal database" in out
        assert "--submit" in out

    def test_no_submit_hint_when_submit_active(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: None)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)
        monkeypatch.setattr("checkproc.confirm_upload", lambda p, y: False)

        run_main(["--keyfile", tmp_keyfile, "--no-db", "--submit"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 not in VirusTotal database" in out
        assert "Rerun with --submit" not in out

    def test_shows_submitted_count(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: None)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)
        monkeypatch.setattr("time.sleep", lambda s: None)
        monkeypatch.setattr("checkproc.submit_to_virustotal",
                            lambda *a, **kw: "analysis-789")

        run_main(["--keyfile", tmp_keyfile, "--no-db", "--yes"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 submitted to VirusTotal" in out

    def test_cached_unknown_counted(
        self, tmp_db, tmp_keyfile, monkeypatch, capsys
    ):
        """Unknown results from cache should be counted in the unknown total."""
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH,
                vt_malicious=None, vt_total=None)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)

        run_main(["--keyfile", tmp_keyfile, "--db", db_path], monkeypatch)
        out = capsys.readouterr().out
        assert "1 not in VirusTotal database" in out
        assert "--submit" in out

    def test_cached_unknown_submitted_with_yes(
        self, tmp_db, tmp_keyfile, monkeypatch, capsys
    ):
        """--yes should upload cached unknowns without prompting."""
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH,
                vt_malicious=None, vt_total=None)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("time.sleep", lambda s: None)
        upload_mock = MagicMock(return_value="analysis-cached")
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--yes",
        ], monkeypatch)
        out = capsys.readouterr().out
        upload_mock.assert_called_once()
        assert "1 submitted to VirusTotal" in out

    def test_cached_unknown_submit_prompts(
        self, tmp_db, tmp_keyfile, monkeypatch, capsys
    ):
        """--submit should prompt for cached unknowns and skip on 'n'."""
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH,
                vt_malicious=None, vt_total=None)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.confirm_upload", lambda p, y: False)
        upload_mock = MagicMock()
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--submit",
        ], monkeypatch)
        upload_mock.assert_not_called()

    def test_cached_signed_not_submitted(
        self, tmp_db, tmp_keyfile, monkeypatch, capsys
    ):
        """Signed binaries cached as unknown should not be submitted."""
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, signed=True,
                authority="Apple Root CA",
                vt_malicious=None, vt_total=None)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        upload_mock = MagicMock()
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        run_main([
            "--keyfile", tmp_keyfile, "--db", db_path, "--yes",
        ], monkeypatch)
        out = capsys.readouterr().out
        upload_mock.assert_not_called()
        assert "Skipped (trusted signature) [CACHED]" in out
        assert "not in VirusTotal database" not in out

    def test_cached_signed_submitted_with_check_signed(
        self, tmp_db, tmp_keyfile, monkeypatch, capsys
    ):
        """--check-signed + --yes should submit cached signed unknowns."""
        db_path, conn = tmp_db
        seed_db(conn, FAKE_EXE, FAKE_HASH, signed=True,
                authority="Apple Root CA",
                vt_malicious=None, vt_total=None)

        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            FAKE_EXE: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("time.sleep", lambda s: None)
        upload_mock = MagicMock(return_value="analysis-signed")
        monkeypatch.setattr("checkproc.submit_to_virustotal", upload_mock)

        run_main([
            "--keyfile", tmp_keyfile, "--db", db_path,
            "--yes", "--check-signed",
        ], monkeypatch)
        upload_mock.assert_called_once()

    def test_check_signed_summary_not_skipped(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """--check-signed: strict-signed should appear in summary without 'skipped'."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("signed", "Apple Root CA"))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (0, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--check-signed",
        ], monkeypatch)
        out = capsys.readouterr().out
        assert "1 signed (strict)" in out
        assert "skipped" not in out
        assert "1 checked against VirusTotal" in out

    def test_checked_count_excludes_uploads(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """Uploads should not inflate the 'checked against VirusTotal' count."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "app")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: None)
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)
        monkeypatch.setattr("time.sleep", lambda s: None)
        monkeypatch.setattr("checkproc.submit_to_virustotal",
                            lambda *a, **kw: "analysis-789")

        run_main(["--keyfile", tmp_keyfile, "--no-db", "--yes"], monkeypatch)
        out = capsys.readouterr().out
        assert "1 checked against VirusTotal" in out
        assert "1 submitted to VirusTotal" in out


# ---------------------------------------------------------------------------
# confirm_upload
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# --kill
# ---------------------------------------------------------------------------

class TestKill:
    def _setup_flagged(self, monkeypatch, fake_unsigned_exe, tmp_keyfile):
        """Common setup: one unsigned exe flagged by VT."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {
            fake_unsigned_exe: [(100, "malware"), (200, "malware2")]
        })
        monkeypatch.setattr("checkproc.sha256_of_file", lambda p: FAKE_HASH)
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (5, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

    def test_kill_with_yes(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        """--kill --yes should kill flagged processes without prompting."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        killed_pids = []
        mock_proc = MagicMock()
        mock_proc.kill = lambda: killed_pids.append(True)

        monkeypatch.setattr("psutil.Process", lambda pid: mock_proc)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill", "--yes",
        ], monkeypatch)
        assert code == 1
        assert len(killed_pids) == 2

    def test_kill_prompts_and_skips_on_no(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        """--kill should prompt and skip when user declines."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        monkeypatch.setattr("checkproc.confirm_kill",
                            lambda path, count, auto: False)
        mock_proc = MagicMock()
        monkeypatch.setattr("psutil.Process", lambda pid: mock_proc)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill",
        ], monkeypatch)
        assert code == 1
        mock_proc.kill.assert_not_called()

    def test_kill_handles_no_such_process(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """--kill should report processes that already exited."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        mock_proc = MagicMock()
        mock_proc.kill.side_effect = psutil.NoSuchProcess(100)
        monkeypatch.setattr("psutil.Process", lambda pid: mock_proc)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill", "--yes",
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "2 process(es) already exited" in out
        assert "Killed" not in out
        assert "Failed" not in out

    def test_kill_handles_access_denied(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """--kill should warn about AccessDenied and suggest sudo."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        mock_proc = MagicMock()
        mock_proc.kill.side_effect = psutil.AccessDenied(100)
        monkeypatch.setattr("psutil.Process", lambda pid: mock_proc)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill", "--yes",
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "Failed to kill 2 process(es) (try sudo)" in out

    def test_kill_skips_non_running_binaries(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        """--kill should skip flagged binaries with no running processes."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {})
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (5, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)
        mock_proc = MagicMock()
        monkeypatch.setattr("psutil.Process", lambda pid: mock_proc)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill", "--yes",
            "--path", fake_unsigned_exe,
        ], monkeypatch)
        assert code == 1
        mock_proc.kill.assert_not_called()

    def test_no_kill_without_flag(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch
    ):
        """Without --kill, no processes should be killed."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        mock_proc = MagicMock()
        monkeypatch.setattr("psutil.Process", lambda pid: mock_proc)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db",
        ], monkeypatch)
        assert code == 1
        mock_proc.kill.assert_not_called()

    def test_kill_shows_killed_count(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """--kill should display the number of killed processes."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        monkeypatch.setattr("psutil.Process", lambda pid: MagicMock())

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill", "--yes",
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "Killed 2 process(es)." in out

    def test_kill_hint_when_flagged_without_kill(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """Hint should suggest --kill when flagged processes exist."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db",
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "Rerun with --kill" in out

    def test_no_kill_hint_when_kill_active(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """No --kill hint when --kill is already active."""
        self._setup_flagged(monkeypatch, fake_unsigned_exe, tmp_keyfile)
        monkeypatch.setattr("psutil.Process", lambda pid: MagicMock())

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db", "--kill", "--yes",
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "Rerun with --kill" not in out

    def test_no_kill_hint_when_no_running_procs(
        self, tmp_keyfile, fake_unsigned_exe, monkeypatch, capsys
    ):
        """No --kill hint when flagged binaries have no running processes."""
        monkeypatch.setattr("checkproc.collect_processes", lambda **kw: {})
        monkeypatch.setattr("checkproc.verify_signature",
                            lambda p: ("unsigned", None))
        monkeypatch.setattr("checkproc.query_virustotal",
                            lambda *a, **kw: (5, 70))
        monkeypatch.setattr("checkproc.DEFAULT_RATE_LIMIT_DELAY", 0)

        code = run_main([
            "--keyfile", tmp_keyfile, "--no-db",
            "--path", fake_unsigned_exe,
        ], monkeypatch)
        assert code == 1
        out = capsys.readouterr().out
        assert "Rerun with --kill" not in out


# ---------------------------------------------------------------------------
# confirm_kill
# ---------------------------------------------------------------------------

class TestConfirmKill:
    def test_auto_yes(self):
        assert checkproc.confirm_kill("/some/path", 2, auto_yes=True) is True

    def test_user_confirms(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "y")
        assert checkproc.confirm_kill("/some/path", 2, auto_yes=False) is True

    def test_user_declines(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        assert checkproc.confirm_kill("/some/path", 2, auto_yes=False) is False

    def test_empty_input_declines(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "")
        assert checkproc.confirm_kill("/some/path", 2, auto_yes=False) is False

    def test_eof_declines(self, monkeypatch):
        monkeypatch.setattr("builtins.input",
                            MagicMock(side_effect=EOFError))
        assert checkproc.confirm_kill("/some/path", 2, auto_yes=False) is False


class TestConfirmUpload:
    def test_auto_yes(self):
        assert checkproc.confirm_upload("/some/path", auto_yes=True) is True

    def test_user_confirms(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "y")
        assert checkproc.confirm_upload("/some/path", auto_yes=False) is True

    def test_user_declines(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        assert checkproc.confirm_upload("/some/path", auto_yes=False) is False

    def test_empty_input_declines(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "")
        assert checkproc.confirm_upload("/some/path", auto_yes=False) is False

    def test_eof_declines(self, monkeypatch):
        monkeypatch.setattr("builtins.input",
                            MagicMock(side_effect=EOFError))
        assert checkproc.confirm_upload("/some/path", auto_yes=False) is False
