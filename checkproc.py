#!/usr/bin/env python3
"""
Check running process executables against the VirusTotal database.
Signed executables are skipped by default.  Runs on Mac only.

Usage:
    echo "your-virustotal-api-key" > .vtkey
    python3 checkproc.py
    python3 checkproc.py --keyfile /path/to/keyfile
    python3 checkproc.py --db /path/to/db.sqlite
    python3 checkproc.py --no-db
    python3 checkproc.py --force
    python3 checkproc.py --pid 1234 5678
    python3 checkproc.py --path /usr/local/bin/suspicious
    python3 checkproc.py --network-only
    python3 checkproc.py --max-age 24
    python3 checkproc.py --timeout 10
    python3 checkproc.py --rate-limit 5
    python3 checkproc.py -q
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

import psutil
import requests

VT_API_URL = "https://www.virustotal.com/api/v3/files"
DEFAULT_RATE_LIMIT_DELAY = 15  # seconds between requests (free API: 4 req/min)
DEFAULT_HTTP_TIMEOUT = 30  # seconds
MAX_VT_RETRIES = 5


# ---------------------------------------------------------------------------
# API key
# ---------------------------------------------------------------------------

def get_api_key(keyfile: str) -> str:
    try:
        with open(keyfile) as f:
            key = f.read().strip()
    except FileNotFoundError:
        print(f"Error: Key file not found: {keyfile}", file=sys.stderr)
        print(f"  echo 'your-api-key' > {keyfile}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Cannot read key file: {keyfile}", file=sys.stderr)
        sys.exit(1)
    if not key:
        print(f"Error: Key file is empty: {keyfile}", file=sys.stderr)
        sys.exit(1)
    return key


# ---------------------------------------------------------------------------
# Hashing / signature / VT
# ---------------------------------------------------------------------------

def sha256_of_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(1 << 16):
                h.update(chunk)
    except (PermissionError, OSError) as e:
        print(e, file=sys.stderr)
        return None
    return h.hexdigest()


def verify_signature(path: str) -> tuple[str, str | None]:
    """Check if a binary has a valid code signature from a trusted developer.

    Returns (status, authority) where status is one of:
      "signed"     — valid strict signature
      "non-strict" — passes codesign but fails --strict (e.g. cryptex binaries)
      "unsigned"   — no valid signature
    and authority is the top-level signer (e.g. "Software Signing") or None.
    """
    try:
        result = subprocess.run(
            ["codesign", "-dv", "--verbose=2", path],
            capture_output=True, text=True, timeout=10,
        )
        # codesign prints info to stderr
        if result.returncode != 0:
            return "unsigned", None

        # Extract the root authority (last Authority= line)
        authorities = []
        for line in result.stderr.splitlines():
            if line.startswith("Authority="):
                authorities.append(line.split("=", 1)[1])

        if not authorities:
            return "unsigned", None

        authority = authorities[-1]

        # Verify the signature is actually valid (not just present)
        verify = subprocess.run(
            ["codesign", "--verify", "--strict", path],
            capture_output=True, timeout=10,
        )
        if verify.returncode == 0:
            return "signed", authority

        # Strict failed — try non-strict
        verify_loose = subprocess.run(
            ["codesign", "--verify", path],
            capture_output=True, timeout=10,
        )
        if verify_loose.returncode == 0:
            return "non-strict", authority

        return "unsigned", None
    except (subprocess.TimeoutExpired, OSError):
        return "unsigned", None


def get_network_pids() -> set[int]:
    """Return the set of PIDs that have network connections or listeners."""
    pids = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.pid:
            pids.add(conn.pid)
    return pids


def collect_processes(
    network_only: bool = False,
    filter_pids: set[int] | None = None,
    filter_paths: set[str] | None = None,
) -> dict[str, list[tuple[int, str]]]:
    """Return a dict mapping executable path -> list of (pid, name)."""
    net_pids = get_network_pids() if network_only else None
    exes: dict[str, list[tuple[int, str]]] = {}
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info
            if network_only and info["pid"] not in net_pids:
                continue
            if filter_pids and info["pid"] not in filter_pids:
                continue
            exe = info.get("exe")
            if not exe or not os.path.isfile(exe):
                continue
            if filter_paths and os.path.realpath(exe) not in filter_paths:
                continue
            exes.setdefault(exe, []).append((info["pid"], info["name"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return exes


def query_virustotal(
    sha256: str, api_key: str, timeout: int = DEFAULT_HTTP_TIMEOUT,
) -> tuple[int, int] | None:
    """Query VT for a hash. Returns (malicious, total) or None."""
    for attempt in range(1, MAX_VT_RETRIES + 1):
        try:
            resp = requests.get(
                f"{VT_API_URL}/{sha256}",
                headers={"x-apikey": api_key},
                timeout=timeout,
            )
        except requests.exceptions.ConnectionError:
            print(f"  [connection error "
                  f"(attempt {attempt}/{MAX_VT_RETRIES})]", file=sys.stderr)
            if attempt == MAX_VT_RETRIES:
                return None
            continue
        except requests.exceptions.Timeout:
            print(f"  [request timed out after {timeout}s "
                  f"(attempt {attempt}/{MAX_VT_RETRIES})]", file=sys.stderr)
            if attempt == MAX_VT_RETRIES:
                return None
            continue
        if resp.status_code == 404:
            return None  # not in VT database
        if resp.status_code == 429:
            if attempt == MAX_VT_RETRIES:
                print(f"  [rate limited — giving up after {MAX_VT_RETRIES} retries]",
                      file=sys.stderr)
                return None
            print(f"  [rate limited — waiting 60s (attempt {attempt}/{MAX_VT_RETRIES})]",
                  file=sys.stderr)
            time.sleep(60)
            continue
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats["malicious"], sum(stats.values())
    return None  # unreachable, but satisfies type checker


MAX_UPLOAD_SIZE = 32 * 1024 * 1024  # 32 MB


def submit_to_virustotal(
    path: str, api_key: str, timeout: int = DEFAULT_HTTP_TIMEOUT,
) -> str | None:
    """Upload a file to VT for scanning. Returns analysis ID or None."""
    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        print(f"  [upload skipped: {e}]", file=sys.stderr)
        return None

    if file_size > MAX_UPLOAD_SIZE:
        print(f"  [upload skipped: file too large "
              f"({file_size / 1024 / 1024:.1f} MB > 32 MB)]", file=sys.stderr)
        return None

    try:
        with open(path, "rb") as f:
            resp = requests.post(
                VT_API_URL,
                headers={"x-apikey": api_key},
                files={"file": (os.path.basename(path), f)},
                timeout=timeout,
            )
        resp.raise_for_status()
        return resp.json()["data"]["id"]
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout) as e:
        print(f"  [upload failed: {e}]", file=sys.stderr)
        return None
    except requests.exceptions.HTTPError:
        print(f"  [upload failed: HTTP {resp.status_code}]", file=sys.stderr)
        return None
    except (OSError, KeyError) as e:
        print(f"  [upload failed: {e}]", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_SCHEMA = """\
CREATE TABLE IF NOT EXISTS executables (
    path                TEXT    NOT NULL,
    sha256              TEXT    NOT NULL,
    signed              INTEGER NOT NULL,
    signature_authority TEXT,
    vt_malicious        INTEGER,
    vt_total            INTEGER,
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,
    last_checked        TEXT    NOT NULL,
    PRIMARY KEY (path, sha256)
);
"""

def db_open(db_path: str, read_only: bool = False) -> sqlite3.Connection | None:
    if read_only and not os.path.exists(db_path):
        print(f"Warning: Database not found: {db_path}", file=sys.stderr)
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(DB_SCHEMA)
    conn.commit()
    return conn


def db_lookup(
    conn: sqlite3.Connection, path: str, sha256: str, max_age_hours: int | None = None,
) -> sqlite3.Row | None:
    """Return a row if this path+hash combo exists (and isn't stale), else None."""
    row = conn.execute(
        "SELECT * FROM executables WHERE path = ? AND sha256 = ?",
        (path, sha256),
    ).fetchone()
    if row is None:
        return None
    if max_age_hours is not None:
        last_checked = row["last_checked"]
        if not last_checked:
            return None
        age = datetime.now(timezone.utc) - datetime.fromisoformat(last_checked)
        if age.total_seconds() > max_age_hours * 3600:
            return None
    return row


def db_upsert(
    conn: sqlite3.Connection,
    path: str,
    sha256: str,
    signed: bool,
    authority: str | None,
    vt_malicious: int | None,
    vt_total: int | None,
    checked: bool = False,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    last_checked = now if checked else ""
    conn.execute(
        """
        INSERT INTO executables
            (path, sha256, signed, signature_authority,
             vt_malicious, vt_total, first_seen, last_seen, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path, sha256) DO UPDATE SET
            signed = excluded.signed,
            signature_authority = excluded.signature_authority,
            vt_malicious = excluded.vt_malicious,
            vt_total = excluded.vt_total,
            last_seen = excluded.last_seen,
            last_checked = CASE
                WHEN excluded.last_checked = '' THEN executables.last_checked
                ELSE excluded.last_checked
            END
        """,
        (path, sha256, int(signed), authority, vt_malicious, vt_total,
         now, now, last_checked),
    )
    conn.commit()


def db_touch_last_seen(conn: sqlite3.Connection, path: str, sha256: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE executables SET last_seen = ? WHERE path = ? AND sha256 = ?",
        (now, path, sha256),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_keyfile = os.path.join(script_dir, ".vtkey")
    default_db = os.path.join(script_dir, ".checkproc.sqlite")

    parser = argparse.ArgumentParser(
        description="Check unsigned running processes against VirusTotal."
    )
    parser.add_argument(
        "--keyfile",
        default=default_keyfile,
        help=f"Path to file containing VT API key (default: {default_keyfile})",
    )
    parser.add_argument(
        "--check-signed",
        action="store_true",
        help="Also check signed executables against VirusTotal (by default, "
             "validly signed binaries are skipped)",
    )
    parser.add_argument(
        "--db",
        default=default_db,
        help=f"Path to SQLite database (default: {default_db})",
    )

    db_mode = parser.add_mutually_exclusive_group()
    db_mode.add_argument(
        "--no-db",
        action="store_true",
        help="Disable the database entirely",
    )
    db_mode.add_argument(
        "--read-only",
        action="store_true",
        help="Read from the database but do not write new results",
    )
    db_mode.add_argument(
        "--write-only",
        action="store_true",
        help="Write results to the database but do not read cached entries "
             "(always perform fresh checks)",
    )

    parser.add_argument(
        "--network-only",
        action="store_true",
        help="Only scan processes with active network connections or listeners (use sudo for all)",
    )
    parser.add_argument(
        "--pid",
        type=int, nargs="+", metavar="PID",
        help="Only scan the specified process ID(s)",
    )
    parser.add_argument(
        "--path",
        nargs="+", metavar="PATH",
        help="Scan the specified executable path(s)",
    )
    parser.add_argument(
        "--timeout",
        type=int, default=DEFAULT_HTTP_TIMEOUT, metavar="SECS",
        help=f"HTTP timeout for VirusTotal requests in seconds "
             f"(default: {DEFAULT_HTTP_TIMEOUT})",
    )
    parser.add_argument(
        "--rate-limit",
        type=int, default=DEFAULT_RATE_LIMIT_DELAY, metavar="SECS",
        help=f"Delay between VirusTotal requests in seconds "
             f"(default: {DEFAULT_RATE_LIMIT_DELAY})",
    )
    parser.add_argument(
        "--max-age",
        type=int, default=None, metavar="HOURS",
        help="Re-check cached entries whose last VT/signature check is older "
             "than this many hours",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Perform VT/signature checks even if the binary is already in "
             "the database",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only produce output when detections are found",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Prompt to upload binaries not found in the VT database",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Auto-confirm prompts without asking (implies --submit)",
    )
    parser.add_argument(
        "--kill",
        action="store_true",
        help="Kill processes whose executables are flagged as malicious",
    )

    args = parser.parse_args()
    if args.yes:
        args.submit = True
    return args


def confirm_upload(path: str, auto_yes: bool) -> bool:
    """Ask the user whether to upload a file. Returns True if confirmed."""
    if auto_yes:
        return True
    try:
        answer = input(f"  Submit {path} to VirusTotal? [y/N] ")
        return answer.strip().lower() == "y"
    except EOFError:
        return False


def confirm_kill(path: str, proc_count: int, auto_yes: bool) -> bool:
    """Ask the user whether to kill processes for a flagged executable."""
    if auto_yes:
        return True
    try:
        answer = input(
            f"  Kill {proc_count} process(es) for {path}? [y/N] "
        )
        return answer.strip().lower() == "y"
    except EOFError:
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    api_key: str | None = None
    quiet = args.quiet

    def log(msg: str = "") -> None:
        if not quiet:
            print(msg)

    use_db = not args.no_db
    db_read = use_db and not args.write_only and not args.force
    db_write = use_db and not args.read_only
    conn = db_open(args.db, read_only=args.read_only) if use_db else None

    # If --read-only and db wasn't found, disable db features
    if use_db and conn is None:
        db_read = False
        db_write = False

    filter_pids = set(args.pid) if args.pid else None
    filter_paths = {os.path.realpath(p) for p in args.path} if args.path else None

    if filter_pids or filter_paths:
        scope = "filtered"
    elif args.network_only:
        scope = "network-connected"
    else:
        scope = "running"
    log(f"Collecting {scope} processes...")
    exes = collect_processes(
        network_only=args.network_only,
        filter_pids=filter_pids,
        filter_paths=filter_paths,
    )

    # Warn about --pid values that didn't match any running process
    if filter_pids:
        found_pids: set[int] = set()
        for procs in exes.values():
            for pid, _ in procs:
                found_pids.add(pid)
        for pid in sorted(filter_pids - found_pids):
            print(f"Warning: PID {pid} not found among running processes",
                  file=sys.stderr)

    # --path: add paths that aren't running as standalone entries
    if filter_paths:
        found_realpaths = {os.path.realpath(e) for e in exes}
        for path in sorted(filter_paths - found_realpaths):
            if os.path.isfile(path):
                exes[path] = []  # no running PIDs
            else:
                print(f"Warning: Path not found: {path}", file=sys.stderr)

    log(f"Found {len(exes)} unique executables across {scope} processes.\n")

    log("Checking signatures and querying VirusTotal...")
    log("-" * 72)

    flagged = []
    signed_strict_count = 0
    non_strict_count = 0
    unsigned_count = 0
    cached_count = 0
    checked_count = 0
    unknown_count = 0
    submitted_count = 0
    api_calls = 0  # all VT API requests, for rate limiting

    for i, (exe_path, procs) in enumerate(sorted(exes.items()), 1):
        if procs:
            pids = ", ".join(str(p) for p, _ in procs)
        else:
            pids = "(not running)"
        log(f"[{i}/{len(exes)}] {exe_path}")
        log(f"  PIDs:    {pids}")

        # Hash first — needed for both db lookup and VT query
        sha256 = sha256_of_file(exe_path)
        if sha256 is None:
            log("  Result:  SKIP (unreadable)")
            log()
            continue

        log(f"  SHA-256: {sha256}")

        # Try the database cache
        if db_read and conn:
            row = db_lookup(conn, exe_path, sha256, max_age_hours=args.max_age)
            if row is not None:
                signed = bool(row["signed"])
                authority = row["signature_authority"]
                vt_malicious = row["vt_malicious"]
                vt_total = row["vt_total"]

                sig_label = f"Valid ({authority})" if signed else "No valid signature"
                log(f"  Signed:  {sig_label}")

                if vt_malicious is None:
                    if signed and not args.check_signed:
                        log("  Result:  Skipped (trusted signature) [CACHED]")
                    else:
                        log("  Result:  Not found in VirusTotal database [CACHED]")
                        unknown_count += 1
                        if args.submit and confirm_upload(exe_path, args.yes):
                            if api_key is None:
                                api_key = get_api_key(args.keyfile)
                            if api_calls > 0:
                                time.sleep(args.rate_limit)
                            api_calls += 1
                            analysis_id = submit_to_virustotal(
                                exe_path, api_key, timeout=args.timeout,
                            )
                            if analysis_id:
                                submitted_count += 1
                                log(f"  Submitted: https://www.virustotal.com/gui/file-analysis/{analysis_id}")
                else:
                    label = "CLEAN" if vt_malicious == 0 else "FLAGGED"
                    log(f"  Result:  {vt_malicious}/{vt_total} engines flagged "
                        f"as malicious [{label}] [CACHED]")
                    if vt_malicious > 0:
                        flagged.append((exe_path, sha256, vt_malicious, vt_total, procs))

                if db_write:
                    db_touch_last_seen(conn, exe_path, sha256)

                cached_count += 1
                log()
                continue

        # Signature check
        sig_status, authority = verify_signature(exe_path)
        signed = sig_status == "signed"
        if sig_status == "signed":
            signed_strict_count += 1
            log(f"  Signed:  Valid ({authority})")
            if not args.check_signed:
                log("  Result:  Skipped (trusted signature)")
                if db_write and conn:
                    db_upsert(conn, exe_path, sha256, True, authority,
                              None, None, checked=True)
                log()
                continue
        elif sig_status == "non-strict":
            log(f"  Signed:  Valid non-strict ({authority})")
            non_strict_count += 1
        else:
            log("  Signed:  No valid signature")
            unsigned_count += 1

        # Query VirusTotal
        if api_key is None:
            api_key = get_api_key(args.keyfile)
        if api_calls > 0:
            time.sleep(args.rate_limit)
        api_calls += 1
        checked_count += 1

        result = query_virustotal(sha256, api_key, timeout=args.timeout)

        vt_malicious = vt_total = None
        if result is None:
            log("  Result:  Not found in VirusTotal database")
            unknown_count += 1
            if args.submit and confirm_upload(exe_path, args.yes):
                if api_calls > 0:
                    time.sleep(args.rate_limit)
                api_calls += 1
                analysis_id = submit_to_virustotal(
                    exe_path, api_key, timeout=args.timeout,
                )
                if analysis_id:
                    submitted_count += 1
                    log(f"  Submitted: https://www.virustotal.com/gui/file-analysis/{analysis_id}")
        else:
            vt_malicious, vt_total = result
            label = "CLEAN" if vt_malicious == 0 else "FLAGGED"
            log(f"  Result:  {vt_malicious}/{vt_total} engines flagged as malicious [{label}]")
            if vt_malicious > 0:
                flagged.append((exe_path, sha256, vt_malicious, vt_total, procs))

        if db_write and conn:
            db_upsert(conn, exe_path, sha256, signed, authority,
                       vt_malicious, vt_total, checked=True)

        log()

    if conn:
        conn.close()

    log("=" * 72)

    # Signature breakdown
    sig_parts = []
    if signed_strict_count:
        label = "signed (strict)"
        if not args.check_signed:
            label += ", skipped"
        sig_parts.append(f"{signed_strict_count} {label}")
    if non_strict_count:
        sig_parts.append(f"{non_strict_count} signed (non-strict)")
    if unsigned_count:
        sig_parts.append(f"{unsigned_count} unsigned")
    if sig_parts:
        log("\n" + "\n".join(f"  {p}" for p in sig_parts))

    # Source breakdown
    source_parts = []
    if cached_count:
        source_parts.append(f"{cached_count} result(s) from cache")
    if checked_count:
        source_parts.append(f"{checked_count} checked against VirusTotal")
    if source_parts:
        log()
        for p in source_parts:
            log(f"  {p}")

    # Results
    log()
    log(f"  {len(flagged)} detection(s)")
    if unknown_count:
        log(f"  {unknown_count} not in VirusTotal database")
    if submitted_count:
        log(f"  {submitted_count} submitted to VirusTotal")

    # Hints
    hints = []
    if cached_count:
        hints.append("Rerun with --force to re-check cached results.")
    if unknown_count and not args.submit:
        hints.append("Rerun with --submit to upload unknown binaries to VirusTotal.")
    if flagged and not args.kill and any(procs for _, _, _, _, procs in flagged):
        hints.append("Rerun with --kill to terminate flagged processes.")
    if hints:
        log()
        for hint in hints:
            log(f"  {hint}")

    log()
    if flagged:
        print(f"⚠  {len(flagged)} executable(s) flagged as malicious:\n")
        for exe_path, sha256, malicious, total, procs in flagged:
            names = ", ".join(f"{name} (PID {pid})" for pid, name in procs)
            print(f"  {exe_path}")
            print(f"    Detections: {malicious}/{total}")
            if names:
                print(f"    Processes:  {names}")
            print(f"    VT link:   https://www.virustotal.com/gui/file/{sha256}")
            print()

        if args.kill:
            killed_count = 0
            failed_count = 0
            gone_count = 0
            for exe_path, sha256, malicious, total, procs in flagged:
                if not procs:
                    continue
                if not confirm_kill(exe_path, len(procs), args.yes):
                    continue
                for pid, name in procs:
                    try:
                        psutil.Process(pid).kill()
                        killed_count += 1
                    except psutil.NoSuchProcess:
                        gone_count += 1
                    except psutil.AccessDenied:
                        failed_count += 1
            if killed_count:
                print(f"  Killed {killed_count} process(es).")
            if gone_count:
                print(f"  {gone_count} process(es) already exited.")
            if failed_count:
                print(f"  Failed to kill {failed_count} process(es) (try sudo).")
    else:
        log("No malicious executables detected.")

    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
