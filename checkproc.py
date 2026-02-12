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
RATE_LIMIT_DELAY = 15  # seconds between requests (free API: 4 req/min)


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


def verify_signature(path: str) -> tuple[bool, str | None]:
    """Check if a binary has a valid code signature from a trusted developer.

    Returns (signed, authority) where authority is the top-level signer
    (e.g. "Software Signing" for Apple binaries) or None.
    """
    try:
        result = subprocess.run(
            ["codesign", "-dv", "--verbose=2", path],
            capture_output=True, text=True, timeout=10,
        )
        # codesign prints info to stderr
        if result.returncode != 0:
            return False, None

        # Extract the root authority (last Authority= line)
        authorities = []
        for line in result.stderr.splitlines():
            if line.startswith("Authority="):
                authorities.append(line.split("=", 1)[1])

        if not authorities:
            return False, None

        # Verify the signature is actually valid (not just present)
        verify = subprocess.run(
            ["codesign", "--verify", "--strict", path],
            capture_output=True, timeout=10,
        )
        if verify.returncode != 0:
            return False, None

        return True, authorities[-1]
    except (subprocess.TimeoutExpired, OSError):
        return False, None


def get_network_pids() -> set[int]:
    """Return the set of PIDs that have network connections or listeners."""
    pids = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.pid:
            pids.add(conn.pid)
    return pids


def collect_processes(network_only: bool = False) -> dict[str, list[tuple[int, str]]]:
    """Return a dict mapping executable path -> list of (pid, name)."""
    net_pids = get_network_pids() if network_only else None
    exes = {}
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info
            if network_only and info["pid"] not in net_pids:
                continue
            exe = info.get("exe")
            if not exe or not os.path.isfile(exe):
                continue
            exes.setdefault(exe, []).append((info["pid"], info["name"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return exes


def query_virustotal(sha256: str, api_key: str) -> tuple[int, int] | None:
    """Query VT for a hash. Returns (malicious, total) or None."""
    resp = requests.get(
        f"{VT_API_URL}/{sha256}",
        headers={"x-apikey": api_key},
    )
    if resp.status_code == 404:
        return None  # not in VT database
    if resp.status_code == 429:
        print("  [rate limited — waiting 60s]")
        time.sleep(60)
        return query_virustotal(sha256, api_key)
    resp.raise_for_status()
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return stats["malicious"], sum(stats.values())


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS executables (
    path            TEXT    NOT NULL,
    sha256          TEXT    NOT NULL,
    signed          INTEGER NOT NULL,
    signature_authority TEXT,
    vt_malicious    INTEGER,
    vt_total        INTEGER,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    PRIMARY KEY (path, sha256)
);
"""


def db_open(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(DB_SCHEMA)
    conn.commit()
    return conn


def db_lookup(conn: sqlite3.Connection, path: str, sha256: str) -> sqlite3.Row | None:
    """Return a row if this path+hash combo exists, else None."""
    row = conn.execute(
        "SELECT * FROM executables WHERE path = ? AND sha256 = ?",
        (path, sha256),
    ).fetchone()
    return row


def db_upsert(
    conn: sqlite3.Connection,
    path: str,
    sha256: str,
    signed: bool,
    authority: str | None,
    vt_malicious: int | None,
    vt_total: int | None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO executables
            (path, sha256, signed, signature_authority,
             vt_malicious, vt_total, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path, sha256) DO UPDATE SET
            signed = excluded.signed,
            signature_authority = excluded.signature_authority,
            vt_malicious = excluded.vt_malicious,
            vt_total = excluded.vt_total,
            last_seen = excluded.last_seen
        """,
        (path, sha256, int(signed), authority, vt_malicious, vt_total, now, now),
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
        description="Check running processes against VirusTotal."
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
        help="Only scan executables with active network connections or listeners",
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
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    api_key = get_api_key(args.keyfile)
    quiet = args.quiet

    def log(msg=""):
        if not quiet:
            print(msg)

    use_db = not args.no_db
    db_read = use_db and not args.write_only and not args.force
    db_write = use_db and not args.read_only
    conn = db_open(args.db) if use_db else None

    scope = "network-connected" if args.network_only else "running"
    log(f"Collecting {scope} processes...")
    exes = collect_processes(network_only=args.network_only)
    log(f"Found {len(exes)} unique executables across {scope} processes.\n")

    log("Checking signatures and querying VirusTotal...")
    log("-" * 72)

    flagged = []
    signed_count = 0
    cached_count = 0
    queried_count = 0

    for i, (exe_path, procs) in enumerate(sorted(exes.items()), 1):
        pids = ", ".join(str(p) for p, _ in procs)
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
            row = db_lookup(conn, exe_path, sha256)
            if row is not None:
                signed = bool(row["signed"])
                authority = row["signature_authority"]
                vt_malicious = row["vt_malicious"]
                vt_total = row["vt_total"]

                sig_label = f"Valid ({authority})" if signed else "No valid signature"
                log(f"  Signed:  {sig_label}")

                if vt_malicious is None:
                    log("  Result:  Not found in VirusTotal database [CACHED]")
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
        signed, authority = verify_signature(exe_path)
        if signed:
            log(f"  Signed:  Valid ({authority})")
            if not args.check_signed:
                log("  Result:  Skipped (trusted signature)")
                if db_write and conn:
                    db_upsert(conn, exe_path, sha256, True, authority, None, None)
                signed_count += 1
                log()
                continue
        else:
            log("  Signed:  No valid signature")

        # Query VirusTotal
        if queried_count > 0:
            time.sleep(RATE_LIMIT_DELAY)
        queried_count += 1

        result = query_virustotal(sha256, api_key)

        vt_malicious = vt_total = None
        if result is None:
            log("  Result:  Not found in VirusTotal database")
        else:
            vt_malicious, vt_total = result
            label = "CLEAN" if vt_malicious == 0 else "FLAGGED"
            log(f"  Result:  {vt_malicious}/{vt_total} engines flagged as malicious [{label}]")
            if vt_malicious > 0:
                flagged.append((exe_path, sha256, vt_malicious, vt_total, procs))

        if db_write and conn:
            db_upsert(conn, exe_path, sha256, signed, authority,
                       vt_malicious, vt_total)

        log()

    if conn:
        conn.close()

    log("=" * 72)
    log(f"\n{cached_count} executable(s) loaded from database cache")
    log(f"{signed_count} executable(s) skipped (valid signature)")
    log(f"{queried_count} executable(s) checked against VirusTotal\n")
    if flagged:
        print(f"⚠  {len(flagged)} executable(s) flagged as malicious:\n")
        for exe_path, sha256, malicious, total, procs in flagged:
            names = ", ".join(f"{name} (PID {pid})" for pid, name in procs)
            print(f"  {exe_path}")
            print(f"    Detections: {malicious}/{total}")
            print(f"    Processes:  {names}")
            print(f"    VT link:   https://www.virustotal.com/gui/file/{sha256}")
            print()
    else:
        log("No malicious executables detected.")


if __name__ == "__main__":
    main()
