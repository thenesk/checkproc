# checkproc

Check running process executables against the VirusTotal database. MacOS only.

Enumerates running processes, hashes their executables (SHA-256), verifies code signatures via `codesign`, and queries VirusTotal. Validly signed binaries are skipped by default. Results are cached in a local SQLite database to avoid redundant API calls.

## Setup

1. Get a free API key from [VirusTotal](https://www.virustotal.com/).

2. Install dependent python modules into local venv:

```bash
./install.sh
```

3. Save your API key:

```bash
echo 'your-api-key' > .vtkey
```

## Usage

Running with `sudo` is recommended for full visibility. Without it, system processes may be skipped and `--network-only` will only see the current user's connections.

```bash
sudo ./checkproc.sh               # full scan with root access
./checkproc.sh                    # scan all running processes
./checkproc.sh --network-only     # only processes with network connections
./checkproc.sh --pid 1234 5678    # specific PIDs
./checkproc.sh --path /usr/local/bin/suspicious  # specific binary (even if not running)
./checkproc.sh --check-signed     # also check signed binaries against VT
./checkproc.sh --force            # ignore cache, re-check everything
./checkproc.sh --max-age 24       # re-check cached entries older than 24 hours
./checkproc.sh --submit           # prompt to upload unknown binaries to VT
./checkproc.sh --yes              # upload unknown binaries without prompting
./checkproc.sh -q                 # quiet mode, only output detections
```

## Options

| Flag | Description |
|---|---|
| `--keyfile PATH` | Path to VT API key file (default: `.vtkey`) |
| `--check-signed` | Also check signed executables against VT |
| `--db PATH` | Path to SQLite cache (default: `.checkproc.sqlite`) |
| `--no-db` | Disable the database entirely |
| `--read-only` | Use cached results but don't write new ones |
| `--write-only` | Write results but don't read from cache |
| `--network-only` | Only scan processes with active network connections |
| `--pid PID [...]` | Only scan specific process IDs |
| `--path PATH [...]` | Scan specific executables (including non-running binaries) |
| `--timeout SECS` | HTTP timeout for VT requests (default: 30) |
| `--rate-limit SECS` | Delay between VT requests (default: 15) |
| `--max-age HOURS` | Re-check cached entries older than this many hours |
| `--force` | Ignore cache and re-check all binaries |
| `-q`, `--quiet` | Only print output when detections are found |
| `--submit` | Prompt to upload binaries not found in the VT database |
| `-y`, `--yes` | Auto-confirm uploads without prompting (implies `--submit`) |

## Exit codes

- `0` -- no detections
- `1` -- one or more executables flagged as malicious

## Tests

```bash
./run_tests.sh        # run all tests
./run_tests.sh -v     # verbose output
```

## Rate limits

The free VirusTotal API allows 4 requests per minute. checkproc automatically waits between requests and retries on rate limit errors.
