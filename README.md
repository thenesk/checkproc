# checkproc

Check unsigned running processes against VirusTotal database. MacOS only.  Written with Claude.

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

```bash
./checkproc.sh                    # scan all running processes
sudo ./checkproc.sh               # full scan with root access
sudo ./checkproc.sh --network-only # only processes with network connections
./checkproc.sh --pid 1234 5678    # specific PIDs
./checkproc.sh --path /usr/local/bin/suspicious  # specific binary (even if not running)
./checkproc.sh --skip-cryptex     # skip Cryptex binaries
./checkproc.sh --check-signed     # also check signed binaries against VT
./checkproc.sh --force            # ignore cache, re-check everything
./checkproc.sh --max-age 24       # re-check cached entries older than 24 hours
./checkproc.sh --submit           # prompt to upload unknown binaries to VT
./checkproc.sh --submit --yes     # upload unknown binaries without prompting
./checkproc.sh --kill             # prompt to kill flagged processes
./checkproc.sh --kill --yes       # kill flagged processes without prompting
./checkproc.sh -q                 # quiet mode, only output detections
```

Example
```bash
./checkproc.sh --skip-cryptex --max-age 24 --kill --submit --yes
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
| `--network-only` | Only scan processes with active network connections (use `sudo` to see all) |
| `--pid PID [...]` | Only scan specific process IDs |
| `--path PATH [...]` | Scan specific executables (including non-running binaries) |
| `--skip-cryptex` | Skip executables under `/System/Volumes/Preboot/Cryptexes/` |
| `--timeout SECS` | HTTP timeout for VT requests (default: 30) |
| `--rate-limit SECS` | Delay between VT requests (default: 15) |
| `--max-age HOURS` | Re-check cached entries older than this many hours |
| `--force` | Ignore cache and re-check all binaries |
| `-q`, `--quiet` | Only print output when detections are found |
| `--submit` | Prompt to upload binaries not found in the VT database |
| `-y`, `--yes` | Auto-confirm prompts without asking (implies `--submit`) |
| `--kill` | Kill processes whose executables are flagged as malicious |

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
