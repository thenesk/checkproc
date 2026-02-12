#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/.venv/bin/activate"
python3 -m pytest "$SCRIPT_DIR/test_checkproc.py" "$@"
