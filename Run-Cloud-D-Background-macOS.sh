#!/bin/zsh -l
set -e

ROOT_DIR="${0:A:h}"
DATA_DIR="${CLOUD_D_DATA_DIR:-$HOME/.cloud-d}"
mkdir -p "$DATA_DIR"
REGISTRATION_CODE_FILE="$DATA_DIR/staff-registration-code"
if [[ -f "$REGISTRATION_CODE_FILE" ]]; then
  export CLOUD_D_STAFF_REGISTRATION_CODE="$(<"$REGISTRATION_CODE_FILE")"
fi
exec >>"$DATA_DIR/server.log" 2>&1
print "[$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')] Starting Cloud-D background service"

cd "$ROOT_DIR"
PYTHON_BIN="$(command -v python3 || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  print "Python 3 was not found. Install Python 3.10 or newer."
  exit 1
fi
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  print "Python 3.10 or newer is required."
  exit 1
fi

if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_BIN" -m venv .venv
fi
if [[ ! -f .venv/.cloud_d_dependencies_ready ]] || ! .venv/bin/python -c 'import cryptography' >/dev/null 2>&1; then
  .venv/bin/python -m pip install -r requirements.txt
  touch .venv/.cloud_d_dependencies_ready
fi

exec .venv/bin/python -m cloud_d.main --no-browser --host 127.0.0.1 --port 8765
