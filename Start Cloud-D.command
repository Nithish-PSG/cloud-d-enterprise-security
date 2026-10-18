#!/bin/zsh
set -e

cd -- "$(dirname -- "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  print "Cloud-D needs Python 3.10 or newer. Install Python 3, then double-click this file again."
  read -k 1 "?Press any key to close..."
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  print "Cloud-D needs Python 3.10 or newer. The Python found on this Mac is too old."
  read -k 1 "?Press any key to close..."
  exit 1
fi

print "Starting Cloud-D. Keep this Terminal window open while you use the dashboard."
exec python3 -m cloud_d.main
