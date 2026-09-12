#!/bin/bash
# nano_flasher.command -- double-click launcher (macOS) for the Nano3s
# flashing GUI. On first run it creates a private Python environment in
# ~/.nano3s-flasher and installs k230-flash + PyObjC into it (about a
# minute); every run after that starts instantly.
#
# USB note: flashing needs libusb. If you hit a "no backend" error:
#   brew install libusb
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="$HOME/.nano3s-flasher/venv"
PY="$VENV/bin/python3"

if [ ! -x "$PY" ]; then
    echo "==> first run: setting up the flasher environment (~1 minute)…"
    PYBIN="$(command -v python3 || true)"
    if [ -z "$PYBIN" ]; then
        echo "python3 not found — install it with: brew install python" >&2
        exit 1
    fi
    "$PYBIN" -m venv "$VENV"
    "$PY" -m pip install --quiet --upgrade pip
    "$PY" -m pip install --quiet k230-flash pyobjc-framework-Cocoa
    echo "==> environment ready"
fi

exec "$PY" "$HERE/nano_flasher.py" "$@"
