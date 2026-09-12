#!/bin/bash
# Fetches the Canaan K230 SDK IPC library variants the builds link against,
# straight from Kendryte's own public repo (https://github.com/kendryte/k230_sdk):
#
#   slave/lib/libipcmsg.a -> vendor/sdk_resource/lib/libipcmsg_slave.a
#       linked by rtos_core.elf (the RT-Smart big core, the "slave" side).
#
#   host/lib/libipcmsg.a  -> vendor/sdk_libs/libipcmsg.a
#       linked by mujina-minerd's nano3s IPC shim (mujina-miner/build.rs,
#       the Linux "host" side) when built with --features nano3s.
#
# Nothing SDK-derived is committed to this repo; this script is the "get it
# yourself" step that replaces that. The public SDK repo names both
# variants "libipcmsg.a" (sibling host/ and slave/ dirs), so each is renamed
# on the way in to where its consumer looks for it.
#
# Uses a blobless, sparse, depth-1 clone so this doesn't pull the rest of
# k230_sdk (kernel, u-boot, buildroot -- multiple GB) just for one ~200KB
# static library.
#
# Run from WSL (needs git+network). Usage:
#   bash install_sdk.sh                 # fetch if missing
#   bash install_sdk.sh --force         # re-fetch even if already present
#   K230_SDK_REF=<branch/tag/sha> bash install_sdk.sh   # pin a specific ref
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RTOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

K230_SDK_URL="https://github.com/kendryte/k230_sdk.git"
K230_SDK_REF="${K230_SDK_REF:-main}"
IPCMSG_COMPONENT_PATH="src/common/cdk/user/component/ipcmsg"
DEST_SLAVE="$RTOS_ROOT/vendor/sdk_resource/lib/libipcmsg_slave.a"
DEST_HOST="$RTOS_ROOT/vendor/sdk_libs/libipcmsg.a"

FORCE=0
[ "$1" = "--force" ] && FORCE=1

if [ -f "$DEST_SLAVE" ] && [ -f "$DEST_HOST" ] && [ "$FORCE" -eq 0 ]; then
    echo "[*] ipcmsg libraries already present -- skipping fetch (pass --force to re-fetch)."
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[*] Fetching kendryte/k230_sdk@$K230_SDK_REF (ipcmsg component only)..."
git clone --filter=blob:none --no-checkout --depth 1 --branch "$K230_SDK_REF" "$K230_SDK_URL" "$WORK/sdk"
cd "$WORK/sdk"
git sparse-checkout init --cone
git sparse-checkout set "$IPCMSG_COMPONENT_PATH"
git checkout --quiet

SRC_SLAVE="$WORK/sdk/$IPCMSG_COMPONENT_PATH/slave/lib/libipcmsg.a"
SRC_HOST="$WORK/sdk/$IPCMSG_COMPONENT_PATH/host/lib/libipcmsg.a"
[ -f "$SRC_SLAVE" ] || { echo "[!] Expected file not found at $SRC_SLAVE -- k230_sdk layout may have changed."; exit 1; }
[ -f "$SRC_HOST" ] || { echo "[!] Expected file not found at $SRC_HOST -- k230_sdk layout may have changed."; exit 1; }

mkdir -p "$(dirname "$DEST_SLAVE")" "$(dirname "$DEST_HOST")"
cp "$SRC_SLAVE" "$DEST_SLAVE"
cp "$SRC_HOST" "$DEST_HOST"

echo "[*] Verifying kd_ipcmsg_connect is present in the fetched archives..."
riscv64-unknown-linux-musl-nm "$DEST_SLAVE" 2>/dev/null | grep -q kd_ipcmsg_connect \
    || nm "$DEST_SLAVE" 2>/dev/null | grep -q kd_ipcmsg_connect \
    || { echo "[!] kd_ipcmsg_connect not found in $DEST_SLAVE -- got the wrong file or a stripped one."; exit 1; }
nm "$DEST_HOST" 2>/dev/null | grep -q kd_ipcmsg_connect \
    || { echo "[!] kd_ipcmsg_connect not found in $DEST_HOST -- got the wrong file or a stripped one."; exit 1; }

echo "[+] Installed $DEST_SLAVE"
echo "[+] Installed $DEST_HOST"
