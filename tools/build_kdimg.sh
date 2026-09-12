#!/bin/bash
# build_kdimg.sh -- assemble a flashable Nano3s .kdimg from a released base
# image plus this repo's built firmware.
#
# Layered, so almost everything runs natively on macOS:
#
#   [1] tools/kdimg.py (pure Python, any OS)
#       unpack the base image's partitions, verify, repack the final image.
#
#   [2] THIS SCRIPT (bash, any OS)
#       stage this repo's build outputs + boot logo over the unpacked
#       trees, generate the repack spec, wire the steps together.
#
#   [3] tools/ubifs_rebuild.sh, run inside ANY Linux container
#       (colima/OrbStack/Docker Desktop on macOS, plain docker on Linux,
#       podman works too via DOCKER=podman). Only UBIFS image creation
#       needs real mtd-utils, and mtd-utils is Linux-only -- this is the
#       single step that cannot run on bare macOS. Everything else,
#       including the actual flashing (k230-flash), is native Mac.
#
# Usage:
#   tools/build_kdimg.sh --base BASE.kdimg --out OUT.kdimg [options]
#
# Options:
#   --rtos PATH        rtos_core.elf to install (default rtos_core/build/rtos_core.elf)
#   --minerd PATH      mujina-minerd to install (default mujina-miner/target/
#                      riscv64gc-unknown-linux-gnu/release/mujina-minerd.stripped)
#   --ui PATH          nano3s_ui binary to install (default nano3s_ui/target/
#                      riscv64gc-unknown-linux-gnu/release/nano3s_ui)
#   --ble PATH         ble_setup binary to install (default: keep base's)
#   --logo PATH        boot logo .rgb565 (default tools/bootlogo.rgb565 if present)
#   --pool URL         stratum pool URL written into mujina_display_startup.sh
#   --user STR         pool username/wallet written into mujina_display_startup.sh
#   --fresh-data       strip WiFi credentials + logs from the data volume so the
#                      flashed device boots into first-time BLE setup (default ON;
#                      pass --keep-data to preserve the base image's /data)
#   --flash            flash OUT.kdimg when done (k230-flash -m SPI_NAND)
#   --keep-work        keep the work directory for debugging
#
# Example (macOS, after building both firmwares):
#   tools/build_kdimg.sh --base ~/Downloads/nano-mujina-alpha-v2.kdimg \
#     --out ~/Downloads/nano-mujina-custom.kdimg \
#     --pool stratum+tcp://pool.example.com:3333 --user YOUR_WALLET.worker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PY="${PYTHON:-python3}"

BASE="" OUT="" RTOS="" MINERD="" UI="" BLE="" LOGO=""
POOL="" PUSER="" FLASH=0 KEEP_WORK=0 KEEP_DATA=0
DOCKER="${DOCKER:-docker}"

while [ $# -gt 0 ]; do
    case "$1" in
        --base) BASE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --rtos) RTOS="$2"; shift 2 ;;
        --minerd) MINERD="$2"; shift 2 ;;
        --ui) UI="$2"; shift 2 ;;
        --ble) BLE="$2"; shift 2 ;;
        --logo) LOGO="$2"; shift 2 ;;
        --pool) POOL="$2"; shift 2 ;;
        --user) PUSER="$2"; shift 2 ;;
        --fresh-data) KEEP_DATA=0; shift ;;
        --keep-data) KEEP_DATA=1; shift ;;
        --flash) FLASH=1; shift ;;
        --keep-work) KEEP_WORK=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

[ -n "$BASE" ] || { echo "error: --base is required" >&2; exit 1; }
[ -n "$OUT" ] || { echo "error: --out is required" >&2; exit 1; }
[ -f "$BASE" ] || { echo "error: base image not found: $BASE" >&2; exit 1; }

# Defaults for repo build outputs (all optional -- anything not supplied or
# missing is simply skipped, and the base image's version stays).
RTOS="${RTOS:-$REPO_ROOT/rtos_core/build/rtos_core.elf}"
MINERD="${MINERD:-$REPO_ROOT/mujina-miner/target/riscv64gc-unknown-linux-gnu/release/mujina-minerd.stripped}"
UI="${UI:-$REPO_ROOT/nano3s_ui/target/riscv64gc-unknown-linux-gnu/release/nano3s_ui}"
if [ -z "$LOGO" ] && [ -f "$REPO_ROOT/tools/bootlogo.rgb565" ]; then
    LOGO="$REPO_ROOT/tools/bootlogo.rgb565"
fi

WORK="${NANO3S_KDIMG_WORK:-$REPO_ROOT/build/kdimg}"
rm -rf "$WORK"
mkdir -p "$WORK/parts" "$WORK/overlay/app_ubi/release/rtt" \
    "$WORK/overlay/app_ubi/release/linux/app" "$WORK/overlay/data"

echo "==> [1/5] Unpacking base image: $BASE"
"$PY" "$SCRIPT_DIR/kdimg.py" extract "$BASE" "$WORK/parts"
"$PY" "$SCRIPT_DIR/kdimg.py" verify "$BASE" | tail -1

echo "==> [2/5] Staging repo build outputs"
pick() { # pick <src> <dest> <label>
    if [ -n "$2" ] && [ -f "$2" ]; then
        cp "$2" "$3"
        echo "    + $1 <- $2"
    else
        echo "    . $1: not supplied/found, keeping base image's version"
    fi
}
pick rtos_core.elf "$RTOS" "$WORK/overlay/app_ubi/release/rtt/rtos_core.elf"
pick mujina-minerd "$MINERD" "$WORK/overlay/data/mujina-minerd"
pick nano3s_ui "$UI" "$WORK/overlay/data/nano3s_ui"
pick ble_setup "$BLE" "$WORK/overlay/data/ble_setup"
pick bootlogo.rgb565 "$LOGO" "$WORK/overlay/app_ubi/release/linux/app/bootlogo.rgb565"
chmod +x "$WORK"/overlay/data/* "$WORK"/overlay/app_ubi/release/rtt/* 2>/dev/null || true

# Startup script: always take ours from deploy/ (it has the boot-logo hold),
# with pool settings patched in if requested.
STARTUP="$WORK/overlay/app_ubi/release/linux/app/mujina_display_startup.sh"
cp "$REPO_ROOT/deploy/mujina_display_startup.sh" "$STARTUP"
chmod +x "$STARTUP"
if [ -n "$POOL" ] || [ -n "$PUSER" ]; then
    [ -n "$POOL" ] && sed -i.bak "s#MUJINA_POOL_URL=[^ ]*#MUJINA_POOL_URL=$POOL#" "$STARTUP"
    [ -n "$PUSER" ] && sed -i.bak "s#MUJINA_POOL_USER=[^ ]*#MUJINA_POOL_USER=$PUSER#" "$STARTUP"
    rm -f "$STARTUP.bak"
    echo "    + startup script: pool=$POOL user=$PUSER"
fi

echo "==> [3/5] Rebuilding app_ubi + data volumes (Linux container step)"
if ! command -v "$DOCKER" >/dev/null 2>&1; then
    echo "  !! $DOCKER not found."
    echo "     The UBIFS rebuild needs any Linux container runtime. On macOS:"
    echo "       brew install colima && colima start      (then rerun this script)"
    echo "     or install OrbStack / Docker Desktop / podman (DOCKER=podman)."
    exit 1
fi
# tools/ubifs_rebuild.sh needs mtd-utils, which is Linux-only -- that makes
# this the single containerized step of the whole pipeline. The script is
# bind-mounted read-only; WORK carries the extracted parts + overlay trees
# in and receives parts_rebuilt/ back out.
echo "    (debian:bookworm-slim + mtd-utils via $DOCKER)"
"$DOCKER" run --rm \
    -v "$WORK:/work" \
    -v "$SCRIPT_DIR/ubifs_rebuild.sh:/ubifs_rebuild.sh:ro" \
    -e KEEP_DATA="$KEEP_DATA" \
    -e WIFI_SSID="${WIFI_SSID:-}" -e WIFI_PASS="${WIFI_PASS:-}" \
    debian:bookworm-slim \
    bash /ubifs_rebuild.sh /work
[ -f "$WORK/parts_rebuilt/app_ubi.bin" ] || { echo "error: app_ubi rebuild failed" >&2; exit 1; }
[ -f "$WORK/parts_rebuilt/data.bin" ] || { echo "error: data rebuild failed" >&2; exit 1; }

echo "==> [4/5] Repacking $OUT"
"$PY" - "$BASE" "$WORK" "$SCRIPT_DIR" <<'EOF'
import json, sys
# Reuse the base image's real partition table, swapping in the two rebuilt
# volume payloads. This preserves the device's exact flash layout.
sys.path.insert(0, sys.argv[3])
from kdimg import load
base, work = sys.argv[1], sys.argv[2]
hdr, parts = load(base)
rebuilt = {"app_ubi", "data"}
spec = {
    "version": hdr["version"],
    "image_info": hdr["image_info"],
    "chip_info": hdr["chip_info"],
    "board_info": hdr["board_info"],
    "parts": [
        {"name": p.name, "offset": p.offset, "size": p.size,
         "erase_size": p.erase_size, "max_size": p.max_size, "flag": p.flag,
         "payload": f"{work}/parts_rebuilt/{p.name}.bin" if p.name in rebuilt
                    else f"{work}/parts/{p.name}.bin"}
        for p in parts
    ],
}
open(f"{work}/repack_spec.json", "w").write(json.dumps(spec, indent=2))
print("    spec generated")
EOF
"$PY" "$SCRIPT_DIR/kdimg.py" create --spec "$WORK/repack_spec.json" "$OUT"
"$PY" "$SCRIPT_DIR/kdimg.py" verify "$OUT" | tail -1

if [ "$KEEP_WORK" = "0" ]; then
    rm -rf "$WORK"
else
    echo "    (work dir kept: $WORK)"
fi

echo "==> [5/5] Done: $OUT"
echo "    Flash with:  k230-flash -m SPI_NAND $OUT"
if [ "$FLASH" = "1" ]; then
    echo "==> Flashing (put the device in burn mode now)..."
    exec "$PY" -m k230_flash -m SPI_NAND "$OUT"
fi
