#!/bin/bash
# build_all.sh -- build all three Nano3s firmware artifacts on macOS via
# Docker, then (optionally) assemble a flashable .kdimg.
#
#   tools/build_all.sh                  # build everything
#   tools/build_all.sh --kdimg --pool stratum+tcp://... --user W.wallet
#   tools/build_all.sh --kdimg          # pool/user stay as in the base image
#
# Artifacts land where build_kdimg.sh looks for them by default:
#   rtos_core/build/rtos_core.elf
#   mujina-miner/target/riscv64gc-unknown-linux-gnu/release/mujina-minerd.stripped
#   nano3s_ui/target/riscv64gc-unknown-linux-gnu/release/nano3s_ui
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER="${DOCKER:-docker}"
KDIMG_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --kdimg) KDIMG_ARGS+=("kdimg"); shift ;;
        --pool|--user|--base|--out|--keep-data|--fresh-data|--flash|--keep-work)
            KDIMG_ARGS+=("$1" "${2:-}"); shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

# The repo must be bind-mounted where its build scripts expect it. Use the
# upstream layout (/work/nano3s/rtos_core, /work/nano3s/mujina-miner) because
# build_mujina_minerd.sh resolves the workspace root relative to itself and
# mujina's .cargo/config.toml hardcodes nothing path-dependent beyond that.
IN_REPO=/work/nano3s

# 1. Build (or refresh) the cross-compile image.
echo "==> [1/4] Building cross-compile image (first run ~5 min, then cached)"
"$DOCKER" build -q -t nano3s-build -f "$SCRIPT_DIR/Dockerfile.build" "$SCRIPT_DIR" >/dev/null
echo "    image ready"

# 2. Big-core RTOS firmware.
echo "==> [2/4] Building rtos_core.elf (big core)"
"$DOCKER" run --rm \
    -v "$REPO_ROOT:$IN_REPO" -w "$IN_REPO/rtos_core" \
    nano3s-build bash -c '
        set -e
        bash tools/install_sdk.sh
        # The container ships the Canaan RT-Smart toolchain
        # (riscv64-unknown-linux-musl-rv64imafdcv-lp64d), so the Makefile
        # defaults build cleanly: no attribute sanitizer, no march fallback,
        # no PIE flags needed.
        make clean >/dev/null 2>&1 || true
        CC=riscv64-unknown-linux-musl-gcc make -j"$(nproc)"
        riscv64-unknown-linux-musl-strip build/rtos_core.elf || true
        file build/rtos_core.elf | head -1
    '

# 3. Little-core binaries (mujina-minerd via the workspace, nano3s_ui standalone).
echo "==> [3/4] Building mujina-minerd + nano3s_ui (little core, static musl)"
"$DOCKER" run --rm \
    -v "$REPO_ROOT:$IN_REPO" -w "$IN_REPO" \
    -e CARGO_HOME=/work/.cargo-home \
    nano3s-build bash -c '
        set -e
        # mujina-minerd: workspace build with the nano3s board feature.
        # --no-default-features drops usb-udev (libudev serial lookup):
        # the device has no USB mining hardware and static-linking libudev
        # is not an option on this rootfs.
        cargo build --release --target riscv64gc-unknown-linux-gnu \
            --no-default-features --features nano3s --bin mujina-minerd
        BIN=target/riscv64gc-unknown-linux-gnu/release/mujina-minerd
        riscv64-linux-gnu-strip --strip-all -o "$BIN.stripped" "$BIN"
        strings "$BIN.stripped" | grep -q nano3s_ipc_ \
            || { echo "[!] nano3s symbols missing from mujina-minerd" >&2; exit 1; }
        ls -lh "$BIN.stripped"

        # nano3s_ui: excluded from the workspace, own lockfile.
        cd nano3s_ui
        cargo build --release --target riscv64gc-unknown-linux-gnu --bin nano3s_ui
        riscv64-linux-gnu-strip --strip-all \
            target/riscv64gc-unknown-linux-gnu/release/nano3s_ui || true
        ls -lh target/riscv64gc-unknown-linux-gnu/release/nano3s_ui
    '

# The workspace builds mujina-minerd into the repo-root target/ dir, but
# build_kdimg.sh looks for it under mujina-miner/target/ -- place a copy so
# the default paths line up.
mkdir -p "$REPO_ROOT/mujina-miner/target/riscv64gc-unknown-linux-gnu/release"
cp -f "$REPO_ROOT/target/riscv64gc-unknown-linux-gnu/release/mujina-minerd.stripped" \
      "$REPO_ROOT/mujina-miner/target/riscv64gc-unknown-linux-gnu/release/mujina-minerd.stripped"

echo "==> [4/4] Done. Artifacts:"
ls -la "$REPO_ROOT/rtos_core/build/rtos_core.elf" \
       "$REPO_ROOT/mujina-miner/target/riscv64gc-unknown-linux-gnu/release/mujina-minerd.stripped" \
       "$REPO_ROOT/nano3s_ui/target/riscv64gc-unknown-linux-gnu/release/nano3s_ui"

if [ "${KDIMG_ARGS:+x}" ]; then
    if [ "${#KDIMG_ARGS[@]}" -eq 1 ] && [ "${KDIMG_ARGS[0]}" = "kdimg" ]; then
        KDIMG_ARGS+=(--base "$HOME/Downloads/nano-mujina-alpha-v2.kdimg" --out "$HOME/Downloads/nano-mujina-custom.kdimg")
    fi
    echo "==> Assembling .kdimg"
    PYTHON="${PYTHON:-python3}" bash "$SCRIPT_DIR/build_kdimg.sh" "${KDIMG_ARGS[@]}"
fi
