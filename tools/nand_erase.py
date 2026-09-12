#!/usr/bin/env python3
"""nand_erase.py -- full-chip erase + bad-block scan for the Nano3s SPI NAND.

The k230 flash library never issues KBURN_CMD_ERASE_LBA (0x20); every flash
relies on the loader's implicit erase-before-write. If interrupted writes left
bad blocks that get silently skipped, the resulting layout shift corrupts any
image -- which matches our symptom exactly (4 different verified images, all
hang identically at the logo).

This tool erases EVERY erase-block on the chip, one at a time, and keeps going
on failures so we get a complete map. A block that fails to erase is bad.
If every block erases clean, the NAND is healthy and the erase also doubles
as the "deep format" a burned-up NAND layout needs.

WARNING: destructive -- wipes the entire NAND. The device must be re-flashed
afterwards (which we need to do anyway).

Usage: nand_erase.py [--dry-run]   (dry-run = probe only, no erase)
"""
import struct
import sys
import time

sys.path.insert(0, "/Users/satsman/.nano3s-flasher/venv/lib/python3.14/site-packages")

from k230_flash import api, usb_utils  # noqa: E402
from k230_flash.burners import (  # noqa: E402
    K230UBOOTBurner,
    KBURN_CMD_NONE,
    KBURN_CMD_ERASE_LBA,
    USBCommunicationError,
)

MEDIA_SPI_NAND = 3
LOADER_ADDRESS = 0x80360000
ERASE_TIMEOUT_MS = 120_000  # per-block; generous


def erase_block(burner, offset, size):
    """One ERASE_LBA round trip. Returns True/False; mirrors write_start cfg."""
    try:
        burner.send_cmd(KBURN_CMD_NONE, b"", expected_response_length=0)
    except Exception:
        pass
    cfg = struct.pack("<QQQQ", offset, size, size, 0)
    try:
        burner.send_cmd(KBURN_CMD_ERASE_LBA, cfg, expected_response_length=8)
        return True
    except (USBCommunicationError, Exception) as e:
        print(f"\n    FAIL @0x{offset:08X}: {e}")
        return False


def main():
    dry = "--dry-run" in sys.argv

    dev, port_path = usb_utils.find_device()
    if dev is None:
        print("no K230 found -- put it in burn mode (hold recessed button + power on)")
        return 1
    usb_utils.init_device(dev)
    dtype = usb_utils.detect_device_type(dev)
    print(f"device at {port_path}, mode: {dtype}")
    if dtype == usb_utils.KBURN_USB_DEV_BROM:
        print("BootROM: pushing loader...")
        dev, port_path = api._boot_loader_and_wait(
            dev, port_path, "SPI_NAND", None, LOADER_ADDRESS, None)
        usb_utils.init_device(dev)
    elif dtype != usb_utils.KBURN_USB_DEV_UBOOT:
        print(f"unexpected mode {dtype}")
        return 1

    burner = K230UBOOTBurner(dev)
    burner.media_type = MEDIA_SPI_NAND
    burner.probe()
    burner.get_capacity()
    print(f"probe ok: in_chunk={burner.in_chunk_size} out_chunk={burner.out_chunk_size} "
          f"blk={burner.blk_sz} erase_size={burner.erase_size} "
          f"cap={burner.capacity // (1024 * 1024)}MB")

    erase_size = burner.erase_size
    capacity = burner.capacity
    if not erase_size or erase_size % burner.blk_sz:
        print(f"refusing: suspicious erase_size {erase_size}")
        return 1
    n_blocks = capacity // erase_size
    print(f"chip: {n_blocks} erase-blocks of {erase_size // 1024} KiB each")

    if dry:
        print("(dry-run: done, no erase performed)")
        return 0

    print("\n=== erasing full chip ===")
    bad = []
    t0 = time.time()
    for i in range(n_blocks):
        off = i * erase_size
        ok = erase_block(burner, off, erase_size)
        if not ok and i == 0:
            # Canary: maybe this loader build doesn't implement ERASE_LBA
            # (it doesn't implement READ_LBA). Flush the pipe and retry once
            # before concluding -- a single timeout is not proof.
            print("    first erase failed -- flushing pipe and retrying once...")
            for _ in range(2):
                try:
                    burner.send_cmd(KBURN_CMD_NONE, b"", expected_response_length=0)
                except Exception:
                    pass
            ok = erase_block(burner, off, erase_size)
            if not ok:
                print("\nABORT: loader does not support ERASE_LBA (two failures on "
                      "block 0). No blocks were meaningfully erased; nothing is lost "
                      "-- the chip was getting wiped anyway.")
                return 2
        if not ok:
            bad.append(off)
        if (i + 1) % 64 == 0 or i == n_blocks - 1:
            pct = 100.0 * (i + 1) / n_blocks
            print(f"  [{pct:5.1f}%] block {i + 1}/{n_blocks} "
                  f"({time.time() - t0:.0f}s, bad so far: {len(bad)})",
                  flush=True)

    dt = time.time() - t0
    print(f"\n=== done in {dt:.0f}s ===")
    if not bad:
        print("ALL BLOCKS ERASED CLEAN -- NAND logic is healthy, no bad blocks")
        return 0
    print(f"{len(bad)} BAD BLOCK(S):")
    for off in bad:
        print(f"  0x{off:08X}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
