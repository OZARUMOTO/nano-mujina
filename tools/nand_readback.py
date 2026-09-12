#!/usr/bin/env python3
"""nand_readback.py -- verify what is ACTUALLY on the Nano3s SPI NAND.

Reads partitions back through the k230 burn loader (KBURN_CMD_READ_LBA /
0x23, mirroring write_start's <offset,size,size,flags> encoding) and
SHA256-compares each against the expected padded partition payload from
the source .kdimg -- exactly the bytes the flasher wrote.

Non-destructive: read only. Device must be in burn mode.

Usage:
  nand_readback.py <image.kdimg> part1 part2 ...
"""
import hashlib
import struct
import sys
import time

sys.path.insert(0, "/Users/satsman/.nano3s-flasher/venv/lib/python3.14/site-packages")

import usb.core  # noqa: E402
from k230_flash import api, usb_utils  # noqa: E402
from k230_flash.burners import (  # noqa: E402
    K230UBOOTBurner,
    PACKET_SIZE,
    HEADER_SIZE,
    KBURN_CMD_NONE,
)
from k230_flash.kdimage import KburnKdImage  # noqa: E402

MEDIA_SPI_NAND = 3
LOADER_ADDRESS = 0x80360000
CHUNK_TIMEOUT = 15000


def nop(burner):
    try:
        burner.send_cmd(KBURN_CMD_NONE, b"", expected_response_length=0)
    except Exception as e:
        print(f"    (nop failed: {e})")


def read_partition(burner, offset, size, name):
    """READ_LBA start + bulk IN stream. Mirrors write_start's cfg layout."""
    nop(burner)
    cfg = struct.pack("<QQQQ", offset, size, size, 0)
    try:
        resp = burner.send_cmd(0x23, cfg, expected_response_length=8)
    except Exception as e:
        print(f"  READ_LBA start failed: {e}")
        return None
    if resp:
        echo = struct.unpack("<QQ", resp)
        print(f"    start-ack: offset=0x{echo[0]:X} size={echo[1]:,}")
    data = bytearray()
    chunk = burner.in_chunk_size or 32768
    while len(data) < size:
        want = min(chunk, size - len(data))
        try:
            pkt = burner.dev.read(burner.ep_in, want, timeout=CHUNK_TIMEOUT)
        except usb.core.USBError as e:
            print(f"    stream error after {len(data):,} bytes: {e}")
            return bytes(data)
        if not pkt:
            break
        data += pkt
    # drain trailing status packet if any
    try:
        pkt = burner.dev.read(burner.ep_in, PACKET_SIZE, timeout=400)
        if pkt:
            cmd, result, dsize = struct.unpack("<HHH", bytes(pkt[:HEADER_SIZE]))
            print(f"    trailing: cmd=0x{cmd:04x} result=0x{result:04x} "
                  f"msg={bytes(pkt[HEADER_SIZE:HEADER_SIZE+dsize])!r}")
    except usb.core.USBError:
        pass
    return bytes(data)


def main():
    img_path = sys.argv[1]
    parts = sys.argv[2:]
    if not parts:
        print("usage: nand_readback.py <image.kdimg> <part> [part...]")
        return 2

    kd = KburnKdImage(img_path)
    items = {i.partName: i for i in kd.items().data}
    for p in parts:
        if p not in items:
            print(f"partition {p!r} not in image (have: {sorted(items)})")
            return 2

    print("=== expected (padded write payload from image) ===")
    expect = {}
    for p in parts:
        it = items[p]
        with kd.open_part_stream(it) as s:
            data = s.read(it.writeSize)
        expect[p] = (it.partOffset, it.writeSize, hashlib.sha256(data).hexdigest())
        print(f"  {p:14s} @0x{it.partOffset:08X} {it.writeSize:>10,} B  sha {expect[p][2][:16]}...")

    print("\n=== device ===")
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
    print(f"probe ok: in_chunk={burner.in_chunk_size} blk={burner.blk_sz} "
          f"cap={burner.capacity // (1024 * 1024)}MB")

    print("\n=== read-back verification ===")
    fails = 0
    for p in parts:
        off, size, want_sha = expect[p]
        print(f"\n-- {p} @0x{off:X} ({size:,} B)")
        got = read_partition(burner, off, size, p)
        if got is None or len(got) != size:
            print(f"  SHORT READ: {len(got or b''):,}/{size:,}")
            fails += 1
            continue
        got_sha = hashlib.sha256(got).hexdigest()
        if got_sha == want_sha:
            print(f"  MATCH  {got_sha[:16]}...")
        else:
            fails += 1
            print("  MISMATCH")
            print(f"    want {want_sha}")
            print(f"    got  {got_sha}")
            with kd.open_part_stream(items[p]) as s:
                want_data = s.read(size)
            first = next((i for i in range(size) if got[i] != want_data[i]), None)
            print(f"    first differing byte: {first}")
            if first is not None:
                lo = max(0, first - 16)
                print(f"    want[{lo}:+32]: {want_data[lo:lo+32].hex()}")
                print(f"    got [{lo}:+32]: {got[lo:lo+32].hex()}")
        nop(burner)

    print(f"\n=== result: {'ALL MATCH' if fails == 0 else str(fails) + ' FAILURES'} ===")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
