#!/usr/bin/env python3
"""kdimg.py -- K230 .kdimg container tool (inspect / extract / create).

Implements the kdimg format the official K230 flashing tools read, so a
custom Nano3s image can be built and audited on any machine with Python 3,
no vendor tooling required.

Layout (reverse-engineered from k230-flash's own kdimage.py, which
documents it in kdimage.md):

  Header, 512 bytes, little-endian:
    magic        u32 = 0x27CB8F93
    crc32        u32 (CRC-32 of the 512-byte header with this field zeroed)
    flag         u32
    version      u32 (1 = V1 partition entries, >=2 = V2)
    part_tbl_num u32
    part_tbl_crc32 u32 (CRC-32 of the raw partition-table bytes)
    image_info   32s
    chip_info    32s
    board_info   64s
    (rest of the 512 bytes: zero padding)

  Partition table: part_tbl_num entries, 256 bytes each:
    V1 (<8I32s32s): magic u32 = 0x91DF6DA4, offset, size, erase_size,
       max_size, flag u32, content_offset, content_size, sha256[32],
       name[32]
    V2 (<5I4xQII32s32s): same fields, but flag is u64 (with 4 pad bytes
       before it) and content_offset/content_size follow as u32.

  Payloads: raw bytes at content_offset, sha256 over exactly
  content_size bytes. The device receives max(content_size, size) bytes
  padded with 0xFF.

Usage:
  kdimg.py inspect IMAGE.kdimg                 # dump header + partition table
  kdimg.py verify IMAGE.kdimg                  # verify every partition's sha256
  kdimg.py extract IMAGE.kdimg [OUTDIR]        # dump each partition payload
  kdimg.py create OUT.kdimg --spec SPEC.json   # build an image from a JSON spec

Spec format for `create` (all offsets are device flash offsets; payloads
are padded to part_max_size with 0xFF in the output file):
  {
    "version": 2,
    "image_info": "nano-mujina", "chip_info": "k230", "board_info": "nano3s",
    "parts": [
      {"name": "loader",   "offset": 0x0,        "size": 0x40000,
       "erase_size": 0x20000, "max_size": 0x40000,
       "payload": "path/to/file.bin"},
      ...
    ]
  }
"""

import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

KDIMG_HEADER_MAGIC = 0x27CB8F93
KDIMG_PART_MAGIC = 0x91DF6DA4
HEADER_FORMAT = "<6I32s32s64s"
HEADER_SIZE = 512
PART_STRUCT_SIZE = 256
PART_FORMAT_V1 = "<8I32s32s"
PART_FORMAT_V2 = "<5I4xQII32s32s"
MAX_PART_TBL_NUM = 512


class KdimgError(ValueError):
    pass


class Part:
    def __init__(self, name, offset, size, erase_size, max_size, flag, content_offset, content_size, sha256):
        self.name = name
        self.offset = offset
        self.size = size
        self.erase_size = erase_size
        self.max_size = max_size
        self.flag = flag
        self.content_offset = content_offset
        self.content_size = content_size
        self.sha256 = sha256  # hex string or None

    @property
    def write_size(self):
        return max(self.content_size, self.size)

    def __repr__(self):
        return f"<Part {self.name!r} off=0x{self.offset:X} max=0x{self.max_size:X}>"


def _parse_header(blob):
    if len(blob) < HEADER_SIZE:
        raise KdimgError(f"file too small for header: {len(blob)} bytes")
    fields = struct.unpack(HEADER_FORMAT, blob[: struct.calcsize(HEADER_FORMAT)])
    hdr = {
        "magic": fields[0],
        "crc32": fields[1],
        "flag": fields[2],
        "version": fields[3],
        "part_tbl_num": fields[4],
        "part_tbl_crc32": fields[5],
        "image_info": fields[6].rstrip(b"\x00").decode("utf-8", "replace"),
        "chip_info": fields[7].rstrip(b"\x00").decode("utf-8", "replace"),
        "board_info": fields[8].rstrip(b"\x00").decode("utf-8", "replace"),
    }
    if hdr["magic"] != KDIMG_HEADER_MAGIC:
        raise KdimgError(f"bad header magic 0x{hdr['magic']:08X} (want 0x{KDIMG_HEADER_MAGIC:08X})")
    check = bytearray(blob[:HEADER_SIZE])
    check[4:8] = b"\x00\x00\x00\x00"
    calc = zlib.crc32(check) & 0xFFFFFFFF
    if calc != hdr["crc32"]:
        raise KdimgError(f"header CRC32 mismatch: file 0x{hdr['crc32']:08X}, computed 0x{calc:08X}")
    if hdr["part_tbl_num"] > MAX_PART_TBL_NUM:
        raise KdimgError(f"implausible partition count {hdr['part_tbl_num']}")
    return hdr


def _parse_part(blob, version):
    if len(blob) < PART_STRUCT_SIZE:
        raise KdimgError("truncated partition entry")
    fmt = PART_FORMAT_V2 if version >= 2 else PART_FORMAT_V1
    u = struct.unpack(fmt, blob[: struct.calcsize(fmt)])
    if u[0] != KDIMG_PART_MAGIC:
        raise KdimgError(f"bad part magic 0x{u[0]:08X}")
    return Part(
        name=u[9].rstrip(b"\x00").decode("utf-8", "replace"),
        offset=u[1],
        size=u[2],
        erase_size=u[3],
        max_size=u[4],
        flag=u[5],
        content_offset=u[6],
        content_size=u[7],
        sha256=u[8].hex(),
    )


def load(path):
    """Parse a kdimg file, returning (header, [Part])."""
    blob = Path(path).read_bytes()
    hdr = _parse_header(blob)
    tbl_size = hdr["part_tbl_num"] * PART_STRUCT_SIZE
    if len(blob) < HEADER_SIZE + tbl_size:
        raise KdimgError("file too small for partition table")
    tbl = blob[HEADER_SIZE : HEADER_SIZE + tbl_size]
    calc = zlib.crc32(tbl) & 0xFFFFFFFF
    if calc != hdr["part_tbl_crc32"]:
        raise KdimgError(f"partition-table CRC32 mismatch: file 0x{hdr['part_tbl_crc32']:08X}, computed 0x{calc:08X}")
    parts = [_parse_part(tbl[i * PART_STRUCT_SIZE : (i + 1) * PART_STRUCT_SIZE], hdr["version"]) for i in range(hdr["part_tbl_num"])]
    parts.sort(key=lambda p: p.offset)
    return hdr, parts


def verify(path, parts=None):
    """Verify every partition's payload sha256. Returns list of (name, ok)."""
    if parts is None:
        _, parts = load(path)
    data = Path(path).read_bytes()
    results = []
    for p in parts:
        payload = data[p.content_offset : p.content_offset + p.content_size]
        if len(payload) != p.content_size:
            results.append((p.name, False))
            continue
        calc = hashlib.sha256(payload).hexdigest()
        ok = calc == p.sha256
        results.append((p.name, ok))
        if not ok:
            print(f"  {p.name}: MISMATCH file={calc} table={p.sha256}", file=sys.stderr)
    return results


def extract(path, outdir, parts=None):
    """Write each partition's payload (unpadded) into outdir/NAME.bin."""
    if parts is None:
        _, parts = load(path)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    data = Path(path).read_bytes()
    written = []
    for p in parts:
        payload = data[p.content_offset : p.content_offset + p.content_size]
        dest = outdir / f"{p.name}.bin"
        dest.write_bytes(payload)
        written.append(dest)
    return written


def _num(v):
    """Accept 0x-prefixed strings or plain ints in specs."""
    return int(v, 0) if isinstance(v, str) else int(v)


def create(out_path, spec_path):
    """Build a kdimg from a JSON spec (see module docstring)."""
    spec = json.loads(Path(spec_path).read_text())
    version = int(spec.get("version", 2))
    if version not in (1, 2):
        raise KdimgError(f"unsupported version {version}")
    entries = []
    total_payload = HEADER_SIZE
    for e in spec["parts"]:
        payload = Path(e["payload"]).read_bytes() if e.get("payload") else b""
        entries.append((e, payload))
        total_payload += len(payload)

    # Partition table region, then payloads -- content offsets are assigned
    # sequentially after the table.
    tbl_num = len(entries)
    tbl_offset = HEADER_SIZE
    content_base = tbl_offset + tbl_num * PART_STRUCT_SIZE

    parts = []
    cursor = content_base
    for e, payload in entries:
        content_offset = cursor if payload else 0
        cursor += len(payload)
        parts.append(
            Part(
                name=e["name"],
                offset=_num(e["offset"]),
                size=_num(e["size"]),
                erase_size=_num(e.get("erase_size", 0)),
                max_size=_num(e["max_size"]),
                flag=_num(e.get("flag", 0)),
                content_offset=content_offset,
                content_size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest() if payload else None,
            )
        )

    # Serialize the table, then the header over it.
    fmt = PART_FORMAT_V2 if version >= 2 else PART_FORMAT_V1
    tbl = bytearray()
    for p in parts:
        name = p.name.encode("utf-8")[:32].ljust(32, b"\x00")
        sha = bytes.fromhex(p.sha256) if p.sha256 else b"\x00" * 32
        if version >= 2:
            tbl += struct.pack(fmt, KDIMG_PART_MAGIC, p.offset, p.size, p.erase_size, p.max_size, p.flag, p.content_offset, p.content_size, sha, name)
        else:
            tbl += struct.pack(fmt, KDIMG_PART_MAGIC, p.offset, p.size, p.erase_size, p.max_size, p.flag & 0xFFFFFFFF, p.content_offset, p.content_size, sha, name)
        tbl += b"\x00" * (PART_STRUCT_SIZE - struct.calcsize(fmt))

    header = bytearray(
        struct.pack(
            HEADER_FORMAT,
            KDIMG_HEADER_MAGIC,
            0,
            int(spec.get("flag", 0)),
            version,
            tbl_num,
            zlib.crc32(bytes(tbl)) & 0xFFFFFFFF,
            spec.get("image_info", "nano-mujina").encode()[:32].ljust(32, b"\x00"),
            spec.get("chip_info", "k230").encode()[:32].ljust(32, b"\x00"),
            spec.get("board_info", "nano3s").encode()[:64].ljust(64, b"\x00"),
        )
    )
    header += b"\x00" * (HEADER_SIZE - len(header))
    calc = zlib.crc32(header) & 0xFFFFFFFF
    header[4:8] = calc.to_bytes(4, "little")

    # Assemble: header + table + payloads (already in table order).
    out = bytearray(header)
    out += tbl
    for _, payload in entries:
        out += payload
    Path(out_path).write_bytes(out)
    print(f"wrote {out_path} ({len(out)} bytes, {tbl_num} partitions)")
    return 0


def cmd_inspect(args):
    hdr, parts = load(args.image)
    print(f"image_info : {hdr['image_info']!r}")
    print(f"chip_info  : {hdr['chip_info']!r}")
    print(f"board_info : {hdr['board_info']!r}")
    print(f"version    : {hdr['version']}   flag: {hdr['flag']:#x}")
    print(f"partitions : {hdr['part_tbl_num']}")
    print()
    print(f"{'NAME':<14} {'OFFSET':>12} {'MAX SIZE':>12} {'CONTENT':>12} {'WRITE':>12}  SHA256[:16]")
    total = 0
    for p in parts:
        total = max(total, p.offset + p.max_size)
        print(
            f"{p.name:<14} 0x{p.offset:08X}  0x{p.max_size:9X}  0x{p.content_size:9X}  0x{p.write_size:9X}  {p.sha256[:16]}"
        )
    print()
    print(f"declared layout end: 0x{total:X} ({total // (1024 * 1024)} MB)")
    return 0


def cmd_verify(args):
    hdr, parts = load(args.image)
    results = verify(args.image, parts)
    bad = [n for n, ok in results if not ok]
    for name, ok in results:
        print(f"  {name:<14} {'OK' if ok else 'FAIL'}")
    print(f"{len(results) - len(bad)}/{len(results)} partitions verified")
    return 1 if bad else 0


def cmd_extract(args):
    hdr, parts = load(args.image)
    dests = extract(args.image, args.outdir, parts)
    for d in dests:
        print(f"  {d} ({d.stat().st_size} bytes)")
    print(f"extracted {len(dests)} partitions to {args.outdir}")
    return 0


def cmd_create(args):
    return create(args.out, args.spec)


def main():
    ap = argparse.ArgumentParser(description="K230 kdimg container tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("inspect", help="dump header + partition table")
    p.add_argument("image")
    p.set_defaults(fn=cmd_inspect)

    p = sub.add_parser("verify", help="verify all partition sha256 digests")
    p.add_argument("image")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("extract", help="extract partition payloads")
    p.add_argument("image")
    p.add_argument("outdir")
    p.set_defaults(fn=cmd_extract)

    p = sub.add_parser("create", help="build a kdimg from a JSON spec")
    p.add_argument("--spec", required=True)
    p.add_argument("out")
    p.set_defaults(fn=cmd_create)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except KdimgError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
