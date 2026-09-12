#!/usr/bin/env python3
"""Convert an image into the Nano3s LCD's boot-logo format.

The Nano3s panel is a 240x240 portrait-mode RGB565 framebuffer. The boot
logo file (bootlogo.rgb565) is exactly 240*240*2 = 115200 bytes of raw
little-endian RGB565 pixel data, no header -- the same layout fb_page's
pizza.rgb565 already uses.

Usage:
    python3 tools/make_bootlogo.py <input image> [output]

Defaults: output = tools/bootlogo.rgb565.

What it does:
  - Converts to RGBA, composites onto pure black (the transparent areas
    of a logo PNG render as the terminal UI's background instead of
    white boxes).
  - Fits INSIDE 240x240 with aspect preserved (letterbox), centered.
  - Center-crops oversized input first so small artwork isn't shrunk
    twice.

Example:
    python3 tools/make_bootlogo.py "~/Downloads/my logo/logo.PNG"
"""

import sys

from PIL import Image

PANEL_W = 240
PANEL_H = 240
OUT_SIZE = PANEL_W * PANEL_H * 2  # 115200 bytes


def rgb565(r: int, g: int, b: int) -> bytes:
    """Pack one pixel as little-endian RGB565, matching the panel's native format."""
    r5 = (r >> 3) & 0x1F
    g6 = (g >> 2) & 0x3F
    b5 = (b >> 3) & 0x1F
    value = (r5 << 11) | (g6 << 5) | b5
    return value.to_bytes(2, "little")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "tools/bootlogo.rgb565"

    im = Image.open(src_path).convert("RGBA")

    # Center-crop oversized input to the panel's aspect before resizing,
    # so the fit pass never shrinks small artwork twice.
    target_ratio = PANEL_W / PANEL_H
    w, h = im.size
    if w / h > target_ratio:
        new_w = int(h * target_ratio)
        left = (w - new_w) // 2
        im = im.crop((left, 0, left + new_w, h))
    elif w / h < target_ratio:
        new_h = int(w / target_ratio)
        top = (h - new_h) // 2
        im = im.crop((0, top, w, top + new_h))

    # Fit inside the panel with aspect preserved (letterbox onto black).
    im.thumbnail((PANEL_W, PANEL_H), Image.LANCZOS)
    canvas = Image.new("RGBA", (PANEL_W, PANEL_H), (0, 0, 0, 255))
    x = (PANEL_W - im.size[0]) // 2
    y = (PANEL_H - im.size[1]) // 2
    canvas.alpha_composite(im, (x, y))
    canvas = canvas.convert("RGB")

    # RGB565 pack, row-major.
    out = bytearray()
    px = canvas.load()
    for yy in range(PANEL_H):
        for xx in range(PANEL_W):
            r, g, b = px[xx, yy]
            out += rgb565(r, g, b)

    if len(out) != OUT_SIZE:
        print(f"error: produced {len(out)} bytes, expected {OUT_SIZE}", file=sys.stderr)
        return 1

    with open(out_path, "wb") as f:
        f.write(out)
    print(f"wrote {out_path} ({len(out)} bytes, {PANEL_W}x{PANEL_H} RGB565)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
