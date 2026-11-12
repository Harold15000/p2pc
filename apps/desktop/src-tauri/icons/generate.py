# SPDX-License-Identifier: Apache-2.0
"""Writes the placeholder app icons of the desktop app (H2 T2-42) next to this script.

The icons are a plain disc in the tray's "sharing" green, drawn here so that the repository holds no image of unknown
origin. Replace them with the real artwork when there is one (keep the file names: `tauri.conf.json` lists them).

Usage: python3 apps/desktop/src-tauri/icons/generate.py   (standard library only)
"""

import struct
import sys
import zlib
from pathlib import Path

COLOUR = (0x2E, 0xA0, 0x43)


def disc_rgba(size: int) -> bytes:
    """A filled, anti-aliased disc on a transparent square, as RGBA rows (the same drawing as src/tray.rs)."""
    centre = size / 2.0
    radius = size / 2.0 - max(1.0, size / 16.0)
    rows = bytearray()
    for y in range(size):
        for x in range(size):
            dx = x + 0.5 - centre
            dy = y + 0.5 - centre
            coverage = min(1.0, max(0.0, radius + 0.5 - (dx * dx + dy * dy) ** 0.5))
            rows += bytes((*COLOUR, round(coverage * 255)))
    return bytes(rows)


def png(size: int) -> bytes:
    """An 8-bit RGBA PNG (colour type 6: Tauri requires RGBA icons)."""
    rgba = disc_rgba(size)
    stride = size * 4
    raw = b"".join(b"\x00" + rgba[y * stride : (y + 1) * stride] for y in range(size))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(sizes: list[int]) -> bytes:
    """A Windows .ico whose images are PNGs (supported since Windows Vista)."""
    images = [png(s) for s in sizes]
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, data in zip(sizes, images):
        side = 0 if size >= 256 else size  # 0 means 256 in an ICO directory entry
        out += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return out + b"".join(images)


def main() -> int:
    here = Path(__file__).resolve().parent
    (here / "32x32.png").write_bytes(png(32))
    (here / "128x128.png").write_bytes(png(128))
    (here / "icon.png").write_bytes(png(512))
    (here / "icon.ico").write_bytes(ico([16, 24, 32, 48, 64, 256]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
