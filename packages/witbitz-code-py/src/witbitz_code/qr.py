"""Render the pairing challenge as a QR — tools/rc-qr.mjs. Byte mode, error correction 'M' (fixed, not boosted: it
survives a phone screen's glare and moiré), the smallest version that fits, a 4-module quiet zone, the same ANSI and SVG
output. The module pattern is segno's, not qrcode-generator's (pad codewords and mask choice differ), so the picture can
differ from the app's while carrying the same text — the tests decode it with the jsQR the phone runs.
"""

from __future__ import annotations

import os
import segno

QUIET = 4  # modules of white margin; below ~4 a scanner loses the finder patterns


def qr_modules(text: str) -> list[list[bool]]:
    qr = segno.make(str(text), error="m", boost_error=False, micro=False, mode="byte")
    return [[bool(bit) for bit in row] for row in qr.matrix_iter(scale=1, border=0)]


def render_ansi(rows: list[list[bool]], compact: bool | None = None) -> str:
    """Dark on a white background via ANSI, so it scans on a dark terminal too. Compact by default, like tools/rc-qr.mjs:
    half blocks, one character per module across and two modules per line ("▀": top in the foreground colour, bottom in
    the background) — a quarter of the two-spaces-per-module drawing. WITBITZ_QR=large (or compact=False) draws that one."""
    if compact is None:
        compact = os.environ.get("WITBITZ_QR") != "large"
    size = len(rows)
    dim = size + QUIET * 2

    def dark(r: int, c: int) -> bool:
        return QUIET <= r < QUIET + size and QUIET <= c < QUIET + size and bool(rows[r - QUIET][c - QUIET])

    if not compact:
        on, off = "\x1b[40m  \x1b[0m", "\x1b[47m  \x1b[0m"
        return "\n".join("".join(on if dark(r, c) else off for c in range(dim)) for r in range(dim))
    lines = []
    for r in range(0, dim, 2):
        cells = "".join(f"\x1b[{30 if dark(r, c) else 97};{40 if dark(r + 1, c) else 107}m▀" for c in range(dim))
        lines.append(cells + "\x1b[0m")
    return "\n".join(lines)


def render_svg(rows: list[list[bool]], px: int = 320) -> str:
    """Black modules on white with the quiet zone — open or scan it on any device."""
    dim = len(rows) + QUIET * 2
    rects = "".join(
        f'<rect x="{c + QUIET}" y="{r + QUIET}" width="1" height="1"/>'
        for r, row in enumerate(rows) for c, d in enumerate(row) if d
    )
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{px}" height="{px}" viewBox="0 0 {dim} {dim}" '
            f'shape-rendering="crispEdges" role="img" aria-label="Pairing QR">'
            f'<rect width="{dim}" height="{dim}" fill="#fff"/><g fill="#000">{rects}</g></svg>')


def qr_ansi(text: str) -> str:
    return render_ansi(qr_modules(text))


def qr_svg(text: str, px: int = 320) -> str:
    return render_svg(qr_modules(text), px)
