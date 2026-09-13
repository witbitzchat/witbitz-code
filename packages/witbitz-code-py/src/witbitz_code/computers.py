"""The account's PAIRED COMPUTERS registry (docs/opencode-relay.md §3.1) — a port of spaces/public/codeComputers.js.

A sealed `op:'state'` doc named 'computers' in the account's index room. Every signed-in device reads it and the pairing
tool writes it, so there is ONE merge rule for all of them, defined in the JS module and reproduced here exactly:

  { v: 1, computers: { <id>: { name, relay, secret, pairedAt, mod } | { removed: true, mod } } }

Last-writer-wins PER ENTRY on `mod`; on a tie a removal wins. A removal is a tombstone that keeps no secret, so an unpair
propagates instead of being re-added by a device that has not heard of it yet.
"""

from __future__ import annotations

import math
import re
import time
from typing import Any
from urllib.parse import unquote

from . import _js

COMPUTERS_DOC = "computers"

_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")
_SECRET = re.compile(r"[A-Za-z0-9_-]{43}")

# ── okRelay: `new URL(u)` is wss:, or ws: on localhost ────────────────────────────────────────────────────────────────
# A WHATWG-URL subset, enough to agree with the browser on what the registry may hold: scheme, authority, port, and the
# IPv4 shorthands (ws://127.1 IS 127.0.0.1 to a browser).
_FORBIDDEN_HOST = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")


def _ipv4_number(part: str) -> int | None:
    if part == "":
        return None
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]*", part):
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part[1:], 8) if re.fullmatch(r"[0-7]+", part[1:]) else None
        return int(part) if re.fullmatch(r"[0-9]+", part) else None
    except ValueError:
        return None


def _parse_host(host: str) -> str | None:
    """Host → its serialized form, or None when a browser would reject the URL."""
    if host.startswith("["):
        return host.lower() if re.fullmatch(r"\[[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*\]", host) else None
    try:
        host = unquote(host, errors="strict")
    except UnicodeDecodeError:
        return None
    host = host.lower()
    if host == "" or _FORBIDDEN_HOST.search(host):
        return None
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts = parts[:-1]
    last = parts[-1]
    if re.fullmatch(r"[0-9]+", last) or re.fullmatch(r"0[xX][0-9a-fA-F]*", last):  # "ends in a number" → must be IPv4
        nums = [_ipv4_number(p) for p in parts]
        if len(parts) > 4 or any(n is None for n in nums) or any(n > 255 for n in nums[:-1]):
            return None
        if nums[-1] >= 256 ** (5 - len(nums)):
            return None
        value = sum(n * 256 ** (3 - i) for i, n in enumerate(nums[:-1])) + nums[-1]
        return ".".join(str((value >> s) & 255) for s in (24, 16, 8, 0))
    return host


def ok_relay(u: Any) -> bool:
    s = _js.js_string(u)
    s = re.sub(r"\A[\x00-\x20]+|[\x00-\x20]+\Z", "", s)
    s = re.sub(r"[\t\n\r]", "", s)
    m = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", s)
    if not m:
        return False
    scheme = m.group(1).lower()
    if scheme not in ("ws", "wss"):
        return False
    rest = re.sub(r"\A[/\\]*", "", s[m.end():])  # special schemes: any run of slashes or backslashes, even none
    authority = re.split(r"[/\\?#]", rest, maxsplit=1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    hp = re.fullmatch(r"(\[[^\]]*\]|[^:]*)(?::([0-9]*))?", authority)
    if not hp:
        return False
    if hp.group(2) and int(hp.group(2)) > 65535:
        return False
    host = _parse_host(hp.group(1))
    if host is None:
        return False
    return scheme == "wss" or host in ("127.0.0.1", "localhost")


def _num(v: Any) -> float:
    """A real number — not true, not "0x10", not [7]."""
    return _js.clean_number(v) if _js.is_num(v) and math.isfinite(v) and v > 0 else 0


# ── the registry ──────────────────────────────────────────────────────────────────────────────────────────────────────
def norm_entry(e: Any) -> dict | None:
    """One entry → its canonical shape, or None when it is not usable."""
    if not isinstance(e, dict):
        return None  # (an array is an object to JS, but has no `mod`, so it ends here too)
    get = e.get
    mod = _num(get("mod", _js.UNDEFINED))
    if not mod:
        return None
    if _js.truthy(get("removed", _js.UNDEFINED)):
        return {"removed": True, "mod": mod}
    secret, relay = get("secret", _js.UNDEFINED), get("relay", _js.UNDEFINED)
    if not isinstance(secret, str) or not _SECRET.fullmatch(secret) or not ok_relay(relay):
        return None
    name = get("name", _js.UNDEFINED)
    return {
        # cut by character (code point, as Array.from), never mid-emoji
        "name": "".join(list(_js.utf16_join([_js.js_string(name if _js.truthy(name) else "computer")]))[:80]),
        "relay": _js.js_string(relay),
        "secret": secret,
        "pairedAt": _num(get("pairedAt", _js.UNDEFINED)) or mod,
        "mod": mod,
    }


def norm_registry(doc: Any) -> dict:
    """Any doc (or nothing) → {v: 1, computers: {…}} with only well-formed entries."""
    out: dict = {"v": 1, "computers": {}}
    src = doc.get("computers") if isinstance(doc, dict) else None
    if not isinstance(src, dict):
        return out  # (an array here has only index keys, which no id can match)
    for cid, e in src.items():
        # An id is only ever data, even one spelled like a built-in ("constructor", "__proto__") — the JS side keeps its
        # entry maps prototype-free for exactly this.
        if not isinstance(cid, str) or not _ID.fullmatch(cid):
            continue
        n = norm_entry(e)
        if n:
            out["computers"][cid] = n
    return out


def merge_registry(a: Any, b: Any) -> dict:
    """Merge two registries: per id the higher `mod` wins; a tie goes to the removal. Pure."""
    x, y = norm_registry(a), norm_registry(b)
    out = {"v": 1, "computers": dict(x["computers"])}
    for cid, e in y["computers"].items():
        cur = out["computers"].get(cid)
        if cur is None or e["mod"] > cur["mod"] or (e["mod"] == cur["mod"] and e.get("removed") and not cur.get("removed")):
            out["computers"][cid] = e
    return out


def same_registry(a: Any, b: Any) -> bool:
    return _js.stringify(_sort_keys(norm_registry(a))) == _js.stringify(_sort_keys(norm_registry(b)))


def _sort_keys(r: dict) -> dict:
    return {"v": 1, "computers": {cid: r["computers"][cid] for cid in sorted(r["computers"])}}


def live_computers(reg: Any) -> list[dict]:
    """The computers you can connect to, oldest pairing first: [{id, name, relay, secret}]."""
    entries = [(cid, e) for cid, e in norm_registry(reg)["computers"].items() if not e.get("removed")]
    entries.sort(key=lambda p: (p[1]["pairedAt"], p[0].encode("utf-16-be", "surrogatepass")))
    return [{"id": cid, "name": e["name"], "relay": e["relay"], "secret": e["secret"]} for cid, e in entries]


def _now_ms() -> int:
    return int(time.time() * 1000)


def with_computer(reg: Any, cid: str, entry: dict, now: float | None = None) -> dict:
    """Add or update one computer (the pairing tool's write)."""
    now = _now_ms() if now is None else now
    prev = norm_registry(reg)["computers"].get(cid)
    mod = max(now, prev["mod"] + 1 if prev else 0)
    new = {k: entry[k] for k in ("name", "relay", "secret") if k in entry}
    new["pairedAt"] = prev["pairedAt"] if prev and not prev.get("removed") else now
    new["mod"] = mod
    return merge_registry(reg, {"computers": {cid: new}})


def without_computer(reg: Any, cid: str, now: float | None = None) -> dict:
    """Tombstone one computer (unpair / "Remove" in Settings)."""
    now = _now_ms() if now is None else now
    prev = norm_registry(reg)["computers"].get(cid)
    return merge_registry(reg, {"computers": {cid: {"removed": True, "mod": max(now, prev["mod"] + 1 if prev else 0)}}})
