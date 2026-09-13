"""JavaScript semantics this port has to reproduce, in one place.

The JS tools are the reference implementation and the page runs them, so wherever the wire or a shared file depends on
a JS rule, Python follows the rule rather than its own idiom:

- JSON.stringify: compact, integral floats print as integers (1000, not 1000.0), lone UTF-16 surrogates are escaped,
  integer-like object keys come first. Byte-identical output keeps the pairings file and the gzip-size threshold equal.
- String lengths and slices count UTF-16 code units (chunking at 192 KiB, `name.slice(0, 80)`, `id.slice(0, 64)`). A
  slice may split a surrogate pair exactly as JS does; joining the halves back recombines it.
- Truthiness, unary `+`, `String(x)`, `Number.isInteger`: the registry and payload readers lean on all of them.
- atob's "forgiving base64": what the page accepts, Python accepts, and nothing more.
"""

from __future__ import annotations

import base64
import decimal
import json
import math
import re
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1


class _Undefined:
    """A property that is absent (JS `undefined`), as opposed to JSON null (None)."""

    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
        return cls._inst

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "undefined"


UNDEFINED = _Undefined()

# ECMAScript WhiteSpace + LineTerminator — what `\s` and String.prototype.trim() mean in JS (Python's differ: no U+FEFF).
WS = "\t\n\x0b\x0c\r \xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
# JS `.` stops at these; Python's `.` stops only at \n.
NOT_LT = "[^\n\r\u2028\u2029]"
_TRIM = re.compile(f"\\A[{WS}]+|[{WS}]+\\Z")


def is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def truthy(v: Any) -> bool:
    if v is None or v is False or v is UNDEFINED:
        return False
    if is_num(v):
        return v == v and v != 0
    if isinstance(v, str):
        return v != ""
    return True  # objects and arrays, even empty ones


def is_integer(v: Any) -> bool:
    """Number.isInteger — 42.0 from JSON counts, exactly as JSON.parse("42.0") === 42 in JS."""
    if not is_num(v):
        return False
    return isinstance(v, int) or (math.isfinite(v) and float(v).is_integer())


def is_safe_integer(v: Any) -> bool:
    return is_integer(v) and abs(v) <= MAX_SAFE_INTEGER


def strict_eq(a: Any, b: Any) -> bool:
    """`===` for JSON values: same kind and equal; objects by identity."""
    if is_num(a) and is_num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, bool) and isinstance(b, bool):
        return a == b
    return a is b


def trim(s: str) -> str:
    return _TRIM.sub("", s)


# ── numbers ───────────────────────────────────────────────────────────────────────────────────────────────────────────
_DEC = re.compile(r"[+-]?(?:Infinity|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)")


def _string_to_number(s: str) -> float:
    t = trim(s)
    if t == "":
        return 0
    if _DEC.fullmatch(t):
        return float(t.replace("Infinity", "inf"))
    for prefix, base, digits in (("0x", 16, "[0-9a-fA-F]"), ("0o", 8, "[0-7]"), ("0b", 2, "[01]")):
        if re.fullmatch(f"0[{prefix[1]}{prefix[1].upper()}]{digits}+", t):
            return float(int(t[2:], base))
    return math.nan


def to_number(v: Any) -> float:
    """Unary `+v`."""
    if v is UNDEFINED:
        return math.nan
    if v is None or v is False:
        return 0
    if v is True:
        return 1
    if is_num(v):
        return v
    if isinstance(v, str):
        return _string_to_number(v)
    if isinstance(v, (list, tuple)):
        return _string_to_number(js_string(v))
    return math.nan


def number_str(x: float) -> str:
    """Number.prototype.toString() — shortest round-trip digits, JS exponent rules."""
    if isinstance(x, int) and abs(x) <= MAX_SAFE_INTEGER:
        return str(x)
    x = float(x)
    if x != x:
        return "NaN"
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    d = decimal.Decimal(repr(abs(x))).normalize()
    _, digits, exp = d.as_tuple()
    s = "".join(map(str, digits))
    k, n = len(s), len(s) + exp
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e = n - 1
    mant = s if k == 1 else s[0] + "." + s[1:]
    return f"{sign}{mant}e{'+' if e >= 0 else '-'}{abs(e)}"


def js_string(v: Any) -> str:
    """String(v)."""
    if v is UNDEFINED:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_num(v):
        return number_str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return ",".join("" if e is None or e is UNDEFINED else js_string(e) for e in v)
    return "[object Object]"


def clean_number(v: float) -> float:
    """A computed number as JS would hold it for JSON: integral floats become ints (so they print as 5, not 5.0)."""
    if isinstance(v, float) and math.isfinite(v) and v.is_integer() and abs(v) <= MAX_SAFE_INTEGER:
        return int(v)
    return v


# ── UTF-16 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def utf16_slice(s: str, start: int, end: int | None = None) -> str:
    b = s.encode("utf-16-le", "surrogatepass")
    return b[2 * start : None if end is None else 2 * end].decode("utf-16-le", "surrogatepass")


def utf16_join(parts) -> str:
    """''.join, then fuse surrogate halves that a UTF-16 slice split — JS strings do this implicitly."""
    s = "".join(parts)
    if not _SURROGATE.search(s):
        return s
    return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


_SURROGATE = re.compile("[\ud800-\udfff]")


def utf8(s: str) -> bytes:
    """A JS string as UTF-8 the way fetch/TextEncoder send it: pairs fused, a lone surrogate becomes U+FFFD."""
    return _SURROGATE.sub("\ufffd", utf16_join([s])).encode("utf-8")

# ── JSON ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_NEEDS_ESCAPE = re.compile('["\\\\\x00-\x1f\ud800-\udfff]')
_INDEX_KEY = re.compile(r"0|[1-9]\d*")


def _quote(s: str) -> str:
    if _SURROGATE.search(s):
        s = utf16_join([s])  # a pair held as two code points is one character to JS
    return '"' + _NEEDS_ESCAPE.sub(lambda m: _ESCAPES.get(m.group(0)) or "\\u%04x" % ord(m.group(0)), s) + '"'


def _ordered_keys(d: dict) -> list:
    keys = [k if isinstance(k, str) else js_string(k) for k in d]
    idx = sorted((k for k in keys if _INDEX_KEY.fullmatch(k) and int(k) < 2**32 - 1), key=int)
    idx_set = set(idx)
    return idx + [k for k in keys if k not in idx_set]


def stringify(v: Any, indent: int | None = None) -> str:
    """JSON.stringify(v, null, indent) for JSON-shaped values."""
    gap = " " * indent if indent else ""

    def ser(x: Any, cur: str) -> str | None:
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if x is UNDEFINED:
            return None
        if is_num(x):
            return number_str(x) if math.isfinite(x) else "null"
        if isinstance(x, str):
            return _quote(x)
        inner = cur + gap
        if isinstance(x, (list, tuple)):
            items = [ser(e, inner) or "null" for e in x]
            if not items:
                return "[]"
            if not gap:
                return "[" + ",".join(items) + "]"
            return "[\n" + inner + (",\n" + inner).join(items) + "\n" + cur + "]"
        if isinstance(x, dict):
            src = {(k if isinstance(k, str) else js_string(k)): val for k, val in x.items()}
            members = []
            for k in _ordered_keys(src):
                sv = ser(src[k], inner)
                if sv is not None:
                    members.append(_quote(k) + (": " if gap else ":") + sv)
            if not members:
                return "{}"
            if not gap:
                return "{" + ",".join(members) + "}"
            return "{\n" + inner + (",\n" + inner).join(members) + "\n" + cur + "}"
        raise TypeError(f"not JSON-serializable: {type(x).__name__}")

    out = ser(v, "")
    if out is None:
        raise TypeError("undefined is not JSON")
    return out


def _no_constants(name: str):
    raise ValueError(f"{name} is not JSON")


def parse(text: str) -> Any:
    """JSON.parse — refuses NaN/Infinity, which Python's json would otherwise accept."""
    return json.loads(text, parse_constant=_no_constants)


def json_bytes(v: Any) -> float:
    """UTF-8 size of JSON.stringify(v ?? null) — Infinity when it cannot be serialized (compress.js _jsonBytes)."""
    try:
        return len(stringify(None if v is UNDEFINED else v).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return math.inf


# ── base64 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
_B64_BAD = re.compile(r"[^A-Za-z0-9+/]")


def atob(s: str) -> bytes:
    """WHATWG forgiving-base64 decode (what `atob` accepts). Raises ValueError where atob throws."""
    t = re.sub(r"[\t\n\x0c\r ]", "", s)
    if len(t) % 4 == 0:
        if t.endswith("=="):
            t = t[:-2]
        elif t.endswith("="):
            t = t[:-1]
    if len(t) % 4 == 1 or _B64_BAD.search(t):
        raise ValueError("invalid base64")
    return base64.b64decode(t + "=" * (-len(t) % 4))


def btoa(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64u(b: bytes) -> str:
    """base64url, unpadded (every B64/b64u/b64url helper on the JS side)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def unb64u_loose(s: Any) -> bytes:
    """deviceLink UNB64 / recovery fromB64url: url alphabet mapped back, then atob (no padding added)."""
    return atob(js_string(s).replace("-", "+").replace("_", "/"))
