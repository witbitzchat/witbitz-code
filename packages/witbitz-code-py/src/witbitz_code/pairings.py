"""This computer's pairings file and the local OpenCode env file — the pure half of tools/opencode-pair.mjs plus the
connector's loader.

~/.witbitz/code/pairings.json (0600) is shared with the JS tools, so it is written byte-for-byte as they write it
(`JSON.stringify(doc, null, 1) + "\\n"`): either implementation can pair a computer and the other can serve or unpair it.

  { "v": 1, "pairings": [ { account, idx: {room, mk}, computerId, secret, name, relay, opencodeUrl } ] }

One entry per (computer, account) — several accounts can pair the same computer, each with its own secret and channel.
"""

from __future__ import annotations

import os
import re
import secrets
import socket
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import _js
from ._js import NOT_LT, UNDEFINED, WS, strict_eq, truthy
from .relay import RELAY_URL, new_relay_secret

DEFAULT_OPENCODE_URL = "http://127.0.0.1:4096"


def pairings_path() -> Path:
    env = os.environ.get("WITBITZ_CODE_PAIRINGS")
    return Path(env) if env else Path.home() / ".witbitz" / "code" / "pairings.json"


def env_path() -> Path:
    env = os.environ.get("OPENCODE_ENV_FILE")
    return Path(env) if env else Path.home() / ".opencode-server.env"


# ── the env file ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _assignment(key: str) -> re.Pattern:
    # JS: /^\s*(?:export\s+)?KEY=(.*)$/ on each line split at /\r?\n/ (a Windows-edited file keeps its password). JS `.`
    # still stops at a lone \r or U+2028, so NOT_LT keeps the two tools agreeing on those.
    return re.compile(f"[{WS}]*(?:export[{WS}]+)?{re.escape(key)}=({NOT_LT}*)")


def env_get(text: Any, key: str) -> str | None:
    """The value of KEY in an env file — the LAST assignment wins, as when the file is sourced. Quotes are stripped."""
    rx = _assignment(key)
    v = None
    for line in re.split(r"\r?\n", _js.js_string(text if truthy(text) else "")):
        m = rx.fullmatch(line)
        if m:
            q = re.fullmatch(f"(['\"])({NOT_LT}*)\\1", _js.trim(m.group(1)))
            v = q.group(2) if q else _js.trim(m.group(1))
    return v


def env_set(text: Any, key: str, value: str) -> str:
    """Set KEY=value: every existing assignment of KEY is removed, one is appended, every other line is kept verbatim."""
    rx = re.compile(f"[{WS}]*(?:export[{WS}]+)?{re.escape(key)}=")
    keep = [ln for ln in re.split(r"\r?\n", _js.js_string(text if truthy(text) else "")) if not rx.match(ln)]
    while keep and keep[-1] == "":
        keep.pop()
    keep.append(f"{key}={value}")
    return "\n".join(keep) + "\n"


def parse_env_password(text: Any) -> str:
    """OPENCODE_SERVER_PASSWORD from an env file ('' when absent)."""
    return env_get(text, "OPENCODE_SERVER_PASSWORD") or ""


def read_env_password(path: Path | None = None) -> str:
    p = path or env_path()
    try:
        return parse_env_password(p.read_text(encoding="utf-8"))
    except OSError:
        return ""


def new_password() -> str:
    """32 URL-safe characters (192 bits) — the LOCAL OpenCode password; it never leaves this computer."""
    return secrets.token_urlsafe(24)


def new_computer_id() -> str:
    """16 random bytes, base64url. One per (computer, account) pairing."""
    return secrets.token_urlsafe(16)


def hostname() -> str:
    return socket.gethostname()


# ── the pairings doc (pure) ───────────────────────────────────────────────────────────────────────────────────────────
def _usable(p: Any) -> bool:
    idx = p.get("idx") if isinstance(p, dict) else None
    return (isinstance(idx, dict) and truthy(idx.get("room")) and truthy(idx.get("mk"))
            and isinstance(p.get("secret"), str) and isinstance(p.get("computerId"), str))


def norm_pairings(doc: Any) -> dict:
    """The pairings file as a list-holder; tolerant of a missing or broken file."""
    lst = doc.get("pairings") if isinstance(doc, dict) else None
    return {"v": 1, "pairings": [p for p in lst if _usable(p)] if isinstance(lst, list) else []}


def upsert_pairing(doc: Any, *, idx: dict, account: str = "", name: str = "", relay: Any = UNDEFINED,
                   opencode_url: Any = UNDEFINED, rotate: bool = False, mint_id: Callable[[], str] = new_computer_id,
                   mint_secret: Callable[[], str] = new_relay_secret) -> dict:
    """Add this computer for an account, or refresh the existing entry (same id + secret unless `rotate`). Pure.
    → {doc, entry, isNew, sharedWith}: sharedWith names the other accounts that reach the same OpenCode."""
    relay = RELAY_URL if relay is UNDEFINED else relay
    opencode_url = DEFAULT_OPENCODE_URL if opencode_url is UNDEFINED else opencode_url
    cur = norm_pairings(doc)
    i = next((k for k, p in enumerate(cur["pairings"]) if strict_eq(p["idx"].get("room"), idx.get("room"))), -1)
    prev = cur["pairings"][i] if i >= 0 else None

    def pick(v: Any, key: str, dflt: Any) -> Any:
        if truthy(v):
            return v
        return prev[key] if prev is not None and truthy(prev.get(key)) else dflt

    entry = {
        "account": pick(account, "account", ""),
        "idx": {"room": idx.get("room"), "mk": idx.get("mk")},
        "computerId": prev["computerId"] if prev is not None else mint_id(),
        "secret": prev["secret"] if prev is not None and not rotate else mint_secret(),
        "name": pick(name, "name", None) or hostname(),
        "relay": relay,
        "opencodeUrl": prev["opencodeUrl"] if prev is not None and truthy(prev.get("opencodeUrl")) else opencode_url,
    }
    pairings = list(cur["pairings"])
    if i >= 0:
        pairings[i] = entry
    else:
        pairings.append(entry)
    others = [p for p in pairings if not strict_eq(p["idx"].get("room"), idx.get("room"))
              and strict_eq(p.get("opencodeUrl", UNDEFINED), entry["opencodeUrl"])]
    return {"doc": {"v": 1, "pairings": pairings}, "entry": entry, "isNew": prev is None,
            "sharedWith": [p["account"] if truthy(p.get("account")) else "(another account)" for p in others]}


def remove_pairings(doc: Any, account: str = "") -> dict:
    """Drop the entries matching `account` (email) — or every entry when `account` is empty. Pure."""
    cur = norm_pairings(doc)
    gone = [p for p in cur["pairings"] if not truthy(account) or strict_eq(p.get("account", UNDEFINED), account)]
    kept = [p for p in cur["pairings"] if not any(p is g for g in gone)]
    return {"doc": {"v": 1, "pairings": kept}, "removed": gone}


# ── files ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
def read_pairings(path: Path | None = None) -> dict:
    try:
        return norm_pairings(_js.parse((path or pairings_path()).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return norm_pairings(None)


def write_private(path: Path, text: str, dir_mode: int = 0o700) -> None:
    """Write a 0600 file atomically: the secret is never readable by others, not even for the moment between write and
    chmod, and a crash never leaves half a file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_in_place(path: Path, text: str) -> None:
    """Rewrite a file the user may manage (the env file — possibly a symlink): atomically at its real location, 0600
    from the first byte, so there is no moment when a new password sits in a world-readable file and no crash that
    leaves the user's other lines half-written."""
    write_private(Path(os.path.realpath(path)), text)


def serialize_pairings(doc: dict) -> str:
    return _js.stringify(doc, 1) + "\n"


def write_pairings(doc: dict, path: Path | None = None) -> None:
    write_private(path or pairings_path(), serialize_pairings(doc))


def load_pairings(path: Path | None = None, log: Callable[[str], Any] | None = None) -> list[dict]:
    """The connector's view: the list (empty when absent). Entries without a secret are skipped, loudly."""
    log = log or (lambda m: print(m, file=sys.stderr, flush=True))
    p = path or pairings_path()
    if not p.exists():
        return []
    try:
        doc = _js.parse(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        log(f"witbitz-code: {p} is not valid JSON ({e})")
        return []
    lst = doc.get("pairings") if isinstance(doc, dict) else None
    out = []
    for entry in lst if isinstance(lst, list) else []:
        secret = entry.get("secret") if isinstance(entry, dict) else None
        if isinstance(secret, str) and _js.utf16_len(secret) >= 43:
            out.append(entry)
        else:
            log("witbitz-code: skipping a pairing with no secret")
    return out
