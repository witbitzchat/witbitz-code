"""Writes to the account: the `computers` registry and the legacy direct-server settings — tools/opencode-pair.mjs.

⚠ The registry and index2 are LIVE ACCOUNT DATA. op:'state' REPLACES a doc, so every write here READS first, refuses
  unless that read was a definitive 200, merges, writes the whole doc back, and verifies by reading it again.
"""

from __future__ import annotations

import time
from typing import Any

from . import _js, compress
from ._js import truthy
from .computers import (
    COMPUTERS_DOC,
    live_computers,
    norm_registry,
    with_computer,
    without_computer,
)
from .net import ApiCall

# Account docs above ~24 KB are gzip-wrapped as { z } (roomSync.js pushIndexDoc) — the same rule as the app.
GZIP_OVER = 24000


def _now_ms() -> int:
    return int(time.time() * 1000)


def unwrap_index_state(state: Any) -> Any:
    return compress.gunzip_b64(state["z"]) if isinstance(state, dict) and isinstance(state.get("z"), str) else state


def wrap_index_state(state: Any) -> Any:
    return {"z": compress.gzip_b64(state)} if compress.HAS_GZIP and compress.json_bytes(state) > GZIP_OVER else state


async def read_doc(call: ApiCall, idx: dict, name: str) -> dict:
    rd = await call({"op": "state", "room": idx["room"], "mk": idx["mk"], "name": name})
    j = rd.j
    err = j.get("error") if isinstance(j, dict) else None
    if rd.status != 200 or not truthy(j) or truthy(err):
        detail = f": {_js.js_string(err)}" if truthy(err) else ""
        return {"ok": False, "why": f"{name} read refused ({rd.status}{detail}) — NOT writing"}
    try:
        state = j.get("state") if isinstance(j, dict) else None
        return {"ok": True, "state": unwrap_index_state(state if truthy(state) else None)}
    except Exception as e:  # a gzip wrap that does not open
        return {"ok": False, "why": f"{name} unreadable ({e}) — NOT writing"}


def _write_body(idx: dict, name: str, patch: Any, summary: str) -> dict:
    return {"op": "state", "room": idx["room"], "mk": idx["mk"], "name": name, "patch": patch, "summary": summary, "by": "node"}


async def publish_computer(*, call: ApiCall, idx: dict, computer_id: str, name: str, relay: str, secret: str,
                           now: float | None = None) -> dict:
    """Put (or refresh) this computer in the account's registry."""
    now = _now_ms() if now is None else now
    rd = await read_doc(call, idx, COMPUTERS_DOC)
    if not rd["ok"]:
        return rd
    nxt = with_computer(rd["state"], computer_id, {"name": name, "relay": relay, "secret": secret}, now)
    wr = await call(_write_body(idx, COMPUTERS_DOC, wrap_index_state({**nxt, "at": now}), "computer paired"))
    if wr.status != 200:
        return {"ok": False, "why": f"computers write refused ({wr.status})"}
    back = await read_doc(call, idx, COMPUTERS_DOC)
    got = norm_registry(back["state"])["computers"].get(computer_id) if back["ok"] else None
    if not got or got.get("removed") or got.get("secret") != secret:
        return {"ok": False, "why": "wrote the registry but the read-back does not match — check the account before relying on it"}
    return {"ok": True, "computers": live_computers(back["state"])}


async def unpublish_computer(*, call: ApiCall, idx: dict, computer_id: str, now: float | None = None) -> dict:
    """Tombstone this computer in the account's registry (its secret leaves the account). Nothing there → nothing written."""
    now = _now_ms() if now is None else now
    rd = await read_doc(call, idx, COMPUTERS_DOC)
    if not rd["ok"]:
        return rd
    cur = norm_registry(rd["state"])["computers"].get(computer_id)
    if not cur or cur.get("removed"):
        return {"ok": True, "noop": True}
    nxt = without_computer(rd["state"], computer_id, now)
    wr = await call(_write_body(idx, COMPUTERS_DOC, wrap_index_state({**nxt, "at": now}), "computer unpaired"))
    if wr.status != 200:
        return {"ok": False, "why": f"computers write refused ({wr.status})"}
    back = await read_doc(call, idx, COMPUTERS_DOC)
    e = norm_registry(back["state"])["computers"].get(computer_id) if back["ok"] else None
    if not e or not e.get("removed"):
        return {"ok": False, "why": "wrote the tombstone but the read-back does not show it"}
    return {"ok": True}


async def clear_legacy_direct(*, call: ApiCall, idx: dict, now: float | None = None) -> dict:
    """The OLD direct path (pre-relay): empty index2.code.base/pass so no device keeps dialling a server address. Keeps
    contacts, calendar and the chosen model/agent; nothing set → nothing written."""
    now = _now_ms() if now is None else now
    rd = await read_doc(call, idx, "index2")
    if not rd["ok"]:
        return rd
    s = rd["state"] if isinstance(rd["state"], dict) else {}
    prev = s.get("code") if isinstance(s.get("code"), dict) else None
    if not prev or (not truthy(prev.get("base")) and not truthy(prev.get("pass"))):
        return {"ok": True, "noop": True}
    prev_mod = _js.to_number(prev.get("mod", _js.UNDEFINED))
    prev_mod = prev_mod if prev_mod == prev_mod and prev_mod != 0 else 0  # Number(prev.mod) || 0
    code = {
        "base": "",
        "pass": "",
        "model": prev["model"] if isinstance(prev.get("model"), str) else "",
        "agent": prev["agent"] if isinstance(prev.get("agent"), str) else "",
        "mod": _js.clean_number(max(now, prev_mod + 1)),
    }
    nxt = dict(s)
    nxt["v"] = s["v"] if truthy(s.get("v")) else 2
    nxt["code"] = code
    nxt["at"] = now
    wr = await call(_write_body(idx, "index2", wrap_index_state(nxt), "code direct server cleared"))
    if wr.status != 200:
        return {"ok": False, "why": f"index2 write refused ({wr.status})"}
    back = await read_doc(call, idx, "index2")
    bs = back.get("state") if back["ok"] else None
    bc = bs.get("code") if isinstance(bs, dict) else None
    if not back["ok"] or not truthy(bs) or not truthy(bc) or not isinstance(bc, dict) or bc.get("base") != "" or bc.get("pass") != "":
        return {"ok": False, "why": "cleared index2 but the read-back does not match"}
    return {"ok": True}
