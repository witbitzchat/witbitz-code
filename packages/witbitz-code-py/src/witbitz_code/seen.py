"""What the person has seen in the Code session list, shared by their devices — spaces/public/codeUnread.js, in Python.

The owner: "When I switch devices I get green dots". The page kept the record per device, so a session read on the phone
was news on the laptop. The computer keeps one too: the connector answers SEEN_ROUTE (GET: its record; POST a device's
record: merged, and the merge back), and every device merges with it. The rules are codeUnread.js's normSeen/mergeSeen;
tests/test_connector_e2e.py runs the same sequence against both connectors.
"""

from __future__ import annotations

import math
import re
from typing import Any

SEEN_ROUTE = "/witbitz/seen"
_SEEN_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
SEEN_MAX = 5000


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0


def _plain(v: float | int) -> float | int:
    return int(v) if isinstance(v, float) and v.is_integer() else v  # 9000.0 → 9000, as JSON.stringify writes it


def norm_seen(o: Any) -> dict:
    """A record from the wire or the disk, checked: session ids, positive numbers, at most SEEN_MAX (the latest looks kept)."""
    if not isinstance(o, dict):
        return {"since": 0, "at": {}}
    raw = o.get("at")
    entries = [(k, _plain(v)) for k, v in (raw.items() if isinstance(raw, dict) else []) if isinstance(k, str) and _SEEN_ID.fullmatch(k) and _num(v)]
    if len(entries) > SEEN_MAX:
        entries = sorted(entries, key=lambda e: -e[1])[:SEEN_MAX]
    since = o.get("since")
    return {"since": _plain(since) if _num(since) else 0, "at": dict(entries)}


def merge_seen(a: dict, b: dict) -> dict:
    """Two records → one: each session's LATER look, the EARLIER first look. The same `a` back when `b` adds nothing."""
    since = min(a["since"], b["since"]) if a["since"] and b["since"] else (a["since"] or b["since"])
    at = a["at"]
    for sid, v in b["at"].items():
        if not (sid in a["at"] and a["at"][sid] >= v):
            if at is a["at"]:
                at = dict(a["at"])
            at[sid] = v
    return a if since == a["since"] and at is a["at"] else {"since": since, "at": at}
