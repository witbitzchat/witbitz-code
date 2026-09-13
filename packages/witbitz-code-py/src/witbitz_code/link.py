"""Make this computer an ADDED DEVICE of a Spaces account by device-link — tools/rc-link.mjs.

It shows a QR carrying an ephemeral PUBLIC key (no secret); a signed-in phone or desktop scans it (Settings → Back up &
recovery → Add a device) and seals the account to that key; this process opens the reply. The reply is relayed
content-blind through /api/link between two public keys the server cannot combine.

Unlike rc-link.mjs this never writes the account to disk: the pairing flow needs it only long enough to publish the
computer, so it stays in memory.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import _js, devicelink, net, qr
from ._js import truthy

DEFAULT_ORIGINS = "https://spaces.witbitz.chat,https://witbitz-spaces.pages.dev"
POLL_S = 2.5
LIFE_MS = 300_000  # the ref stays valid until a seal is posted, so a slow (Google-failed → email-code) verification fits


def parse_origins(env: Any) -> list[str]:
    """Poll EVERY origin whose /api/link relay is live — the node connects whichever one the phone sealed the reply to."""
    s = _js.js_string(env if truthy(env) else DEFAULT_ORIGINS)
    return [o for o in (re.sub(r"/\Z", "", _js.trim(x)) for x in s.split(",")) if o]


def _now_ms() -> int:
    return int(time.time() * 1000)


def account_from_payload(pay: Any) -> dict | None:
    """The account this computer now belongs to, from an opened link payload: the master + the index-room pointer."""
    if not isinstance(pay, dict) or not isinstance(pay.get("master"), str) or not pay["master"]:
        return None
    anchor = pay.get("anchor")
    email = pay.get("email") if truthy(pay.get("email")) else (anchor.get("email") if isinstance(anchor, dict) else None)

    def orelse(v: Any, dflt: Any) -> Any:
        return v if truthy(v) else dflt

    return {
        "v": 1,
        "linkedAt": _now_ms(),
        "master": pay["master"],
        "code": orelse(pay.get("code"), ""),
        "email": orelse(email, ""),
        "idx": orelse(pay.get("idx"), None),
        "rel": orelse(pay.get("rel"), None),
        "pipes": orelse(pay.get("pipes"), None),
        "anchor": orelse(anchor, None),
    }


def _node_base64(s: str) -> bytes:
    """Buffer.from(s, 'base64'): lenient — stops at '=', skips anything outside the alphabet."""
    body = re.sub(r"[^A-Za-z0-9+/]", "", s.split("=", 1)[0])
    body = body[: len(body) - (len(body) % 4 == 1)]
    return _js.atob(body)


async def pull_index_room(account: Any, origins: list[str], post_json: net.PostJson) -> dict | None:
    """GAP-CLOSER: the link carried no index-room pointer → derive the backup location from the master, read the gated
    backup with the release token, and take its indexRoom {room, mk}. Tries each origin; the pointer or None."""
    if not isinstance(account, dict) or not truthy(account.get("master")):
        return None
    try:
        master = _node_base64(_js.js_string(account["master"]).replace("-", "+").replace("_", "/"))
    except ValueError:
        return None
    if len(master) != 32:
        return None
    loc = devicelink.derive_keys_from_secret(master)
    rel = account.get("rel")
    token = rel.get("token") if isinstance(rel, dict) else None
    for origin in origins:
        blob = None
        if truthy(token):
            try:
                r = await post_json(f"{origin}/api/backup/release", {"token": token, "id": loc["id"]})
                if isinstance(r, dict) and truthy(r.get("ok")) and truthy(r.get("blob")):
                    blob = r["blob"]
            except Exception:
                pass  # try the next origin
        if not blob:
            continue
        try:
            payload = devicelink.unseal(loc["key"], blob)
            ir = payload.get("indexRoom") if isinstance(payload, dict) else None
            if isinstance(ir, dict) and truthy(ir.get("room")) and truthy(ir.get("mk")):
                return ir
        except Exception:
            pass  # wrong key / tamper
    return None


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


def _out(*a: Any, **kw: Any) -> None:
    print(*a, flush=True, **kw)


def _err(*a: Any) -> None:
    print(*a, file=sys.stderr, flush=True)


async def link_node(*, life_ms: float | None = None, poll_s: float = POLL_S, origins: list[str] | None = None,
                    get_json: net.GetJson | None = None, post_json: net.PostJson | None = None,
                    challenge: devicelink.LinkChallenge | None = None, svg_path: Path | None = None,
                    out: Callable = _out, err: Callable = _err) -> dict | None:
    """Show the device-link QR and wait for a signed-in device to seal the account to this computer. Returns the account,
    or None when it did not complete (expired, or a reply that would not open) — never exits the process."""
    if origins is None:
        origins = parse_origins(os.environ.get("RC_LINK_ORIGIN"))
    if life_ms is None:
        raw = os.environ.get("RC_LINK_WAIT_MS")
        life_ms = _js.to_number(raw) if raw else LIFE_MS
    client = None
    if get_json is None or post_json is None:
        client = net.new_client()
        get_json = get_json or net.make_get_json(client)
        post_json = post_json or net.make_post_json(client)
    try:
        return await _link(life_ms, poll_s, origins, get_json, post_json, challenge, svg_path, out, err)
    finally:
        if client is not None:
            await client.aclose()


async def _link(life_ms, poll_s, origins, get_json, post_json, challenge, svg_path, out, err) -> dict | None:
    ch = challenge or devicelink.new_link_challenge()
    out(f"witbitz-code: pairing this computer with your account · polling {', '.join(origins)}\n")
    out(qr.qr_ansi(ch.text) + "\n")
    svg = svg_path or Path.home() / ".witbitz-rc.link.svg"
    try:
        _write_private(svg, qr.qr_svg(ch.text) + "\n")
        out(f"  (QR also saved to {svg} · raw: {ch.text})")
    except OSError:
        out(f"  (raw: {ch.text})")
    wait_s = life_ms / 1000 if math.isfinite(life_ms) else 0
    out(f"  waiting up to {round(wait_s)}s for your device to seal the account to this computer…\n")
    until = time.monotonic() + wait_s
    warned = False
    while time.monotonic() < until:
        await asyncio.sleep(poll_s)
        r = None
        for origin in origins:
            try:
                rr = await get_json(f"{origin}/api/link?ref={ch.ref}")
            except Exception:
                continue
            if isinstance(rr, dict) and rr.get("reason") == "unavailable" and not warned:
                err(f"witbitz-code: note — {origin} has no device-link relay; ignoring it.")
                warned = True
            if isinstance(rr, dict) and truthy(rr.get("ok")):
                r = rr
                break
        if r is None:
            continue  # 404 on all = not sealed yet
        pay = None
        try:
            pay = devicelink.read_link_payload(devicelink.open_link_reply(ch.priv, {"ref": ch.ref, "epk": r.get("epk"), "blob": r.get("blob")}))
        except Exception:
            pass  # not ours / tampered
        if not pay:
            err("witbitz-code: a reply arrived but did not open — start again on both devices.")
            return None
        account = account_from_payload(pay)
        if not account:
            err("witbitz-code: the reply carried no account key.")
            return None
        via = "link" if account["idx"] else ""
        if not account["idx"]:
            out("witbitz-code: no index pointer in the link — recovering it from your account backup… ", end="")
            idx = None
            try:
                idx = await pull_index_room(account, origins, post_json)
            except Exception:
                pass
            if idx:
                account["idx"], via = idx, "backup"
                out("✓")
            else:
                out("not found (the release token may have expired — pair again)")
        out(f"witbitz-code: ✓ linked as a device of {account['email'] or '(your account)'}")
        room = account["idx"].get("room") if isinstance(account["idx"], dict) else None
        out(f"  index room → {room} (via {via})" if account["idx"] else "  index room → (none)")
        return account
    err("witbitz-code: the code expired before your device sealed to it. Run it again for a fresh QR.")
    return None
