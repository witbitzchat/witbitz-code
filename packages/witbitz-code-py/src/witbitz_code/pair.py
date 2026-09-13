"""PAIR this computer with your Spaces account, so the Code section on every device you are signed in on reaches the
OpenCode running here — through the sealed relay, with nothing typed. The flows of tools/opencode-pair.mjs.

What a pairing is (docs/opencode-relay.md §3): a random 32-byte SECRET per (computer, account), stored here in
~/.witbitz/code/pairings.json (0600) and published into the account's sealed `computers` registry, which every signed-in
device reads. The relay channel and both encryption keys derive from it; the relay never sees it.

Several accounts can pair the same computer — each is a separate entry, secret and channel (§10). OpenCode has no users,
so every paired account reaches the same sessions, files and shell; this tool says so when a second account pairs.
"""

from __future__ import annotations

import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from . import account as acct
from . import link, net
from . import pairings as pp
from ._js import UNDEFINED, number_str, to_number, truthy
from .connector import START_HINT

LinkFn = Callable[[], Awaitable[Any]]


def _out(msg: str) -> None:
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class UsageError(Exception):
    pass


@dataclass
class Args:
    rotate: bool = False
    dry: bool = False
    unpair: bool = False
    status: bool = False
    name: str = ""
    account: str = ""
    opencode_url: str = ""


def parse_args(argv: list[str]) -> Args:
    a = Args()
    i = 0
    while i < len(argv):
        x = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if x == "--rotate":
            a.rotate = True
        elif x == "--dry-run":
            a.dry = True
        elif x == "--unpair":
            a.unpair = True
        elif x == "--status":
            a.status = True
        elif x in ("--name", "--account", "--opencode-url", "--port"):
            i += 1
            if x == "--name":
                a.name = nxt
            elif x == "--account":
                a.account = nxt
            elif x == "--opencode-url":
                a.opencode_url = nxt
            else:
                port = to_number(nxt)
                if truthy(port):
                    a.opencode_url = f"http://127.0.0.1:{number_str(port)}"
        else:
            raise UsageError(f"witbitz-code: unknown argument {x}")
        i += 1
    return a


def ensure_local_password(out: Callable[[str], Any] = _out) -> None:
    path = pp.env_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        text = ""
    if pp.env_get(text, "OPENCODE_SERVER_PASSWORD"):
        return
    pp.write_in_place(path, pp.env_set(text, "OPENCODE_SERVER_PASSWORD", pp.new_password()))
    out(f"witbitz-code: ✓ minted a local OpenCode password in {path} (0600) — it never leaves this computer")


async def _publish_entry(call: net.ApiCall, e: dict, out: Callable, err: Callable) -> bool:
    r = await acct.publish_computer(call=call, idx=e["idx"], computer_id=e["computerId"], name=e["name"], relay=e["relay"],
                                    secret=e["secret"])
    who = e["account"] or "account"
    if not r["ok"]:
        err(f"witbitz-code: ✖ {who}: {r['why']}")
        return False
    out(f"witbitz-code: ✓ \"{e['name']}\" is in {e['account'] or 'the account'}'s computers ({len(r['computers'])} paired)")
    lg = await acct.clear_legacy_direct(call=call, idx=e["idx"])
    if not lg["ok"]:
        out(f"witbitz-code: ⚠ could not clear the old direct-server settings ({lg['why']}) — harmless while a computer is paired")
    elif not lg.get("noop"):
        out("witbitz-code: ✓ cleared the old direct-server address from the account (devices use the relay now)")
    return True


async def _link_by_qr(link_fn: LinkFn | None, out: Callable, err: Callable) -> dict | None:
    """The QR ritual: show the Add-a-device QR and wait for a signed-in device to seal the account to this computer. The
    account stays in memory; an expired or failed scan changes nothing."""
    out("witbitz-code: on your phone open Spaces → Settings → Back up & recovery → Add a device, and scan the QR below "
        "with the account to pair.\n")
    account = await (link_fn() if link_fn else link.link_node())
    if not account:
        return None
    idx = account.get("idx")
    if not isinstance(idx, dict) or not truthy(idx.get("room")) or not truthy(idx.get("mk")):
        err("witbitz-code: the scan carried no index-room pointer, so there is nowhere to publish — nothing changed.")
        return None
    return account


async def main(argv: list[str], *, call: net.ApiCall | None = None, link_fn: LinkFn | None = None,
               out: Callable[[str], Any] = _out, err: Callable[[str], Any] = _err) -> int:
    """pair / --status / --unpair / --rotate. Returns the exit code."""
    try:
        args = parse_args(argv)
    except UsageError as e:
        err(str(e))
        return 2
    client = None
    if call is None and not args.status:
        client = net.new_client()
        call = net.make_api_call(client)
    try:
        return await _run(args, call, link_fn, out, err)
    finally:
        if client is not None:
            await client.aclose()


async def _run(args: Args, call: Any, link_fn: LinkFn | None, out: Callable, err: Callable) -> int:
    doc = pp.read_pairings()

    if args.status:
        if not doc["pairings"]:
            out("witbitz-code: not paired")
        for p in doc["pairings"]:
            out(f"· \"{p.get('name')}\" → {p.get('account') or '(account)'} · OpenCode {p.get('opencodeUrl')} · relay {p.get('relay')}")
        return 0

    if args.unpair:
        targets = [p for p in doc["pairings"] if not args.account or p.get("account") == args.account]
        if not targets:
            err(f"witbitz-code: no pairing{' for ' + args.account if args.account else ''} on this computer")
            return 1
        if len(targets) > 1 and not args.account:
            names = ", ".join(str(p.get("account")) for p in targets)
            err(f"witbitz-code: this computer is paired with {len(targets)} accounts ({names}) — pass --account <email>")
            return 1
        if args.dry:
            out(f"witbitz-code: --dry-run — would remove \"{targets[0].get('name')}\" from {targets[0].get('account')}")
            return 0
        ok = True
        for p in targets:
            r = await acct.unpublish_computer(call=call, idx=p["idx"], computer_id=p["computerId"])
            if not r["ok"]:
                ok = False
                err(f"witbitz-code: ✖ {p.get('account')}: {r['why']} — kept the local pairing so you can retry")
                continue
            note = " (it was not listed)" if r.get("noop") else ""
            out(f"witbitz-code: ✓ removed \"{p.get('name')}\" from {p.get('account')}{note} — every device drops it on its next sync")
            pp.write_pairings(pp.remove_pairings(pp.read_pairings(), p.get("account") or "")["doc"])
        out(f"witbitz-code: restart the connector ({START_HINT}) so it stops answering on the old channel.")
        return 0 if ok else 1

    if args.rotate:
        if not doc["pairings"]:
            err("witbitz-code: nothing to rotate — pair first")
            return 1
        to_rotate = [x for x in doc["pairings"] if not args.account or x.get("account") == args.account]
        if args.dry:
            out(f"witbitz-code: --dry-run — would rotate {len(to_rotate)} pairing(s)")
            return 0
        cur, ok = doc, True
        for p in to_rotate:
            u = pp.upsert_pairing(cur, account=p.get("account") or "", idx=p["idx"], name=p.get("name") or "",
                                  relay=p.get("relay", UNDEFINED), opencode_url=p.get("opencodeUrl", UNDEFINED), rotate=True)
            if await _publish_entry(call, u["entry"], out, err):
                cur = u["doc"]
                pp.write_pairings(cur)
            else:
                ok = False
        out("witbitz-code: restart the connector so it listens on the new channel(s).")
        return 0 if ok else 1

    # PAIR — the QR ritual
    if args.dry:
        out("witbitz-code: --dry-run — would show the QR, then publish this computer to the scanning account")
        return 0
    account = await _link_by_qr(link_fn, out, err)
    if not account:
        err("witbitz-code: pairing did not complete — nothing changed.")
        return 1
    u = pp.upsert_pairing(doc, account=account.get("email") or "", idx=account["idx"], name=args.name,
                          opencode_url=args.opencode_url or UNDEFINED)
    ensure_local_password(out)
    if not await _publish_entry(call, u["entry"], out, err):
        err("witbitz-code: nothing saved locally — scan again to retry.")
        return 1
    pp.write_pairings(u["doc"])
    e = u["entry"]
    out(f"witbitz-code: ✓ {'paired' if u['isNew'] else 'refreshed'} \"{e['name']}\" with {e['account'] or 'your account'} ({pp.pairings_path()})")
    if u["sharedWith"]:
        out(f"witbitz-code: ⚠ this computer's OpenCode ({e['opencodeUrl']}) is now reachable from {e['account']} AND {', '.join(u['sharedWith'])}.")
        out("              OpenCode has no users: they share every session, file and shell. Fine for your own accounts;")
        out("              for another person run a separate OpenCode (another port and OS user) and pair with --opencode-url.")
    out(f"witbitz-code: next — start OpenCode and the connector:  {START_HINT}")
    return 0
