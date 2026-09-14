"""The connector end to end, driven as the Code page drives it, against a fake OpenCode that checks the password and a
fake relay that records what it forwards.

- CONFORMANCE: one protocol sequence (nonce, 400/409/403/413/499/504, per-client subscriptions, replay across a
  restart) run against BOTH connectors — the Python one and tools/opencode-connector.mjs — with a Python client.
- THE PAGE: the real page transport (spaces/public/codeTransport.js) drives the Python connector, including a connector
  restart mid-request: the pending read is re-asked under the new nonce and the event stream is renewed.
- Python-only failure paths: relay drop → new nonce, per-client TTL, a stuck socket, stopping mid-request.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import tempfile
import urllib.parse
from pathlib import Path

import pytest
from conftest import _PRELUDE, NODE, js_source, node_env, requires_node, run_node
from fakes import BIG, PASSWORD, FakeOpenCode, fake_relay, until
from websockets.asyncio.client import connect as ws_connect

from witbitz_code import _js
from witbitz_code import connector as conn
from witbitz_code.connector import pairings_for_port, sse_reader, start_connector
from witbitz_code.relay import RelayPeer, new_relay_secret

AUTH = "Basic " + base64.b64encode(f"opencode:{PASSWORD}".encode()).decode()
EVENTS = [{"type": "message.part.delta", "properties": {"delta": f"tok{i} ✓😀"}} for i in range(30)]
CURRENT = object()  # PyClient.call: use the nonce from the latest hello


def sha(s: str) -> str:
    return hashlib.sha256(_js.utf8(s)).hexdigest()


def run(coro, timeout=120):
    return asyncio.run(asyncio.wait_for(coro, timeout))


class Rig:
    async def __aenter__(self):
        self.relay = await fake_relay()
        self.oc = FakeOpenCode(auto_events=EVENTS)
        self.secret = new_relay_secret()
        self.attach_root = Path(tempfile.mkdtemp(prefix="wb-conf-att-"))  # never the real ~/.witbitz/code/attachments
        return self

    def pairing(self, **kw):
        return {"name": "test-box", "computerId": "cmp_test", "secret": self.secret, "relay": self.relay.url,
                "opencodeUrl": self.oc.url, "password": PASSWORD, **kw}

    def hits(self, url):
        return [s for s in self.oc.seen_copy() if (s.get("url") or "").split("?")[0] == url]  # by path, any query

    async def __aexit__(self, *exc):
        await self.relay.close()
        self.oc.close()


class PyClient:
    """A minimal page: learns the nonce from the connector's sealed hello and puts it on everything it sends."""

    def __init__(self, secret: str, relay: str, cid: str = "py-client"):
        self.got: list = []
        self.n = 0
        self.nonce = ""
        self.cid = cid
        self.peer = RelayPeer(secret=secret, role="client", relay=relay, on_message=self._on, min_backoff=0.05)

    def _on(self, m):
        if isinstance(m, dict) and m.get("t") == "hello" and isinstance(m.get("k"), str) and m["k"]:
            self.nonce = m["k"]
        self.got.append(m)

    async def start(self):
        await self.peer.start()
        assert await until(lambda: self.peer.is_open and self.peer.peers == 2, 15), "client and connector are on the channel"
        await self.peer.send({"t": "ping"})
        assert await until(lambda: bool(self.nonce), 8), "the connector announced its nonce"

    def hellos(self):
        return [m for m in self.got if isinstance(m, dict) and m.get("t") == "hello"]

    def res(self, rid):
        return next((x for x in self.got if isinstance(x, dict) and x.get("t") == "res" and x.get("id") == rid), None)

    async def send_req(self, m, p, b=None, k=CURRENT, rid=None):
        self.n += 1
        rid = rid or f"r{self.n}"
        msg = {"t": "req", "id": rid, "m": m, "p": p, **({} if b is None else {"b": json.dumps(b, ensure_ascii=False)})}
        if k is CURRENT:
            msg["k"] = self.nonce
        elif k is not None:
            msg["k"] = k
        assert await self.peer.send(msg)
        return rid

    async def call(self, m, p, b=None, k=CURRENT, rid=None, timeout=10.0):
        rid = await self.send_req(m, p, b, k, rid)
        assert await until(lambda: self.res(rid) is not None, timeout), f"a response to {m} {p}"
        return self.res(rid)

    async def sub(self, p, c=None, k=CURRENT):
        return await self.peer.send({"t": "sub", "c": c or self.cid, "k": self.nonce if k is CURRENT else k, "p": p})

    async def unsub(self, p, c=None, k=CURRENT):
        return await self.peer.send({"t": "unsub", "c": c or self.cid, "k": self.nonce if k is CURRENT else k, "p": p})

    def events(self):
        return [(m["p"], d) for m in self.got if isinstance(m, dict) and m.get("t") == "evts" for d in json.loads(m["b"])]


# ── the two connectors behind one interface ───────────────────────────────────────────────────────────────────────────
class PyConnector:
    OPTION_NAMES = {"maxSenders": "max_senders", "maxResponseBytes": "max_response_bytes", "autoDir": "auto_dir", "autoPollMs": "auto_poll_ms",
                    "attachRoot": "attach_root", "attachMaxFileBytes": "attach_max_file_bytes"}

    def __init__(self, rig, timeout_ms, **options):
        self.rig, self.timeout_ms, self.c = rig, timeout_ms, None
        self.options = {self.OPTION_NAMES[k]: v for k, v in options.items()}

    async def start(self):
        self.c = await start_connector([self.rig.pairing()], flush_ms=40, log=lambda m: None, request_timeout_ms=self.timeout_ms,
                                       **self.options)

    async def stop(self):
        if self.c:
            await self.c.aclose()
            self.c = None


JS_CONNECTOR = """
  import { startConnector } from '@TOOLS@/opencode-connector.mjs'
  const c = await startConnector({ pairings: [INPUT.pairing], flushMs: 40, log: () => {}, requestTimeoutMs: INPUT.timeoutMs, ...INPUT.options })
  console.log(JSON.stringify('ready'))
  await new Promise((r) => setTimeout(r, 120000))
  c.stop()
  process.exit(0)
"""


class JsConnector:
    def __init__(self, rig, timeout_ms, **options):
        self.rig, self.timeout_ms, self.proc, self.options = rig, timeout_ms, None, options

    async def start(self):
        self.proc = await asyncio.create_subprocess_exec(
            NODE, "--input-type=module", "-e", _PRELUDE + js_source(JS_CONNECTOR), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=node_env())
        self.proc.stdin.write(json.dumps({"pairing": self.rig.pairing(), "timeoutMs": self.timeout_ms, "options": self.options}).encode())
        self.proc.stdin.close()
        line = await asyncio.wait_for(self.proc.stdout.readline(), 20)
        assert json.loads(line) == "ready", (await self.proc.stderr.read()).decode()

    async def stop(self):
        if self.proc and self.proc.returncode is None:
            self.proc.kill()
            await self.proc.wait()
        self.proc = None


# ── CONFORMANCE: the same sequence against both connectors ───────────────────────────────────────────────────────────
async def conformance(rig: Rig, connector) -> None:
    await connector.start()
    client = PyClient(rig.secret, rig.relay.url)
    try:
        await client.start()
        hello = client.hellos()[-1]
        assert set(hello) == {"t", "ver", "name", "computerId", "k", "ts", "caps", "auto"} and hello["ver"] == "1"
        assert (hello["caps"], hello["auto"]) == (["auto", "attachments", "outputs"], []), "both connectors do Auto mode (test_auto.py), save attachments and serve produced files"
        assert (hello["name"], hello["computerId"]) == ("test-box", "cmp_test") and isinstance(hello["ts"], int)
        assert re.fullmatch(r"[A-Za-z0-9_-]{24}", hello["k"]), "18 random bytes, base64url"

        # REPLAY guard: no nonce, a wrong nonce → 409, and OpenCode never hears of it. The nonce is checked BEFORE the
        # allowlist; an over-long id is refused before either.
        for k in (None, "not-the-nonce", ""):
            r = await client.call("GET", "/agent", k=k)
            assert r["st"] == 409 and json.loads(r["b"])["error"].startswith("stale:"), (k, r)
        assert (await client.call("POST", "/session/ses_1/shell", k="nope"))["st"] == 409
        assert (await client.call("GET", "/agent", rid="x" * 65))["st"] == 400
        assert (await client.call("GET", "/agent", rid="y" * 65, k="nope"))["st"] == 400
        assert (await client.call("GET", "/agent", rid="z" * 64))["st"] == 200, "64 is still fine"
        assert len(rig.hits("/agent")) == 1

        r = await client.call("GET", "/agent")
        assert (r["st"], json.loads(r["b"])) == (200, [{"name": "build"}])
        assert rig.hits("/agent")[-1]["auth"] == AUTH, "the password never travels — the connector adds it"

        # KEYS: the two catalog answers leave the computer rebuilt from an allowlist — no credential in either.
        for path in ("/config", "/config/providers"):
            r = await client.call("GET", path)
            assert r["st"] == 200 and "SECRET" not in r["b"], (path, r)
        assert json.loads((await client.call("GET", "/config/providers"))["b"])["providers"][0]["models"] == {
            "claude-sonnet-4-6": {"name": "Claude Sonnet 4.6", "input": ["text", "image"]}}
        for p in ("/session/ses_1/shell", "/session/./message", "/session/.hidden/message", "/session/../config"):
            assert (await client.call("POST" if p.endswith("shell") else "GET", p))["st"] == 403, p
        assert (await client.call("GET", "/session/ses.with.dots_1/message"))["st"] == 200, "dots inside a segment are fine"

        big = await client.call("GET", "/session/ses_big/message")
        assert big["st"] == 200 and big["b"] == BIG
        body = {"big": "é" * 300_000 + "😀" * 3000}
        echo = await client.call("POST", "/session/ses_1/message?directory=%2Fx", body)
        assert echo["st"] == 200 and json.loads(echo["b"]) == {"echoed": body}
        huge = await client.call("GET", "/session/ses_huge/message", timeout=30)
        assert huge["st"] == 413 and json.loads(huge["b"])["error"] == "OpenCode's answer is over 30 MB — too large to send through the relay"

        # Subscriptions: a stale nonce opens nothing; interest is per client id; the stream closes with its last watcher.
        await client.sub("/event", c="phone", k="stale")
        await asyncio.sleep(0.4)
        assert rig.oc.stream_count() == 0
        await client.sub("/event", c="phone")
        await client.sub("/event", c="desk")
        assert await until(lambda: rig.oc.stream_count() == 1)
        assert await until(lambda: len(client.events()) >= 30, 10)
        assert [json.loads(d) for _, d in client.events()[:30]] == EVENTS
        await client.unsub("/event", c="phone", k="stale")
        await client.unsub("/event", c="phone")
        await asyncio.sleep(0.4)
        assert rig.oc.stream_count() == 1, "the desk is still watching"
        await client.peer.send({"t": "sub", "k": client.nonce, "p": "/event"})  # no client id: the anonymous interest
        await asyncio.sleep(0.2)
        await client.peer.send({"t": "unsub", "k": client.nonce, "p": "/event"})  # removes only that one
        await asyncio.sleep(0.4)
        assert rig.oc.stream_count() == 1, "an unsub without an id never closes the stream for the desk"
        await client.unsub("/event", c="desk")
        assert await until(lambda: rig.oc.stream_count() == 0, 5), "the last watcher leaving closes it"

        # Cancel needs the current nonce and the exact id.
        await client.send_req("GET", "/session/ses_slow/message", rid="slow")
        assert await until(lambda: len(rig.hits("/session/ses_slow/message")) == 1)
        await client.peer.send({"t": "cancel", "id": "slow", "k": "stale"})
        await asyncio.sleep(0.4)
        assert not any(s.get("aborted") for s in rig.oc.seen_copy()), "a stale cancel is ignored"
        await client.peer.send({"t": "cancel", "id": "slow", "k": client.nonce})
        assert await until(lambda: (client.res("slow") or {}).get("st") == 499, 5)
        assert await until(lambda: any(s.get("aborted") for s in rig.oc.seen_copy()), 5), "OpenCode saw the call go away"

        # A read that outlives the connector's timeout is a 504, not "cancelled".
        r = await client.call("GET", "/session/ses_slow/message", rid="slow2", timeout=10)
        assert (r["st"], json.loads(r["b"])) == (504, {"error": "OpenCode did not answer within 3 s"})

        # REPLAY ACROSS A RESTART: a turn recorded on the wire does not run again once the connector has restarted.
        rig.relay.recorded.clear()
        assert (await client.call("POST", "/session/ses_1/message", {"parts": [{"type": "text", "text": "rm -rf"}]}))["st"] == 200
        assert len(rig.hits("/session/ses_1/message")) == 2
        recorded = list(rig.relay.recorded)
        old = client.nonce
        await connector.stop()
        await connector.start()
        assert await until(lambda: client.nonce and client.nonce != old, 15), "the restarted connector announced a NEW nonce"
        channel = client.peer.channel
        async with await ws_connect(f"{rig.relay.url}/c/{channel}") as injector:
            for frame in recorded:
                await injector.send(frame)
            await asyncio.sleep(0.8)
        assert len(rig.hits("/session/ses_1/message")) == 2, "the replayed turn never reached OpenCode"
        assert (await client.call("GET", "/agent", k=old))["st"] == 409, "the old nonce is dead"
        assert (await client.call("GET", "/agent"))["st"] == 200, "the new one works"

        # ATTACHMENTS (docs/code-attachments.md): a file in a turn is saved under the attachments folder, OpenCode gets a note
        # in its place, the session gets the folder rule ONCE, the page gets the file back from the connector itself, and a
        # deleted session takes its files along. A text file needs no Tinfoil copy, so both connectors behave the same here.
        attach_root = rig.attach_root
        turn = {"parts": [{"type": "text", "text": "read it"}, {"type": "file", "mime": "text/plain", "filename": "notes.txt",
                                                                 "url": "data:text/plain;base64," + base64.b64encode(b"ZUCCHINI-771").decode()}]}
        r = await client.call("POST", "/session/ses_1/message?directory=%2Fw", turn)
        sent = json.loads(r["b"])["echoed"]
        name = "notes.txt"
        staged = hashlib.sha256(b"ZUCCHINI-771").hexdigest()[:8] + "-" + name
        assert r["st"] == 200 and [p["type"] for p in sent["parts"]] == ["text", "text"] and sent["parts"][1]["synthetic"] is True
        assert sent["parts"][1]["text"] == (
            "The user attached files. They are saved on this computer — open them with the read tool.\n"
            f"• notes.txt — 12 B — {attach_root}/ses_1/{staged}")
        assert (attach_root / "ses_1" / staged).read_bytes() == b"ZUCCHINI-771"
        patches = [h for h in rig.oc.seen_copy() if h.get("method") == "PATCH" and h["url"].startswith("/session/ses_1")]
        assert len(patches) == 1 and json.loads(patches[0]["body"]) == {"permission": [{"permission": "external_directory", "pattern": f"{attach_root}/ses_1/*", "action": "allow"}]}
        assert "directory=%2Fw" in patches[0]["url"]
        await client.call("POST", "/session/ses_1/message?directory=%2Fw", turn)
        assert len([h for h in rig.oc.seen_copy() if h.get("method") == "PATCH"]) == 1, "the rule is added once per session"
        back = await client.call("GET", f"/witbitz/attachment?session=ses_1&file={staged}")
        assert back["st"] == 200 and json.loads(back["b"]) == {"name": name, "mime": "text/plain", "size": 12, "b64": base64.b64encode(b"ZUCCHINI-771").decode()}
        assert (await client.call("GET", "/witbitz/attachment?session=ses_1&file=..%2F..%2Fpairings.json"))["st"] == 400
        assert not any(h.get("url", "").startswith("/witbitz") for h in rig.oc.seen_copy()), "OpenCode never sees the route"
        assert (await client.call("DELETE", "/session/ses_1?directory=%2Fw"))["st"] == 200
        assert await until(lambda: not (attach_root / "ses_1").exists()), "a deleted session takes its files along"

        # OUTPUTS (spaces/public/codeOutputs.js): a file a reply produced comes back for the preview under it — from the folder
        # OpenCode reports for the session, whatever folder the page claims; outside it, or a secret-looking name, refused.
        work = Path(tempfile.mkdtemp(prefix="wb-conf-out-")) / "תיקייה 1"
        (work / "out").mkdir(parents=True)
        pdf = work / "out" / "fixed.pdf"
        pdf.write_bytes(b"%PDF-1.4 fixed")
        os.utime(pdf, (1789000000, 1789000000))
        (work.parent / "other.pdf").write_bytes(b"not in the session")
        rig.oc.session_dirs["ses_out"] = str(work)
        q = lambda p, extra="": f"/witbitz/output?session=ses_out&directory=%2Fclaimed&path={urllib.parse.quote(str(p), safe='')}{extra}"  # noqa: E731
        stat = await client.call("GET", q(pdf, "&stat=1"))
        assert stat["st"] == 200 and json.loads(stat["b"]) == {"name": "fixed.pdf", "kind": "pdf", "mime": "application/pdf", "size": 14, "mtime": 1789000000000}
        full = await client.call("GET", q(pdf))
        assert full["st"] == 200 and json.loads(full["b"]) == {"name": "fixed.pdf", "kind": "pdf", "mime": "application/pdf", "size": 14, "mtime": 1789000000000,
                                                                "b64": base64.b64encode(b"%PDF-1.4 fixed").decode()}
        assert (await client.call("GET", q(work.parent / "other.pdf")))["st"] == 403
        assert (await client.call("GET", q(work / "out" / "my-secret.pdf")))["st"] == 403
        assert (await client.call("GET", f"/witbitz/output?session=ses_nope&path={urllib.parse.quote(str(pdf), safe='')}"))["st"] == 404
        assert any(h.get("url") == "/session/ses_out?directory=%2Fclaimed" for h in rig.oc.seen_copy()), "looked up in the page's project"
        assert not any(h.get("url", "").startswith("/witbitz") for h in rig.oc.seen_copy()), "OpenCode never sees the route"
    finally:
        await client.peer.aclose()
        await connector.stop()


def test_conformance_python_connector():
    async def go():
        async with Rig() as rig:
            await conformance(rig, PyConnector(rig, 2500, attachRoot=str(rig.attach_root)))

    run(go())


@requires_node
def test_conformance_js_connector_the_same_sequence():
    async def go():
        async with Rig() as rig:
            await conformance(rig, JsConnector(rig, 2500, attachRoot=str(rig.attach_root)))

    run(go())


CONNECTORS = [pytest.param(PyConnector, id="python"), pytest.param(JsConnector, id="js", marks=requires_node)]


@pytest.mark.parametrize("make", CONNECTORS)
def test_replay_within_one_nonce_rotates_it_once_later_sockets_push_the_sender_out(make):
    """tools/opencode-connector.test.mjs "REPLAY: once enough later sockets push a sender out of the window…", for both
    connectors: with a window of 2 senders, three later page sockets evict the first — the nonce rotates, and the first
    socket's recorded turn, injected from a PAGE socket, is refused."""

    async def go():
        async with Rig() as rig:
            connector = make(rig, 30_000, maxSenders=2)
            await connector.start()
            client = PyClient(rig.secret, rig.relay.url)
            later = []
            try:
                await client.start()
                rig.relay.recorded.clear()
                assert (await client.call("POST", "/session/ses_1/message", {"parts": []}))["st"] == 200
                frames = [f for f in rig.relay.recorded if '"q"' in f]
                nonce, hellos = client.nonce, len(client.hellos())
                for _ in range(3):  # iOS reconnecting: each socket is a new sender the connector hears
                    p = RelayPeer(secret=rig.secret, role="client", relay=rig.relay.url)
                    later.append(p)
                    await p.start()
                    assert await until(lambda p=p: p.is_open)
                    await p.send({"t": "ping"})
                    await asyncio.sleep(0.12)
                assert await until(lambda: len(client.hellos()) > hellos and client.nonce != nonce, 5), "a new nonce was announced"
                async with await ws_connect(f"{rig.relay.url}/c/{client.peer.channel}") as injector:
                    for f in frames:
                        await injector.send(f)
                    await asyncio.sleep(0.6)
                assert len(rig.hits("/session/ses_1/message")) == 1, "the replay never ran"
                assert (await client.call("GET", "/agent"))["st"] == 200, "the page carries on under the new nonce"
            finally:
                for p in later:
                    await p.aclose()
                await client.peer.aclose()
                await connector.stop()

    run(go())


@pytest.mark.parametrize("make", CONNECTORS)
def test_an_answer_over_the_cap_is_refused_while_reading(make):
    async def go():
        async with Rig() as rig:
            connector = make(rig, 30_000, maxResponseBytes=50_000)
            await connector.start()
            client = PyClient(rig.secret, rig.relay.url)
            try:
                await client.start()
                r = await client.call("GET", "/session/ses_big/message")
                assert (r["st"], json.loads(r["b"])) == (413, {"error": "OpenCode's answer is over <1 MB — too large to send through the relay"})
                small = await client.call("GET", "/agent")
                assert small["st"] == 200, "under the cap is untouched"
            finally:
                await client.peer.aclose()
                await connector.stop()

    run(go())


# ── THE PAGE: codeTransport.js against the Python connector ──────────────────────────────────────────────────────────
JS_PAGE = """
  import { relayTransport } from '@PUBLIC@/codeTransport.js'
  import { createInterface } from 'node:readline'
  const INPUT = JSON.parse(process.env.WBC_INPUT)
  const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]()
  const say = (v) => process.stdout.write(JSON.stringify(v) + '\\n')
  const until = async (fn, ms = 10000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 15)) } return false }
  const hex = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map((x) => x.toString(16).padStart(2, '0')).join('')
  const t = relayTransport({ computer: { secret: INPUT.secret, relay: INPUT.relay, name: 'desk' } })
  const out = { online: await until(() => t.status() === 'online', 15000) }
  const pick = (r) => ({ status: r.status, ok: r.ok, json: r.json })
  out.agent = pick(await t.request('GET', '/agent'))
  out.forbidden = (await t.request('POST', '/session/ses_1/shell')).status
  out.dot = (await t.request('DELETE', '/session/.')).status
  out.post = pick(await t.request('POST', '/session/ses_1/message?directory=%2Fhome%2Fu', { parts: [{ type: 'text', text: 'hi 😀' }] }))
  const bigBody = 'q'.repeat(400000) + '😀'.repeat(5000)
  const echo = await t.request('POST', '/session/ses_1/message', { big: bigBody })
  out.bigPost = { status: echo.status, same: (await hex(echo.json.echoed.big)) === (await hex(bigBody)) }
  const big = await t.request('GET', '/session/ses_big/message')
  out.big = { status: big.status, len: big.text.length, sha: await hex(big.text) }
  const evs = []
  t.subscribe('/event?directory=%2Fhome%2Fu', (ev) => evs.push(ev))
  out.events = await until(() => evs.length >= 30) && evs.slice(0, 30)
  // a read left pending across a connector restart
  const pending = t.request('GET', '/session/ses_once/message')
  say({ phase: 'pending' })
  await lines.next() // Python restarted the connector
  const again = await pending
  out.resent = pick(again)
  out.eventsAfterRestart = await until(() => evs.length >= 60, 15000)
  out.status = t.status()
  t.close()
  say({ phase: 'done', out })
  process.exit(0)
"""


@requires_node
def test_the_page_transport_rides_a_python_connector_restart():
    async def go():
        async with Rig() as rig:
            py = PyConnector(rig, 30_000)
            await py.start()
            proc = await asyncio.create_subprocess_exec(
                NODE, "--input-type=module", "-e", js_source(JS_PAGE), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=node_env(WBC_INPUT=json.dumps({"secret": rig.secret, "relay": rig.relay.url})))

            async def read_json():
                line = await asyncio.wait_for(proc.stdout.readline(), 60)
                assert line, (await proc.stderr.read()).decode()
                return json.loads(line)

            try:
                assert await read_json() == {"phase": "pending"}
                assert await until(lambda: rig.oc.once_calls == 1, 10), "the read reached OpenCode, which sits on it"
                await py.stop()
                await py.start()
                proc.stdin.write(b"restarted\n")
                await proc.stdin.drain()
                done = await read_json()
                assert done["phase"] == "done"
                out = done["out"]
                assert out["online"]
                assert out["agent"] == {"status": 200, "ok": True, "json": [{"name": "build"}]}
                assert out["forbidden"] == 403 and out["dot"] == 403
                assert out["post"]["json"] == {"echoed": {"parts": [{"type": "text", "text": "hi 😀"}]}}
                assert out["bigPost"] == {"status": 200, "same": True}
                assert out["big"] == {"status": 200, "len": _js.utf16_len(BIG), "sha": sha(BIG)}
                assert out["events"] == EVENTS, "in order, byte-exact"
                assert out["resent"] == {"status": 200, "ok": True, "json": {"once": 2}}, "re-asked under the new nonce"
                assert out["eventsAfterRestart"], "the stream was renewed with the new connector"
                assert out["status"] == "online"
                assert rig.oc.once_calls == 2, "asked exactly twice: the original and one re-ask"
                assert all(s["auth"] == AUTH for s in rig.oc.seen_copy() if "auth" in s)
            finally:
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
                await py.stop()

    run(go())


# ── Python-only failure paths ─────────────────────────────────────────────────────────────────────────────────────────
def _closed_port() -> int:
    """A port nothing listens on (refused at once — some hosts silently drop a well-known one like 9)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_opencode_not_running_is_a_502_naming_the_command_to_start_it():
    port = _closed_port()

    async def go():
        async with Rig() as rig:
            c = await start_connector([rig.pairing(opencodeUrl=f"http://127.0.0.1:{port}/")], log=lambda m: None)
            client = PyClient(rig.secret, rig.relay.url)
            try:
                await client.start()
                r = await client.call("GET", "/agent")
                assert r["st"] == 502
                assert json.loads(r["b"])["error"] == f"OpenCode is not answering at http://127.0.0.1:{port} — start it on that computer: witbitz-code serve"
            finally:
                await client.peer.aclose()
                await c.aclose()

    run(go())


def test_a_relay_drop_brings_a_new_nonce_and_the_env_file_password(tmp_path):
    async def go():
        env = tmp_path / "oc.env"
        env.write_bytes(f"A=1\r\nOPENCODE_SERVER_PASSWORD={PASSWORD}\r\n".encode())  # CRLF: a Windows-edited file
        async with Rig() as rig:
            logs = []
            pairing = rig.pairing(envFile=str(env))
            del pairing["password"]
            c = await start_connector([pairing], log=logs.append)
            c.peers[0].min_backoff = 0.05
            client = PyClient(rig.secret, rig.relay.url)
            try:
                await client.start()
                old = client.nonce
                states = []
                client.peer.on_state = states.append
                rig.relay.drop_all()
                assert await until(lambda: "connecting" in states and client.peer.is_open and client.peer.peers == 2
                                   and sum("relay open" in ln for ln in logs) >= 2, 10), f"both came back: {states} {logs}"
                await client.peer.send({"t": "ping"})
                assert await until(lambda: client.nonce != old, 5), "a new socket, a new nonce"
                assert (await client.call("GET", "/agent", k=old))["st"] == 409
                r = await client.call("GET", "/agent")
                assert r["st"] == 200 and rig.hits("/agent")[-1]["auth"] == AUTH
            finally:
                await client.peer.aclose()
                await c.aclose()

    run(go())


def test_subscription_interest_expires_per_client(monkeypatch):
    monkeypatch.setattr(conn, "SWEEP_EVERY_S", 0.05)
    monkeypatch.setattr(conn, "SUB_TTL_S", 0.6)

    async def go():
        async with Rig() as rig:
            c = await start_connector([rig.pairing()], flush_ms=40, log=lambda m: None)
            client = PyClient(rig.secret, rig.relay.url)
            try:
                await client.start()
                await client.sub("/event", c="phone")
                await client.sub("/event", c="desk")
                assert await until(lambda: rig.oc.stream_count() == 1)
                for _ in range(6):  # the phone keeps renewing; the desk went quiet
                    await asyncio.sleep(0.2)
                    await client.sub("/event", c="phone")
                assert rig.oc.stream_count() == 1
                assert set(c.servers[0]._subs["/event"].clients) == {"phone"}, "the desk expired on its own"
                assert await until(lambda: rig.oc.stream_count() == 0, 5), "and the phone too, once it stopped"
                await client.sub("/event?directory=%2Fa&x=1")  # not an allowed event path
                await asyncio.sleep(0.3)
                assert not any("x=1" in (s.get("url") or "") for s in rig.oc.seen_copy())
                await client.peer.send({"t": "sub", "k": client.nonce, "p": "/event"})  # no c → '_'
                assert await until(lambda: rig.oc.stream_count() == 1)
                assert set(c.servers[0]._subs["/event"].clients) == {"_"}
                await client.peer.send({"t": "unsub", "k": client.nonce, "p": "/event"})  # no c → everyone
                assert await until(lambda: rig.oc.stream_count() == 0)
            finally:
                await client.peer.aclose()
                await c.aclose()

    run(go())


def test_pairings_for_port_matches_js():
    pairings = [{"opencodeUrl": u} for u in ["http://127.0.0.1:4096", "http://127.0.0.1:4097/", "http://localhost", "https://h:443",
                                             "http://127.0.0.1:80", "not a url", "", "http://[::1]:4096", "http://h:99999",
                                             "https://127.0.0.1", "wss://h", "ws://h:80", "https://h:8443", "HTTPS://h"]]
    ports = [4096, 4097, 80, 443, "4096", 8443]
    ours = [[i for i, p in enumerate(pairings) if p in pairings_for_port(pairings, port)] for port in ports]
    if NODE:
        js = run_node("""
          import { pairingsForPort } from '@TOOLS@/opencode-connector.mjs'
          OUT(INPUT.ports.map((port) => pairingsForPort(INPUT.pairings, port).map((p) => INPUT.pairings.indexOf(p))))
        """, {"pairings": pairings, "ports": ports})
        assert ours == [[pairings.index(p) for p in [pairings[i] for i in row]] for row in js]
    assert ours[0] == [0, 6, 7], "an empty opencodeUrl means the default 127.0.0.1:4096"
    assert ours[3] == [3, 9, 13], "https: defaults to 443 (only https: — wss: counts as 80, as in JS)"


class StuckSocket:
    """A socket on a dead TCP path: send and close never return; only aborting the transport ends it."""

    def __init__(self):
        self.gone = asyncio.Event()
        self.aborted = False
        self.transport = self

    def abort(self):
        self.aborted = True
        self.gone.set()

    async def send(self, frame):
        await asyncio.Event().wait()

    async def close(self, code=1000):
        await asyncio.Event().wait()

    def __aiter__(self):
        return self

    async def __anext__(self):
        await self.gone.wait()
        raise StopAsyncIteration


def test_a_send_stuck_on_a_dead_path_drops_the_socket_reconnects_and_shutdown_stays_bounded(monkeypatch):
    from witbitz_code import relay as relay_mod

    monkeypatch.setattr(relay_mod, "SEND_TIMEOUT_S", 0.2)
    monkeypatch.setattr(relay_mod, "CLOSE_TIMEOUT_S", 0.2)

    async def go():
        sockets = []

        async def connect(url):
            sockets.append(StuckSocket())
            return sockets[-1]

        peer = RelayPeer(secret=new_relay_secret(), role="computer", relay="wss://unused.example", connect=connect, min_backoff=0.01)
        await peer.start()
        assert await until(lambda: peer.is_open)
        first, queued = peer.send({"t": "res", "id": "big", "b": "x" * 300_000}), peer.send({"t": "hello"})
        assert await asyncio.wait_for(first, 3) is False and await asyncio.wait_for(queued, 3) is False
        assert sockets[0].aborted, "the stuck socket was dropped"
        assert await until(lambda: len(sockets) >= 2 and peer.is_open, 3), "and the peer dialled again"
        await asyncio.wait_for(peer.aclose(), 3)  # close() on the new stuck socket never returns — aclose still does
        assert sockets[-1].aborted

    run(go())


def test_kick_skips_a_backoff_wait_and_reconnect_redials_an_open_socket():
    async def go():
        async with Rig() as rig:
            opened, peer_calls = [], []
            p = RelayPeer(secret=rig.secret, role="client", relay=rig.relay.url, min_backoff=60, max_backoff=60,
                          on_state=lambda s: opened.append(s), on_peers=peer_calls.append)
            await p.start()
            try:
                assert await until(lambda: p.is_open)
                rig.relay.drop_all()
                assert await until(lambda: not p.is_open and p.waiting, 5), "dropped, now waiting out a 60 s backoff"
                p.kick()
                assert await until(lambda: p.is_open, 3), "kick() skipped the wait"
                p.kick()  # open: nothing to do
                opens = opened.count("open")
                total = sum(len(v) for v in rig.relay.channels.values())
                peer_calls.clear()
                p.reconnect()
                assert await until(lambda: opened.count("open") == opens + 1 and p.is_open, 5), "redialled at once"
                assert 0 not in peer_calls, "the replaced socket's close is not reported (as the JS onclose guard)"
                assert await until(lambda: sum(len(v) for v in rig.relay.channels.values()) == total, 5), "the old socket is gone"
                # stop() during a backoff wait, start() again, kick(): still exactly one socket
                rig.relay.drop_all()
                assert await until(lambda: p.waiting, 5)
                p.stop()
                assert not p.waiting
                await p.start()
                p.kick()
                assert await until(lambda: p.is_open, 5)
                await asyncio.sleep(0.2)
                assert sum(len(v) for v in rig.relay.channels.values()) == 1, "no orphan left on the channel"
            finally:
                await p.aclose()

    run(go())


def test_stopping_the_connector_mid_request_does_not_hang():
    async def go():
        async with Rig() as rig:
            c = await start_connector([rig.pairing()], log=lambda m: None)
            client = PyClient(rig.secret, rig.relay.url)
            try:
                await client.start()
                await client.send_req("GET", "/session/ses_slow/message", rid="slow")
                assert await until(lambda: len(rig.hits("/session/ses_slow/message")) == 1)
                await asyncio.wait_for(c.aclose(), 8)
                assert client.res("slow") is None, "a stopping connector sends no answer"
            finally:
                await client.peer.aclose()

    run(go())


def test_send_resolves_false_with_no_open_socket_and_bursts_keep_order():
    async def go():
        p = RelayPeer(secret=new_relay_secret(), role="client", relay="ws://127.0.0.1:9")
        assert await p.send({"t": "req"}) is False
        with pytest.raises(ValueError):
            RelayPeer(secret=new_relay_secret(), role="page")
        async with Rig() as rig:
            got = []
            computer = RelayPeer(secret=rig.secret, role="computer", relay=rig.relay.url, on_message=lambda m: got.append(m["n"]))
            client = RelayPeer(secret=rig.secret, role="client", relay=rig.relay.url)
            await computer.start()
            await client.start()
            try:
                assert await until(lambda: computer.is_open and client.is_open and client.peers == 2)
                assert rig.relay.channels.keys() == {computer.channel}
                sends = [client.send({"t": "req", "n": i, "pad": "x" * (250_000 if i % 3 == 0 else 10)}) for i in range(20)]
                assert all(await asyncio.gather(*sends))
                assert await until(lambda: len(got) == 20, 10), got
                assert got == list(range(20))
            finally:
                await client.aclose()
                await computer.aclose()

    run(go())


def test_sse_reader_splits_like_the_js_one():
    got = []
    feed = sse_reader(got.append)
    for chunk in ["data: a\n", "\ndata: b\r\n", "data: c\r\n\r\n: comment\n\nevent: x\ndata:d\n\n", "data: partial"]:
        feed(chunk)
    assert got == ["a", "b\nc", "d"]


def test_the_nonce_is_fresh_per_socket_and_no_hello_goes_out_without_one():
    async def go():
        sent = []

        class Peer:
            peers = 2

            def send(self, m):
                sent.append(m)

        s = conn.PairingServer({"secret": new_relay_secret(), "name": "n"}, client=None, flush_ms=10, log=lambda m: None)
        s.peer = Peer()
        assert s.hello() is None and sent == []
        s._on_state("open")
        s._on_state("open")
        ks = [m["k"] for m in sent]
        assert len(ks) == 2 and ks[0] != ks[1] and all(len(base64.urlsafe_b64decode(k + "==")) == 18 for k in ks)
        assert os.environ.get("WITBITZ_CODE_BUNDLED") is None

    run(go())
