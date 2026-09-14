"""The Code section's end on YOUR computer — tools/opencode-connector.mjs.

OpenCode stays on 127.0.0.1. This process dials OUT to the sealed relay once per pairing and does for the Code page what a
browser on the same machine would do: it calls OpenCode's HTTP API (with the local password, which never leaves this
machine) and streams OpenCode's events back — every frame sealed with keys derived from the pairing secret, so the relay
forwards bytes it cannot read.

It serves ONLY the calls the Code page makes (relay.allowed_request): OpenCode can run shell commands here, so a leaked
secret must not unlock more than the page itself can do.
"""

from __future__ import annotations

import asyncio
import base64
import codecs
import math
import os
import re
import sys
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import _js
from .attachments import (ATTACHMENT_ROUTE, MAX_FILE_BYTES, attachment_rule, default_root, prune_attachments,
                          remove_session_attachments, serve_attachment, stage_message_body)
from .auto_runner import AutoRunner
from .pairings import DEFAULT_OPENCODE_URL, hostname, read_env_password
from .relay import RELAY_URL, Connect, RelayPeer, allowed_event_path, allowed_request, project_response

VERSION = "1"  # the hello protocol version, as the JS connector sends it
REQUEST_TIMEOUT_MS = 30_000
HELLO_EVERY_S = 20.0  # the page counts the computer online while a hello arrived in the last 30 s
SUB_TTL_S = 75.0  # a page re-subscribes every 30 s; a client that stops renewing is dropped
SWEEP_EVERY_S = 15.0
MAX_RESPONSE = 30 * 1024 * 1024  # bytes; below the page's 32 MiB reassembly cap: refuse while reading, not by a timeout
START_HINT = "witbitz-code serve"
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")  # an HTTP method fetch() would accept


def default_auto_dir() -> Path:
    """Auto mode's state (per pairing) and its verdict log — the JS connector's AUTO_DIR."""
    return Path(os.environ.get("WITBITZ_CODE_AUTO_DIR") or Path.home() / ".witbitz" / "code")


def _round(x: float) -> int:
    return math.floor(x + 0.5)  # Math.round, not banker's rounding


def sse_reader(on_data: Callable[[str], Any]) -> Callable[[str], None]:
    """Split an SSE text stream into `data:` payloads (one per event, multi-line data joined) — the JS sseReader,
    including what it does not handle (a bare \\r line ending), so both connectors deliver the same events."""
    buf = ""
    sep = re.compile(r"\r?\n\r?\n")

    def feed(chunk: str) -> None:
        nonlocal buf
        buf += chunk
        while True:
            m = sep.search(buf)
            if not m:
                return
            block, buf = buf[: m.start()], buf[m.end():]
            lines = re.split(r"\r?\n", block)
            data = "\n".join(re.sub(r"\A ", "", ln[5:]) for ln in lines if ln.startswith("data:"))
            if data:
                on_data(data)

    return feed


def pairings_for_port(pairings: list[dict], port: Any) -> list[dict]:
    """The pairings served by the OpenCode on `port`. Two connectors (one OpenCode per account) must never both answer
    the same channel — every event would arrive twice — so each serves only the pairings that point at its own port."""
    return [p for p in pairings if _url_port(p.get("opencodeUrl") or DEFAULT_OPENCODE_URL) == _js.to_number(port)]


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def _url_port(url: Any) -> float:
    """new URL(url).port, which is '' for the scheme's own default port; '' counts as 443 for https:, else 80."""
    try:
        u = urlsplit(_js.trim(_js.js_string(url)))
        if not u.scheme or not u.netloc:
            return math.nan
        port = u.port
    except ValueError:
        return math.nan
    if port is None or port == _DEFAULT_PORTS.get(u.scheme.lower()):
        return 443 if u.scheme.lower() == "https" else 80  # u.port || (https: ? 443 : 80) — ws/wss/ftp count as 80
    return port


@dataclass
class _Sub:
    clients: dict  # client id → last renewed (monotonic s); the stream is shared, interest is per device
    buffer: list = field(default_factory=list)
    task: asyncio.Task | None = None
    timer: asyncio.TimerHandle | None = None


class _Inflight:
    def __init__(self) -> None:
        self.aborted = False
        self.timed_out = False
        self.task: asyncio.Task | None = None

    def abort(self) -> None:
        self.aborted = True
        if self.task is not None:
            self.task.cancel()

    def time_out(self) -> None:
        self.timed_out = True
        self.abort()


_ALL = object()  # internal only: close a stream for every client (nobody watching, the sweep emptied it, stopping)


class _TooLarge(Exception):
    pass


def _client_id(c: Any) -> str:
    return _js.utf16_slice(c, 0, 64) if isinstance(c, str) and c else "_"


class PairingServer:
    """One pairing: one RelayPeer on its channel, serving one local OpenCode."""

    def __init__(self, pairing: dict, *, client: httpx.AsyncClient, flush_ms: float, log: Callable[[str], Any],
                 connect: Connect | None = None, request_timeout_ms: float = REQUEST_TIMEOUT_MS, max_senders: int = 64,
                 max_response_bytes: int = MAX_RESPONSE, auto_dir: Path | None = None, auto_poll_ms: float = 1000,
                 attach_root: Path | None = None, attach_max_file_bytes: int = MAX_FILE_BYTES) -> None:
        self.pairing = pairing
        # Attachments, the Claude Code way (docs/code-attachments.md): files a turn carries are saved here, per session.
        self._attach_root = Path(attach_root) if attach_root else default_root()
        self._attach_max = attach_max_file_bytes
        self._ruled: set[str] = set()
        self._pruned_at = time.time()
        self.name = pairing.get("name") if _js.truthy(pairing.get("name")) else hostname()
        self.base = re.sub(r"/+\Z", "", _js.js_string(pairing.get("opencodeUrl") or DEFAULT_OPENCODE_URL))
        self._client = client
        self._flush_s = flush_ms / 1000
        self._timeout_ms = request_timeout_ms
        self._max_response = max_response_bytes
        self._log = log
        self._inflight: dict[str, _Inflight] = {}
        self._subs: dict[str, _Sub] = {}
        self._tasks: set[asyncio.Task] = set()
        self._stopping = False
        # ★ REPLAY ACROSS RESTARTS. The frame layer drops a replay only while this process remembers the sender, so a
        #   sealed request recorded earlier (by anyone on the path — the relay included) could be re-sent after a restart
        #   and run again. Each socket therefore announces a fresh random nonce inside its sealed hello, and a request
        #   must carry the CURRENT one: a recording from before a restart or reconnect carries a nonce nobody accepts.
        self.nonce = ""
        self.peer = RelayPeer(secret=pairing["secret"], role="computer", relay=pairing.get("relay") or RELAY_URL,
                              on_state=self._on_state, on_peers=self._on_peers, on_message=self._on_message, connect=connect,
                              # A page socket fell out of the replay window: its recorded frames would open again — rotate the
                              # nonce so every request it ever sealed is refused, and tell the pages (they re-ask reads).
                              on_evict=lambda _sender: self._rotate(), max_senders=max_senders)
        # Auto mode's loop for this pairing (docs/code-auto-mode.md) — its state is read now, so the first hello lists it.
        safe_id = _js.utf16_slice(re.sub(r"[^A-Za-z0-9_-]", "_", _js.js_string(pairing.get("computerId") or "default")), 0, 64)
        auto_dir = Path(auto_dir) if auto_dir else default_auto_dir()
        self.auto = AutoRunner(base=self.base, auth=self._auth, client=client, poll_ms=auto_poll_ms, log=log,
                               state_path=auto_dir / f"auto-{safe_id}.json", log_path=auto_dir / "auto-log.jsonl",
                               on_verdict=lambda v: self.peer.send({"t": "autoverdict", **v, "ts": int(time.time() * 1000)}))

    # ── lifecycle ─────────────────────────────────────────────────────────────────────────────────────────────────────
    async def start(self) -> None:
        self._spawn(self._every(SWEEP_EVERY_S, self._sweep))
        self._spawn(self._every(HELLO_EVERY_S, lambda: self.hello() if self.peer.peers >= 2 else None))
        self.auto.start()
        await self.peer.start()

    def stop(self) -> None:
        self._stopping = True
        self.auto.stop()
        for p in list(self._subs):
            self._unsubscribe(p, _ALL)
        for c in list(self._inflight.values()):
            c.abort()
        for t in list(self._tasks):
            t.cancel()
        self.peer.stop()

    async def aclose(self) -> None:
        self.stop()
        await self.peer.aclose()
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=5)

    def _spawn(self, coro: Any) -> asyncio.Task:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    @staticmethod
    async def _every(seconds: float, fn: Callable[[], Any]) -> None:
        while True:
            await asyncio.sleep(seconds)
            fn()

    # ── relay events ──────────────────────────────────────────────────────────────────────────────────────────────────
    def _on_state(self, s: str) -> None:
        self._log(f"witbitz-code: {self.name} · relay {s}")
        if s == "open":
            self._rotate()

    def _rotate(self) -> None:
        self.nonce = _js.b64u(os.urandom(18))
        self.hello()

    def _on_peers(self, n: int) -> None:
        if n >= 2:
            self.hello()
        else:
            for p in list(self._subs):
                self._unsubscribe(p, _ALL)  # nobody is watching: close OpenCode's streams

    def _on_message(self, m: Any) -> None:
        self._spawn(self._handle_logged(m))

    async def _handle_logged(self, m: Any) -> None:
        try:
            await self._handle(m)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._log(f"witbitz-code: {self.name} · {e}")

    def hello(self) -> asyncio.Future | None:
        if not self.nonce:
            return None  # no hello before this socket has its nonce
        # caps: what this connector can do beyond the requests — a page shows the Auto switch only when `auto` is here.
        return self.peer.send({"t": "hello", "ver": VERSION, "name": self.name, "computerId": self.pairing.get("computerId") or "",
                               "k": self.nonce, "ts": int(time.time() * 1000), "caps": ["auto", "attachments"], "auto": self.auto.sessions()})

    def _auth(self) -> dict:
        pw = self.pairing.get("password") or read_env_password(Path(self.pairing["envFile"]) if self.pairing.get("envFile") else None)
        return {"authorization": "Basic " + base64.b64encode(f"opencode:{pw}".encode()).decode()} if pw else {}

    async def _handle(self, m: Any) -> None:
        if not isinstance(m, dict) or not isinstance(m.get("t"), str):
            return
        t = m["t"]
        if t == "ping":
            self.hello()
            return
        current = isinstance(m.get("k"), str) and m["k"] == self.nonce
        if t == "cancel":
            c = self._inflight.get(m.get("id")) if current and isinstance(m.get("id"), str) else None
            if c:
                c.abort()
        elif t == "sub":
            if current:
                self._subscribe(m.get("p"), m.get("c"))
        elif t == "unsub":
            if current:
                self._unsubscribe(m.get("p"), m.get("c"))  # no id = the anonymous interest, as in sub
        elif t == "auto":
            # Auto mode on/off for one session — nonce-checked like a request (a recording cannot switch it). No new power: a
            # page that can switch Auto could already answer the same asks itself.
            if current and self.auto.set_auto(m.get("sid"), m.get("dir"), _js.truthy(m.get("on"))):
                self.hello()
        elif t == "req":
            await self._request(m, current)

    # ── requests ──────────────────────────────────────────────────────────────────────────────────────────────────────
    async def _request(self, m: dict, current: bool) -> None:
        rid = m["id"] if isinstance(m.get("id"), str) else ""
        if not rid:
            return

        def reply(st: int, b: Any) -> asyncio.Future:
            return self.peer.send({"t": "res", "id": rid, "st": st, "b": b if isinstance(b, str) else _js.stringify(b)})

        # Refuse rather than truncate: a shortened id could collide, and `cancel` would look up the long one.
        if _js.utf16_len(rid) > 64:
            await reply(400, {"error": "request id longer than 64 characters"})
            return
        if not current:
            await reply(409, {"error": "stale: this computer's connector changed — reconnecting"})
            return
        p = m.get("p") if isinstance(m.get("p"), str) else ""
        bare, _, query = p.partition("?")
        # A saved attachment, for the page's chip (preview, download): answered HERE from the attachments folder, never forwarded.
        if m.get("m") == "GET" and bare == ATTACHMENT_ROUTE:
            q = dict(urllib.parse.parse_qsl(query))
            st, b = serve_attachment(root=self._attach_root, session=q.get("session"), file=q.get("file"))
            await reply(st, b)
            return
        if not allowed_request(m.get("m"), m.get("p")):
            await reply(403, {"error": "not allowed by the connector"})
            return
        method, path, body = m["m"], m["p"], m.get("b")
        # ATTACHMENTS: the files a turn carries are saved on this computer and the message names them.
        turn_of = re.fullmatch(r"/session/([^/]+)/message", bare) if method == "POST" else None
        if turn_of and isinstance(body, str) and '"file"' in body:
            try:
                parsed = _js.parse(body)
            except Exception:  # OpenCode answers a malformed body itself
                parsed = None
            has_files = isinstance(parsed, dict) and isinstance(parsed.get("parts"), list) and any(
                isinstance(x, dict) and x.get("type") == "file" and str(x.get("url") or "").startswith("data:") for x in parsed["parts"])
            if has_files:
                # Only for a session OpenCode has — an invented id must not get a folder (security review: disk filling).
                known = await self._session_for(turn_of.group(1), query)
                if known is None:
                    await reply(404, {"error": "no such session on this computer"})
                    return
                self._prune_daily()
                staged = stage_message_body(parsed, session_id=turn_of.group(1), root=self._attach_root, max_file_bytes=self._attach_max)
                if staged and "error" in staged:
                    await reply(staged["error"]["status"], {"error": staged["error"]["message"]})
                    return
                if staged:
                    await self._allow_attachment_reads(turn_of.group(1), query, known)
                    body = _js.stringify(staged["body"])
        ctrl = _Inflight()
        self._inflight[rid] = ctrl
        # A turn POST returns only when the model has finished; it has no timeout (its progress rides the event stream).
        turn = method == "POST" and path.split("?")[0].endswith("/message")
        timer = None if turn else asyncio.get_running_loop().call_later(self._timeout_ms / 1000, ctrl.time_out)
        ctrl.task = asyncio.get_running_loop().create_task(self._forward(method, path, body))
        try:
            try:
                status, text = await asyncio.shield(ctrl.task)
            except asyncio.CancelledError:
                if not ctrl.aborted or self._stopping:  # the connector itself is stopping: no answer, just go
                    ctrl.task.cancel()
                    raise
                raise _Aborted() from None
        except _TooLarge:
            mb = _round(self._max_response / 1048576) or "<1"
            await reply(413, {"error": f"OpenCode's answer is over {mb} MB — too large to send through the relay"})
            return
        except (_Aborted, Exception):
            if ctrl.timed_out:
                await reply(504, {"error": f"OpenCode did not answer within {_round(self._timeout_ms / 1000)} s"})
            elif ctrl.aborted:
                await reply(499, {"error": "cancelled"})
            else:
                await reply(502, {"error": f"OpenCode is not answering at {self.base} — start it on that computer: {START_HINT}"})
            return
        finally:
            if timer is not None:
                timer.cancel()
            if self._inflight.get(rid) is ctrl:
                del self._inflight[rid]
        # /config and /config/providers carry API keys: rebuilt from an allowlist of fields before they leave (relay.py).
        status, text = project_response(method, path, status, text)
        gone = re.fullmatch(r"/session/([^/]+)", bare) if method == "DELETE" and 200 <= status < 300 else None
        if gone:
            remove_session_attachments(self._attach_root, gone.group(1))  # a deleted session takes its saved files along
        await reply(status, text)

    async def _session_for(self, sid: str, query: str) -> dict | None:
        """The session as OpenCode has it, or None when it has no such session (or cannot say)."""
        try:
            r = await self._client.get(f"{self.base}/session/{sid}" + (f"?{query}" if query else ""), headers=self._auth())
            if r.status_code >= 300:
                return None
            s = r.json()
            return s if isinstance(s, dict) else None
        except Exception:  # noqa: BLE001
            return None

    def _prune_daily(self) -> None:
        if time.time() - self._pruned_at < 86400:
            return
        self._pruned_at = time.time()
        try:
            prune_attachments(self._attach_root)
        except OSError:
            pass

    async def _allow_attachment_reads(self, sid: str, query: str, s: dict) -> None:
        """One rule per session lets the agent read THAT session's folder (external_directory) — and nothing next to it.
        Measured: PATCH /session/:id APPENDS the rule to a session that already exists."""
        if sid in self._ruled:
            return
        rule = attachment_rule(self._attach_root, sid)
        url = f"{self.base}/session/{sid}" + (f"?{query}" if query else "")
        try:
            perms = s.get("permission")
            has = isinstance(perms, list) and any(isinstance(x, dict) and x.get("permission") == rule["permission"] and x.get("pattern") == rule["pattern"] and x.get("action") == "allow" for x in perms)
            if not has:
                p = await self._client.patch(url, headers={**self._auth(), "content-type": "application/json"}, content=_js.utf8(_js.stringify({"permission": [rule]})))
                if p.status_code >= 300:
                    raise RuntimeError(f"PATCH answered {p.status_code}")
            self._ruled.add(sid)
        except Exception as e:  # noqa: BLE001 — reading the files will ask; the turn still goes
            self._log(f"opencode-connector: {self.name} · could not allow attachment reads for {sid} ({e}) — reading them will ask")

    async def _forward(self, method: Any, path: str, body: Any) -> tuple[int, str]:
        if not isinstance(method, str) or not _TOKEN.fullmatch(method):
            raise ValueError("not an HTTP method")
        headers = {**self._auth(), **({"content-type": "application/json"} if isinstance(body, str) else {})}
        content = _js.utf8(body) if isinstance(body, str) else None
        # Read with a cap: refuse while reading, never after holding an unbounded answer in memory.
        async with self._client.stream(method, self.base + path, headers=headers, content=content) as r:
            dec = codecs.getincrementaldecoder("utf-8-sig")("replace")  # TextDecoder: BOM dropped, bad bytes replaced
            parts, size = [], 0
            async for chunk in r.aiter_bytes():
                size += len(chunk)
                if size > self._max_response:
                    raise _TooLarge()  # leaving the stream context drops the connection: OpenCode stops sending
                parts.append(dec.decode(chunk))
            parts.append(dec.decode(b"", final=True))
            return r.status_code, "".join(parts)

    # ── events ────────────────────────────────────────────────────────────────────────────────────────────────────────
    # One OpenCode stream per path, shared by every device watching it; each device (its client id `c`) renews its own
    # interest, so one device leaving never closes the stream another is still reading.
    def _subscribe(self, p: Any, c: Any = None) -> None:
        if not allowed_event_path(p):
            return
        cid = _client_id(c)
        existing = self._subs.get(p)
        if existing:
            existing.clients[cid] = time.monotonic()
            return
        sub = _Sub(clients={cid: time.monotonic()})
        self._subs[p] = sub
        sub.task = self._spawn(self._pump(p, sub))

    def _unsubscribe(self, p: Any, c: Any) -> None:
        """One client leaves (no id = the anonymous '_'), or — internally, with _ALL — everyone."""
        sub = self._subs.get(p) if isinstance(p, str) else None
        if not sub:
            return
        if c is not _ALL:
            sub.clients.pop(_client_id(c), None)
            if sub.clients:
                return
        del self._subs[p]
        if sub.timer:
            sub.timer.cancel()
        if sub.task:
            sub.task.cancel()

    def _flush(self, p: str, sub: _Sub) -> None:
        sub.timer = None
        if not sub.buffer:
            return
        batch, sub.buffer = sub.buffer, []
        self.peer.send({"t": "evts", "p": p, "b": _js.stringify(batch)})

    async def _pump(self, p: str, sub: _Sub) -> None:
        loop = asyncio.get_running_loop()

        def on_data(data: str) -> None:
            sub.buffer.append(data)
            if not sub.timer:
                sub.timer = loop.call_later(self._flush_s, self._flush, p, sub)

        while self._subs.get(p) is sub:
            try:
                headers = {**self._auth(), "accept": "text/event-stream"}
                async with self._client.stream("GET", self.base + p, headers=headers) as r:
                    if not 200 <= r.status_code < 300:
                        raise RuntimeError(f"event stream {r.status_code}")
                    feed = sse_reader(on_data)
                    dec = codecs.getincrementaldecoder("utf-8-sig")("replace")
                    async for chunk in r.aiter_bytes():
                        feed(dec.decode(chunk))
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # OpenCode restarted, or is not running yet
            if self._subs.get(p) is not sub:
                break
            await asyncio.sleep(1)  # OpenCode went away mid-stream: try again while someone watches

    def _sweep(self) -> None:
        now = time.monotonic()
        for p, s in list(self._subs.items()):
            for cid, at in list(s.clients.items()):
                if now - at > SUB_TTL_S:
                    del s.clients[cid]
            if not s.clients:
                self._unsubscribe(p, _ALL)


class _Aborted(Exception):
    pass


@dataclass
class Connector:
    servers: list[PairingServer]
    client: httpx.AsyncClient

    @property
    def peers(self) -> list[RelayPeer]:
        return [s.peer for s in self.servers]

    def stop(self) -> None:
        for s in self.servers:
            s.stop()

    async def aclose(self) -> None:
        for s in self.servers:
            await s.aclose()
        await self.client.aclose()


def _log_stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def local_client() -> httpx.AsyncClient:
    # trust_env=False: OpenCode is on 127.0.0.1 and a proxy from the environment must never see its password.
    # No client timeout: the 30 s request timer covers the whole call, and an event stream is open-ended.
    return httpx.AsyncClient(trust_env=False, follow_redirects=True, timeout=httpx.Timeout(None, connect=10.0))


async def start_connector(pairings: list[dict], *, flush_ms: float = 120, log: Callable[[str], Any] = _log_stderr,
                          client: httpx.AsyncClient | None = None, connect: Connect | None = None,
                          request_timeout_ms: float = REQUEST_TIMEOUT_MS, max_senders: int = 64,
                          max_response_bytes: int = MAX_RESPONSE, auto_dir: Path | None = None, auto_poll_ms: float = 1000,
                          attach_root: Path | None = None, attach_max_file_bytes: int = MAX_FILE_BYTES) -> Connector:
    """Serve the given pairings until stop()/aclose(). Options exist for tests: flush_ms, log, client, connect,
    request_timeout_ms, max_senders, max_response_bytes, auto_dir, auto_poll_ms."""
    client = client or local_client()
    try:
        pruned = prune_attachments(Path(attach_root) if attach_root else default_root())
        if pruned:
            log(f"opencode-connector: removed {pruned} attachment folder(s) untouched for 30 days")
    except OSError:
        pass
    servers = []
    for p in pairings:
        s = PairingServer(p, client=client, flush_ms=flush_ms, log=log, connect=connect, request_timeout_ms=request_timeout_ms,
                          max_senders=max_senders, max_response_bytes=max_response_bytes, auto_dir=auto_dir, auto_poll_ms=auto_poll_ms,
                          attach_root=attach_root, attach_max_file_bytes=attach_max_file_bytes)
        await s.start()
        servers.append(s)
    return Connector(servers, client)
