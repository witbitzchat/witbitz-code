"""The sealed wire between the Spaces Code section and the connector on this computer (docs/opencode-relay.md §3–§4).

A second implementation of spaces/public/codeRelay.js, held to it by the pinned vectors in spaces/test/codeRelay.test.mjs
and by this package's cross-implementation tests (a frame sealed by either end opens in the other).

  secret S (32 bytes, per computer × account pairing)
    ├─ channel = b64url(HKDF(S, "channel"))        → wss://code-relay.witbitz.chat/c/<channel>   (the relay's routing key)
    ├─ kC2S    = HKDF(S, "client-to-computer")     → AES-256-GCM, page → computer
    └─ kS2C    = HKDF(S, "computer-to-client")     → AES-256-GCM, computer → page

A frame on the socket:  {"v":1,"s":<sender id>,"q":<seq>,"n":<iv>,"c":<ciphertext>}  — AAD "wbcr1|v|s|q", so the clear
header is authenticated; receivers drop any q ≤ the last one seen from that sender (replay).
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _js
from ._js import UNDEFINED, b64u

RELAY_URL = "wss://code-relay.witbitz.chat"

# The relay's heartbeat (spaces/public/codeRelay.js RELAY_PING): the relay answers the ping itself, to the sender alone. A
# dead network path leaves a socket "open" for a quarter of an hour; no pong within PONG_WAIT_S → redial. Enforced only once
# this peer's relay has answered: an older relay broadcasts the first ping, and is sent no more.
RELAY_PING = '{"t":"relay-ping"}'
RELAY_PONG = '{"t":"relay-pong"}'
HEARTBEAT_S = 25.0
PONG_WAIT_S = 10.0
SALT = b"witbitz-code-relay-v1"
CHUNK = 192 * 1024  # UTF-16 code units of `b`, as in JS: Cloudflare caps a message at 1 MiB and a frame is ~4/3 of it
MAX_TOTAL = 32 * 1024 * 1024
MAX_FRAME = 8 * 1024 * 1024  # what this end will accept from the socket; the real relay caps at 1 MiB anyway
SEND_TIMEOUT_S = 30.0  # one frame (≤ ~256 KB) that cannot drain in this long means the path is dead, not slow
CLOSE_TIMEOUT_S = 3.0


def unb64u(s: Any) -> bytes:
    """codeRelay.js unb64u: map the url alphabet back, pad, atob. Raises ValueError where atob throws."""
    t = _js.js_string(s).replace("-", "+").replace("_", "/")
    return _js.atob(t + "=" * ((4 - len(t) % 4) % 4))


def new_relay_secret() -> str:
    """A new pairing secret: 32 random bytes, base64url."""
    return b64u(os.urandom(32))


# ── keys ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _hkdf(raw: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=info.encode()).derive(raw)


def derive_relay_bytes(secret: str) -> tuple[str, bytes, bytes]:
    """Secret → (channel, raw c2s key, raw s2c key). Raw keys exist for the vector tests; use derive_relay otherwise."""
    raw = unb64u(secret)
    if len(raw) != 32:
        raise ValueError("relay secret must be 32 bytes")  # a truncated copy must fail loudly
    return b64u(_hkdf(raw, "channel")), _hkdf(raw, "client-to-computer"), _hkdf(raw, "computer-to-client")


@dataclass(frozen=True)
class RelayKeys:
    channel: str
    c2s: AESGCM = field(repr=False)
    s2c: AESGCM = field(repr=False)


def derive_relay(secret: str) -> RelayKeys:
    channel, c2s, s2c = derive_relay_bytes(secret)
    return RelayKeys(channel, AESGCM(c2s), AESGCM(s2c))


# ── frames ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _aad(v: Any, s: str, q: int) -> bytes:
    return f"wbcr1|{_js.js_string(v)}|{s}|{q}".encode()


def _as_key(key: AESGCM | bytes) -> AESGCM:
    return AESGCM(key) if isinstance(key, (bytes, bytearray)) else key


class Sealer:
    """A sealer for ONE socket: its own random sender id and a counter."""

    def __init__(self, key: AESGCM | bytes) -> None:
        self._key = _as_key(key)
        self.sender = b64u(os.urandom(12))
        self._q = 0

    def seal(self, msg: Any) -> str:
        # Sealing is synchronous here, so the sequence number and the AAD can never disagree (the JS ★ bug); ordering on
        # the socket is RelayPeer.send's job.
        self._q += 1
        seq = self._q
        iv = os.urandom(12)
        ct = self._key.encrypt(iv, _js.stringify(msg).encode("utf-8"), _aad(1, self.sender, seq))
        return _js.stringify({"v": 1, "s": self.sender, "q": seq, "n": b64u(iv), "c": b64u(ct)})


class Opener:
    """The other direction's key + a replay window per sender. open() returns the message, or None for anything that is
    not a valid, fresh frame for this key (junk, the relay's own control frames, the wrong key, a replay)."""

    def __init__(self, key: AESGCM | bytes, max_senders: int = 64, on_evict: Callable[[str], Any] | None = None) -> None:
        self._key = _as_key(key)
        self._max = max_senders
        self._on_evict = on_evict
        self._last: OrderedDict[str, int] = OrderedDict()  # sender → highest q accepted, least recently used first

    def open(self, text: Any) -> Any:
        if not isinstance(text, str):
            return None
        try:
            f = _js.parse(text)
        except ValueError:
            return None
        if not isinstance(f, dict):
            return None
        v, s, q, n, c = (f.get(k, UNDEFINED) for k in ("v", "s", "q", "n", "c"))
        if not (_js.is_num(v) and v == 1) or not isinstance(s, str) or not _js.is_safe_integer(q) or q < 1:
            return None
        if not isinstance(n, str) or not isinstance(c, str):
            return None
        q = int(q)
        if q <= self._last.get(s, 0):
            return None
        try:
            pt = self._key.decrypt(unb64u(n), unb64u(c), _aad(v, s, q))
        except Exception:  # bad base64, wrong key, tampered header or body — all the same to a receiver
            return None
        self._last.pop(s, None)
        self._last[s] = q
        if len(self._last) > self._max:
            # A sender pushed out of the window could have its recorded frames replayed from now on — so say so: the
            # connector rotates its nonce, which voids every request that sender ever sealed.
            gone, _ = self._last.popitem(last=False)
            _call(self._on_evict, gone)
        try:
            return _js.parse(pt.decode("utf-8-sig", "replace"))  # TextDecoder: BOM dropped, bad bytes replaced
        except ValueError:
            return None


def peers_of(text: Any) -> int | None:
    """Is this socket message the relay's own unsealed peer count? → n, else None."""
    if not isinstance(text, str) or not text.startswith('{"t":"peers"'):
        return None
    try:
        m = _js.parse(text)
    except ValueError:
        return None
    n = m.get("n") if isinstance(m, dict) else None
    return int(n) if _js.is_integer(n) else None


# ── chunking ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def chunk_message(msg: Any, size: int = CHUNK) -> list:
    """A message whose string field `b` is large → parts {…msg, b: slice, part: i, of: n}; small → [msg].
    Sizes and slices are UTF-16 code units, so both implementations cut a body at the same places."""
    b = msg.get("b") if isinstance(msg, dict) else None
    if not isinstance(b, str):
        return [msg]
    units = b.encode("utf-16-le", "surrogatepass")
    total = len(units) // 2
    if total <= size:
        return [msg]
    of = math.ceil(total / size)
    return [
        {**msg, "b": units[2 * i * size : 2 * (i + 1) * size].decode("utf-16-le", "surrogatepass"), "part": i, "of": of}
        for i in range(of)
    ]


def _now_ms() -> float:
    return time.time() * 1000


@dataclass
class _Partial:
    of: int
    at: float
    parts: dict = field(default_factory=dict)
    size: int = 0


class Reassembler:
    """Collects parts by (t, id). push(msg) → the whole message once complete, the message itself if unchunked, else None."""

    def __init__(self, timeout_ms: float = 60_000, max_total: int = MAX_TOTAL, clock: Callable[[], float] = _now_ms):
        self._open: dict[str, _Partial] = {}
        self._timeout = timeout_ms
        self._max = max_total
        self._clock = clock

    def push(self, msg: Any) -> Any:
        if not isinstance(msg, dict) or "of" not in msg:
            return msg
        of, part, b = msg["of"], msg.get("part", UNDEFINED), msg.get("b")
        if not _js.is_integer(of) or of < 1 or not _js.is_integer(part) or part < 0 or part >= of or not isinstance(b, str):
            return None
        if of > 2**32 - 1:  # JS `new Array(of)` throws past this; the message is dropped there too
            return None
        of, part = int(of), int(part)
        k = f"{_js.js_string(msg.get('t', UNDEFINED))}:{_js.js_string(msg.get('id', UNDEFINED))}"
        now = self._clock()
        for key in [key for key, e in self._open.items() if now - e.at > self._timeout]:
            del self._open[key]
        e = self._open.get(k)
        if e is None:
            e = self._open[k] = _Partial(of=of, at=now)
        if e.of != of:
            del self._open[k]
            return None
        if part not in e.parts:
            e.parts[part] = b
            e.size += _js.utf16_len(b)
        if e.size > self._max:
            del self._open[k]
            return None
        if len(e.parts) < of:
            return None
        del self._open[k]
        whole = dict(msg)
        whole["b"] = _js.utf16_join(e.parts[i] for i in range(of))
        whole.pop("part", None)
        whole.pop("of", None)
        return whole


# ── the socket ────────────────────────────────────────────────────────────────────────────────────────────────────────
Connect = Callable[[str], Awaitable[Any]]


async def default_connect(url: str) -> Any:
    from websockets.asyncio.client import connect

    # No Origin header (the relay admits a socket without one — only browsers must carry an allowed Origin), no
    # compression (the payload is ciphertext). Protocol pings notice a dead TCP path that a sealed hello cannot.
    return await connect(url, max_size=MAX_FRAME, compression=None, open_timeout=15, close_timeout=2,
                         ping_interval=30, ping_timeout=30)


def _call(fn: Callable | None, *args: Any) -> None:
    if fn is None:
        return
    try:
        fn(*args)
    except Exception:  # a handler bug must not kill the socket
        pass


class RelayPeer:
    """One end of a channel, with reconnect. role 'client' (the page) seals with c2s and opens s2c; 'computer' the reverse.

        peer = RelayPeer(secret=..., role="computer", on_message=..., on_peers=..., on_state=...)
        await peer.start(); await peer.send({"t": "hello"}); await peer.aclose()

    A fresh sealer (new sender id, q from 1) per socket, so a reconnect is never mistaken for a replay.
    """

    def __init__(self, *, secret: str, role: str, relay: str = RELAY_URL, on_message: Callable | None = None,
                 on_peers: Callable | None = None, on_state: Callable | None = None, on_evict: Callable | None = None,
                 max_senders: int = 64, min_backoff: float = 0.5, max_backoff: float = 15.0, connect: Connect | None = None,
                 heartbeat: float = HEARTBEAT_S, pong_wait: float = PONG_WAIT_S) -> None:
        if role not in ("client", "computer"):
            raise ValueError("role must be client or computer")
        self.secret = secret
        self.role = role
        self.relay = re.sub(r"/+$", "", _js.js_string(relay))
        self.on_message, self.on_peers, self.on_state, self.on_evict = on_message, on_peers, on_state, on_evict
        self.max_senders = max_senders
        self.min_backoff, self.max_backoff = min_backoff, max_backoff
        self.peers = 0
        self.state = "idle"  # idle | connecting | open | closed
        self._connect = connect or default_connect
        self._keys: RelayKeys | None = None
        self._ws: Any = None
        self._sealer: Sealer | None = None
        self._backoff = min_backoff
        self._stopped = True
        self._task: asyncio.Task | None = None
        self._stopping_task: asyncio.Task | None = None
        self._wake: asyncio.Event | None = None
        self.waiting = False  # inside a backoff wait (state reads 'connecting' then too)
        self._redial = False
        self._send_chain: asyncio.Future | None = None
        self._closing: set[asyncio.Task] = set()
        self.heartbeat, self.pong_wait = heartbeat, pong_wait
        self.relay_answers = False  # this socket's relay has answered a ping
        self.relay_known = False  # ...or an earlier socket's did: a missing pong then means a dead path from the first ping
        self._pinged_unanswered = False
        self._last_pong = 0.0
        self._probes: set[asyncio.Task] = set()

    @property
    def channel(self) -> str | None:
        return self._keys.channel if self._keys else None

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    async def start(self) -> None:
        self._stopped = False
        if self._keys is None:
            self._keys = derive_relay(self.secret)
        old = self._task
        if old is not None and not old.done():
            if old is not self._stopping_task:
                return  # already running
            await asyncio.wait([old])  # start() right after stop(): let the cancelled loop finish before dialling again
        self._stopping_task = None
        self._task = asyncio.get_running_loop().create_task(self._run())

    def stop(self) -> None:
        self._stopped = True
        self.waiting = False  # a stop during a backoff wait must not leave kick() believing a wait is pending
        if self._task is not None:
            self._task.cancel()
            self._stopping_task = self._task
        self._close_ws(self._ws)
        self._ws = None
        self._set_state("closed")

    async def aclose(self) -> None:
        """stop(), then wait (bounded) for the socket task and the close handshakes to finish."""
        self.stop()
        pending = [t for t in [self._task, *self._closing] if t is not None]
        if pending:
            await asyncio.wait(pending, timeout=CLOSE_TIMEOUT_S + 1)

    def kick(self) -> None:
        """Reconnect now (e.g. the page became visible again) instead of waiting out the backoff. An "open" socket is asked
        about instead: the relay must answer a ping, or it is redialled (a socket frozen, not closed).
        ★ `connecting` covers two situations: a socket actually dialling (leave it) and a backoff WAIT (skip it)."""
        if not self._stopped and self.state == "open":
            self.probe()
            return
        if self._stopped or (self.state == "connecting" and not self.waiting):
            return
        self._backoff = self.min_backoff
        if self._wake is not None:
            self._wake.set()

    def probe(self) -> None:
        """Ping the relay on the current socket; no pong within pong_wait → reconnect()."""
        ws = self._ws
        if self._stopped or ws is None or self.state != "open":
            return
        try:
            t = asyncio.get_running_loop().create_task(self._probe(ws))
        except RuntimeError:
            return
        self._probes.add(t)
        t.add_done_callback(self._probes.discard)

    async def _probe(self, ws: Any) -> None:
        enforce = self.relay_answers or self.relay_known
        if not enforce and self._pinged_unanswered:
            return  # an older relay: it broadcasts pings — send it no more
        sent = time.monotonic()
        try:
            await ws.send(RELAY_PING)
        except Exception:
            return
        if not enforce:
            self._pinged_unanswered = True  # learning whether this relay answers at all
            return
        await asyncio.sleep(self.pong_wait)
        if self._ws is ws and not self._stopped and self.state == "open" and not self._last_pong >= sent:
            self.reconnect()  # a dead path: the relay did not hear us, or we did not hear it

    async def _heartbeat(self, ws: Any) -> None:
        while self._ws is ws and not self._stopped:
            self.probe()
            await asyncio.sleep(self.heartbeat)

    def reconnect(self) -> None:
        """Drop the current socket and dial again now — for a socket that is "open" but has gone silent (a dead path)."""
        if self._stopped:
            return
        ws, self._ws = self._ws, None
        self.peers = 0
        self._backoff = self.min_backoff
        if ws is not None:
            self._redial = True  # the socket loop ends without a peers callback or a backoff, as the JS onclose guard does
            self._close_ws(ws, 4000)
        elif self._wake is not None:
            self._wake.set()

    def _set_state(self, s: str) -> None:
        if self.state != s:
            self.state = s
            _call(self.on_state, s)

    def _close_ws(self, ws: Any, code: int = 1000) -> None:
        if ws is None:
            return
        try:
            t = asyncio.get_running_loop().create_task(_close_quietly(ws, code))
        except Exception:
            _abort(ws)
            return
        self._closing.add(t)
        t.add_done_callback(self._closing.discard)

    async def _run(self) -> None:
        keys = self._keys
        assert keys is not None
        url = f"{self.relay}/c/{keys.channel}"
        while not self._stopped:
            self._set_state("connecting")
            try:
                ws = await self._connect(url)
            except asyncio.CancelledError:
                raise
            except Exception:
                ws = None
            if ws is not None:
                await self._serve_socket(ws, keys)
            else:
                self.peers = 0
                _call(self.on_peers, 0)
            if self._stopped:
                return
            if self._redial:
                self._redial = False
                continue  # reconnect(): dial again at once
            self._set_state("connecting")
            wait, self._backoff = self._backoff, min(self.max_backoff, self._backoff * 2)
            self._wake = asyncio.Event()
            self.waiting = True
            try:
                await asyncio.wait_for(self._wake.wait(), wait)
            except asyncio.TimeoutError:
                pass
            finally:
                self._wake = None
                self.waiting = False

    async def _serve_socket(self, ws: Any, keys: RelayKeys) -> None:
        sealer = Sealer(keys.c2s if self.role == "client" else keys.s2c)
        opener = Opener(keys.s2c if self.role == "client" else keys.c2s, self.max_senders, lambda s: _call(self.on_evict, s))
        reasm = Reassembler()
        self._ws, self._sealer = ws, sealer
        self._backoff = self.min_backoff
        self.relay_answers, self._pinged_unanswered, self._last_pong = False, False, 0.0
        self._set_state("open")
        beat = asyncio.get_running_loop().create_task(self._heartbeat(ws)) if self.heartbeat > 0 else None
        try:
            # One loop, one frame at a time: frames are opened in the order they arrived (the JS recvChain).
            async for data in ws:
                if self._ws is not ws:
                    break
                if not isinstance(data, str):
                    continue
                if data == RELAY_PONG:
                    self.relay_answers = self.relay_known = True
                    self._pinged_unanswered = False
                    self._last_pong = time.monotonic()
                    continue
                if data == RELAY_PING:
                    continue  # another peer's ping, broadcast by a relay that does not answer it
                n = peers_of(data)
                if n is not None:
                    self.peers = n
                    _call(self.on_peers, n)
                    continue
                msg = reasm.push(opener.open(data))
                if _js.truthy(msg):
                    _call(self.on_message, msg)
        except asyncio.CancelledError:
            self._close_ws(ws)
            raise
        except Exception:
            pass  # the socket went away; reconnect
        finally:
            if beat is not None:
                beat.cancel()
            replaced = self._ws is not ws
            if not replaced:
                self._ws = None
        if replaced:
            return  # reconnect() (or stop()) took this socket away: its close is not news
        self._close_ws(ws)
        self.peers = 0
        _call(self.on_peers, 0)

    def send(self, msg: Any) -> asyncio.Future:
        """Seal and send (chunked if large). The returned future resolves False when there is no open socket.

        ★ ONE AT A TIME, IN CALL ORDER. Receivers drop a frame whose sequence is not above the last one opened, so frames
          must reach the socket in the order they were numbered. Each send waits for the previous one — chained at call
          time, so fire-and-forget sends from a timer or handler still go out in the order they were made.
        """
        loop = asyncio.get_running_loop()
        prev = self._send_chain

        async def run() -> bool:
            if prev is not None and not prev.done():
                await asyncio.wait([prev])
            return await self._send_now(msg)

        task = loop.create_task(run())
        task.add_done_callback(_consume)
        self._send_chain = task
        return task

    async def _send_now(self, msg: Any) -> bool:
        ws = self._ws
        if ws is None or self.state != "open" or self._sealer is None:
            return False
        sealer = self._sealer
        for part in chunk_message(msg):
            frame = sealer.seal(part)
            if self._ws is not ws:
                return False
            try:
                await asyncio.wait_for(ws.send(frame), SEND_TIMEOUT_S)
            except asyncio.TimeoutError:
                # ★ A send stuck on a dead TCP path (the laptop slept, Wi-Fi dropped) never returns, and websockets' own
                #   keepalive ping waits behind the same full buffer — so nothing else would notice. Drop the socket: the
                #   receive loop ends, queued sends resolve False, and the peer reconnects.
                _abort(ws)
                return False
            except Exception:
                return False
        return True


def _abort(ws: Any) -> None:
    transport = getattr(ws, "transport", None)
    if transport is not None:
        try:
            transport.abort()
        except Exception:
            pass


async def _close_quietly(ws: Any, code: int = 1000) -> None:
    """A close handshake, bounded: on a dead path it would wait on the same undrainable buffer as a send."""
    try:
        await asyncio.wait_for(ws.close(code), CLOSE_TIMEOUT_S)
    except asyncio.CancelledError:
        _abort(ws)
        raise
    except Exception:
        _abort(ws)


def _consume(t: asyncio.Future) -> None:
    if not t.cancelled():
        t.exception()  # retrieved, so a fire-and-forget failure is not reported as "never retrieved"


# ── what the connector serves ─────────────────────────────────────────────────────────────────────────────────────────
# Only the calls the Code section makes (opencodeApp.js). OpenCode can run shell commands on the computer; a leaked
# secret must not unlock more than the page itself can do. Paths carry their query string (?directory=…).
# A segment may contain dots but never START with one: '.' and '..' are collapsed by HTTP clients (fetch and httpx alike)
# onto a route that is not on this list — `DELETE /session/.` would reach DELETE /session.
_SEG = r"(?!\.)[A-Za-z0-9_.-]{1,128}"
_ALLOW = [
    (m, re.compile(p))
    for m, p in [
        ("GET", "/experimental/session"),
        ("GET", "/agent"),
        ("GET", "/api/model"),
        ("GET", "/config"),  # answered through project_response — never as OpenCode sent it
        ("GET", "/config/providers"),  # the model menu: what is CONNECTED on this computer (project_response, no keys)
        ("POST", "/session"),
        ("GET", f"/session/{_SEG}/message"),
        ("POST", f"/session/{_SEG}/message"),
        ("POST", f"/session/{_SEG}/abort"),
        ("POST", f"/session/{_SEG}/permissions/{_SEG}"),
        ("POST", f"/permission/{_SEG}/reply"),  # the same answer with a message for the model (a person's Deny)
        ("GET", "/permission"),  # what is still waiting — a card comes back after switching sessions (the asks the stream carries)
        ("PATCH", f"/session/{_SEG}"),
        ("DELETE", f"/session/{_SEG}"),
        # New session's folder picker: the computer's home, and folder listings under it (names, never contents)
        ("GET", "/path"),
        ("GET", "/file"),
        # the agent's question tool: what is pending, and the answer or the dismissal (inside the agent loop)
        # the "/" menu reads commands and skills; POST /session/:id/command runs !`…` from its arguments — never listed
        ("GET", "/command"),
        ("GET", f"/session/{_SEG}/todo"),  # the agent's todo list, as it stands
        ("GET", "/question"),
        ("POST", f"/question/{_SEG}/reply"),
        ("POST", f"/question/{_SEG}/reject"),
        # /undo /redo /compact: files back to OpenCode's pre-turn snapshot, forward again, and a model-written summary
        ("POST", f"/session/{_SEG}/revert"),
        ("POST", f"/session/{_SEG}/unrevert"),
        ("POST", f"/session/{_SEG}/summarize"),
        ("GET", "/session/status"),  # which sessions are running a turn, for the list (reads only)
    ]
]


def allowed_request(method: Any, path_with_query: Any) -> bool:
    """Is `method path?query` something the connector will forward? The event stream is NOT here: it is `sub`."""
    m = _js.js_string(method if _js.truthy(method) else "").upper()
    p = _js.js_string(path_with_query if _js.truthy(path_with_query) else "")
    if not p.startswith("/") or ".." in p or "//" in p or "#" in p:
        return False
    path = p.split("?")[0]
    return any(am == m and rx.fullmatch(path) for am, rx in _ALLOW)  # fullmatch: JS `$` never matches before a \n


_EVENT = re.compile(r"/event\?directory=[^&#]*")


def allowed_event_path(p: Any) -> bool:
    """The event-stream path a `sub` may name: /event, optionally ?directory=… (and nothing else)."""
    s = _js.js_string(p if _js.truthy(p) else "")
    return s == "/event" or bool(_EVENT.fullmatch(s))


# ── what the connector gives back ─────────────────────────────────────────────────────────────────────────────────────
# Two routes the page needs answer with SECRETS in them (measured, opencode 1.18): GET /config resolves every `{env:…}` in
# the provider options, and GET /config/providers carries each connected provider's stored API key in `key`. The page
# needs names, not credentials, so the connector rebuilds those answers from an ALLOWLIST of fields — codeRelay.js
# `projectResponse`, which this mirrors field for field.
_PROJECTED = {"/config", "/config/providers"}
_MAX_PROVIDERS, _MAX_MODELS = 100, 2000
_MEDIA = ["text", "image", "pdf", "audio", "video"]


def _s200(v: Any) -> str | None:
    return _js.utf16_slice(v, 0, 200) if isinstance(v, str) else None


def _project_input(caps: Any) -> list | None:
    inp = caps.get("input") if isinstance(caps, dict) else None
    if isinstance(inp, list):
        return [k for k in _MEDIA if k in inp]
    if isinstance(inp, dict):
        return [k for k in _MEDIA if inp.get(k) is True]
    return None


def _project_models(models: Any, keep: Callable[[dict], dict]) -> dict:
    out: dict = {}
    if not isinstance(models, dict):
        return out
    for k in list(models.keys())[:_MAX_MODELS]:
        mid = _s200(k)
        if not mid:
            continue
        m = models[k] if isinstance(models[k], dict) else {}
        out[mid] = keep(m)
    return out


def _named(m: dict) -> dict:
    return {"name": _s200(m.get("name"))} if _s200(m.get("name")) else {}


def _project_config(c: dict) -> dict:
    out: dict = {}
    if _s200(c.get("model")):
        out["model"] = _s200(c.get("model"))
    if _s200(c.get("small_model")):
        out["small_model"] = _s200(c.get("small_model"))
    src = c.get("provider") if isinstance(c.get("provider"), dict) else {}
    provider: dict = {}
    for pid in list(src.keys())[:_MAX_PROVIDERS]:
        if not _s200(pid):
            continue
        p = src[pid] if isinstance(src[pid], dict) else {}
        entry: dict = {"models": _project_models(p.get("models"), _named)}
        if _s200(p.get("name")):
            entry["name"] = _s200(p.get("name"))
        provider[_s200(pid)] = entry
    out["provider"] = provider
    return out


def _provider_model(m: dict) -> dict:
    o: dict = {}
    if _s200(m.get("name")):
        o["name"] = _s200(m.get("name"))
    if _s200(m.get("status")):
        o["status"] = _s200(m.get("status"))
    inp = _project_input(m.get("capabilities"))
    if inp is not None:
        o["input"] = inp
    return o


def _project_providers(d: dict) -> dict:
    providers = []
    for p in (d.get("providers") if isinstance(d.get("providers"), list) else [])[:_MAX_PROVIDERS]:
        if not isinstance(p, dict) or not _s200(p.get("id")):
            continue
        entry: dict = {"id": _s200(p.get("id")), "models": _project_models(p.get("models"), _provider_model)}
        if _s200(p.get("name")):
            entry["name"] = _s200(p.get("name"))
        if _s200(p.get("source")):
            entry["source"] = _s200(p.get("source"))
        providers.append(entry)
    default: dict = {}
    if isinstance(d.get("default"), dict):
        for k in list(d["default"].keys())[:_MAX_PROVIDERS]:
            if _s200(k) and _s200(d["default"][k]):
                default[_s200(k)] = _s200(d["default"][k])
    return {"providers": providers, "default": default}


def project_response(method: Any, path_with_query: Any, status: int, text: str) -> tuple[int, str]:
    """The answer the connector sends for `method path` — projected for the routes above, untouched otherwise."""
    path = _js.js_string(path_with_query if _js.truthy(path_with_query) else "").split("?")[0]
    if _js.js_string(method if _js.truthy(method) else "").upper() != "GET" or path not in _PROJECTED:
        return status, text
    if not 200 <= status < 300:
        return status, _js.stringify({"error": f"OpenCode answered {status} for {path}"})
    try:
        v = _js.parse(text)
    except Exception:
        v = None
    if not isinstance(v, dict):
        return 502, _js.stringify({"error": f"OpenCode sent an unexpected answer for {path}"})
    return status, _js.stringify(_project_config(v) if path == "/config" else _project_providers(v))
