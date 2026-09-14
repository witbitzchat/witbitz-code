"""Local stand-ins with the real services' observable semantics.

fake_relay   — relay/relay.mjs: a message goes to every OTHER socket on /c/<channel>, and the channel hears
               {"t":"peers","n"} on every join and leave (spaces/test/fakeRelay.mjs, in Python).
FakeOpenCode — an HTTP server that checks the Basic password, echoes bodies, streams SSE, and records what reached it.
mock_api     — the account API: op:'state' reads when there is no patch and REPLACES the doc when there is one.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import select
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from websockets.asyncio.server import serve

from witbitz_code import compress
from witbitz_code.net import ApiReply

PASSWORD = "local-only-password"
BIG = "z" * (192 * 1024 * 2 + 123) + "😀ünïcødé" * 1000  # longer than two frames, with astral characters to split


# What OpenCode answers for /config and /config/providers, with a SECRET where it really puts credentials (measured,
# opencode 1.18: resolved `{env:…}` provider options, and each connected provider's stored `key`).
LEAKY = {
    "/config": {"model": "trustedrouter/deepseek/deepseek-v4-flash", "mcp": {"gh": {"environment": {"GITHUB_TOKEN": "SECRET-mcp"}}},
                "provider": {"trustedrouter": {"name": "TrustedRouter", "options": {"apiKey": "SECRET-resolved"},
                                               "models": {"deepseek/deepseek-v4-flash": {"name": "DeepSeek V4 Flash"}}}}},
    "/config/providers": {"providers": [{"id": "anthropic", "name": "Anthropic", "source": "api", "key": "SECRET-key",
                                         "options": {"headers": {"x": "SECRET-h"}},
                                         "models": {"claude-sonnet-4-6": {"name": "Claude Sonnet 4.6", "headers": {"x-api-key": "SECRET-mh"},
                                                                          "capabilities": {"input": {"text": True, "image": True}}}}}],
                          "default": {"anthropic": "claude-sonnet-4-6"}},
}


# ── the relay ─────────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class FakeRelay:
    server: Any
    channels: dict = field(default_factory=dict)
    recorded: list = field(default_factory=list)  # every message forwarded, as the relay operator could keep them
    answer_pings: bool = True  # False: an older relay, which broadcasts {"t":"relay-ping"} like any message
    stalled: set = field(default_factory=set)  # sockets on a dead network path: "open", but nothing reaches or leaves them

    def stall(self) -> None:
        for conns in self.channels.values():
            self.stalled.update(conns)

    @property
    def url(self) -> str:
        host, port = self.server.sockets[0].getsockname()[:2]
        return f"ws://{host}:{port}"

    def drop_all(self) -> None:
        for conns in self.channels.values():
            for ws in list(conns):
                ws.transport.abort()

    async def close(self) -> None:
        self.drop_all()
        self.server.close()
        await self.server.wait_closed()


async def fake_relay(*, answer_pings: bool = True) -> FakeRelay:
    relay = FakeRelay(server=None, answer_pings=answer_pings)

    async def announce(conns: set) -> None:
        msg = json.dumps({"t": "peers", "n": len(conns)}, separators=(",", ":"))
        for ws in list(conns):
            if ws in relay.stalled:
                continue
            try:
                await ws.send(msg)
            except Exception:
                pass

    async def handler(ws: Any) -> None:
        ch = re.sub(r"^/c/", "", ws.request.path)
        conns = relay.channels.setdefault(ch, set())
        conns.add(ws)
        await announce(conns)
        try:
            async for msg in ws:
                if ws in relay.stalled:
                    continue
                if relay.answer_pings and msg == '{"t":"relay-ping"}':
                    await ws.send('{"t":"relay-pong"}')
                    continue
                relay.recorded.append(msg)
                for other in list(conns):
                    if other is not ws and other not in relay.stalled:
                        try:
                            await other.send(msg)
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            conns.discard(ws)
            await announce(conns)

    relay.server = await serve(handler, "127.0.0.1", 0, max_size=None, compression=None)
    return relay


# ── OpenCode ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class FakeOpenCode:
    """Runs in its own threads, so it works the same for a Python connector (asyncio loop) and a node one."""

    def __init__(self, *, auto_events: list | None = None, auto_delay: float = 0.3) -> None:
        self.seen: list[dict] = []
        self.streams: set = set()
        self.lock = threading.Lock()
        self.auto_events = auto_events or []
        self.auto_delay = auto_delay
        self.session_dirs: dict[str, str] = {}  # session id → its folder, as GET /session/:id reports it (produced files)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:  # quiet
                pass

            def _body(self) -> str:
                n = int(self.headers.get("content-length") or 0)
                return self.rfile.read(n).decode("utf-8") if n else ""

            def _send(self, status: int, body: str, ctype: str = "application/json") -> None:
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _gone(self) -> bool:
                r, _, _ = select.select([self.connection], [], [], 0.05)
                if not r:
                    return False
                try:
                    return self.connection.recv(1, socket.MSG_PEEK) == b""
                except OSError:
                    return True

            def _handle(self) -> None:
                body = self._body()
                with outer.lock:
                    outer.seen.append({"method": self.command, "url": self.path, "auth": self.headers.get("authorization") or "", "body": body})
                ok = self.headers.get("authorization") == "Basic " + base64.b64encode(f"opencode:{PASSWORD}".encode()).decode()
                if not ok:
                    return self._send(401, "unauthorized", "text/plain")
                path = self.path.split("?")[0]
                if path == "/agent":
                    return self._send(200, json.dumps([{"name": "build"}]))
                parts = path.split("/")
                if len(parts) == 3 and parts[1] == "session" and parts[2] in outer.session_dirs and self.command == "GET":
                    return self._send(200, json.dumps({"id": parts[2], "directory": outer.session_dirs[parts[2]]}, ensure_ascii=False))
                if path in LEAKY:  # a credential planted where OpenCode really puts one (spaces/test/leakyOpenCode.mjs)
                    return self._send(200, json.dumps(LEAKY[path]))
                if path == "/session/ses_big/message":
                    return self._send(200, BIG)
                if path == "/session/ses_1/message" and self.command == "POST":
                    return self._send(200, json.dumps({"echoed": json.loads(body)}, ensure_ascii=False))
                if path == "/session/ses_huge/message":
                    return self._send(200, "h" * (30 * 1024 * 1024 + 1))
                if path == "/session/ses_once/message":  # the first call hangs (and is abandoned); later calls answer
                    with outer.lock:
                        outer.once_calls += 1
                        first = outer.once_calls == 1
                    if not first:
                        return self._send(200, json.dumps({"once": outer.once_calls}))
                    while not self._gone():
                        pass
                    return
                if path == "/session/ses_slow/message":
                    while not self._gone():
                        pass
                    with outer.lock:
                        outer.seen.append({"aborted": path})
                    return
                if path == "/permission" and self.command == "GET":  # Auto mode's poll (auto_runner.py)
                    with outer.lock:
                        pending = json.dumps(outer.pending)
                    return self._send(200, pending)
                reply = re.fullmatch(r"/permission/([^/]+)/reply", path)
                if reply and self.command == "POST":
                    with outer.lock:
                        outer.pending[:] = [p for p in outer.pending if p.get("id") != reply.group(1)]
                    return self._send(200, "true")
                if path == "/event":
                    return self._stream()
                return self._send(200, json.dumps({"ok": True}))

            def _stream(self) -> None:
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b": open\n\n")
                self.wfile.flush()
                queue: list = []
                with outer.lock:
                    outer.streams.add(id(queue))
                    outer._queues[id(queue)] = queue
                if outer.auto_events:
                    def later() -> None:
                        time.sleep(outer.auto_delay)
                        outer.emit_all(outer.auto_events)
                    threading.Thread(target=later, daemon=True).start()
                try:
                    while True:
                        with outer.lock:
                            items, queue[:] = list(queue), []
                        for obj in items:
                            self.wfile.write(f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode("utf-8"))
                        self.wfile.write(b":\n\n")  # heartbeat: notices a caller that went away
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    pass
                finally:
                    with outer.lock:
                        outer.streams.discard(id(queue))
                        outer._queues.pop(id(queue), None)

            do_GET = do_POST = do_PATCH = do_DELETE = _handle

        self._queues: dict = {}
        self.pending: list = []  # permission asks waiting, as GET /permission lists them
        self.once_calls = 0
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def emit_all(self, objs: list) -> None:
        with self.lock:
            for q in self._queues.values():
                q.extend(objs)

    def stream_count(self) -> int:
        with self.lock:
            return len(self.streams)

    def seen_copy(self) -> list:
        with self.lock:
            return list(self.seen)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# ── the account API ───────────────────────────────────────────────────────────────────────────────────────────────────
class MockApi:
    def __init__(self, read_status: int = 200, docs: dict | None = None) -> None:
        self.read_status = read_status
        self.docs = docs if docs is not None else {}
        self.writes: list[dict] = []

    async def call(self, body: dict) -> ApiReply:
        if body.get("op") != "state":
            return ApiReply(400, {"error": "unexpected op"})
        if "patch" not in body:
            if self.read_status != 200:
                return ApiReply(self.read_status, {"error": "nope"})
            return ApiReply(200, {"state": self.docs.get(body["name"])})
        self.writes.append(body)
        self.docs[body["name"]] = json.loads(json.dumps(body["patch"]))
        return ApiReply(200, {"ok": True})

    def plain(self, name: str) -> Any:
        d = self.docs.get(name)
        return compress.gunzip_b64(d["z"]) if isinstance(d, dict) and isinstance(d.get("z"), str) else d


async def until(fn, timeout: float = 5.0, every: float = 0.015) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return True
        await asyncio.sleep(every)
    return False
