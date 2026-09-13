"""witbitz-code — connect the Spaces Code section to OpenCode on this computer (docs/opencode-relay.md). The same commands
as the single-file Node download (tools/witbitz-code.mjs):

  witbitz-code pair [--name desk]       scan the QR with the Spaces app → this computer joins that account
  witbitz-code serve [--port 4096]      start OpenCode (if it is not running) and the connector
  witbitz-code status                   what this computer is paired with
  witbitz-code rotate                   new secrets (no scan) — restart serve afterwards
  witbitz-code unpair [--account a@b]   remove this computer from an account
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import sys
from typing import Any

import httpx

from . import __version__
from . import pair as pair_cmd
from . import pairings as pp
from ._js import to_number, truthy
from .connector import pairings_for_port, start_connector

HELP = f"""witbitz-code {__version__} — reach OpenCode on this computer from the Spaces Code section, end-to-end encrypted.

  pair [--name <name>]         show a QR code; scan it in Spaces (Settings → Back up & recovery → Add a device)
  serve [--port <n>] [--no-opencode]
                               start OpenCode on 127.0.0.1 (unless it is already running) and the connector
  status                       list this computer's pairings
  rotate [--account <email>]   replace the pairing secret(s) without a scan, then restart serve
  unpair [--account <email>]   remove this computer from an account

Nothing listens on the network: OpenCode stays on 127.0.0.1 and the connector dials out to wss://code-relay.witbitz.chat.
"""


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _flag(args: list[str], name: str, dflt: str = "") -> str:
    if name not in args:
        return dflt
    i = args.index(name)
    return args[i + 1] if i + 1 < len(args) else ""


async def is_listening(port: int) -> bool:
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=1.5) as c:
            await c.get(f"http://127.0.0.1:{port}/")
        return True
    except httpx.HTTPError:
        return False


class _Stop:
    """Ctrl-C / SIGTERM → a flag, installed BEFORE OpenCode is started so a signal during startup cannot orphan it. The
    first signal asks politely; the handlers are then removed, so a second Ctrl-C interrupts even a stuck shutdown."""

    def __init__(self) -> None:
        self.event = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        self._sigs: list[int] = []
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._loop.add_signal_handler(sig, self._fire)
                self._sigs.append(sig)
            except (NotImplementedError, RuntimeError):
                pass  # Windows: Ctrl-C arrives as KeyboardInterrupt, and the finally blocks still stop OpenCode

    def _fire(self) -> None:
        self.event.set()
        self.remove()

    def remove(self) -> None:
        for sig in self._sigs:
            try:
                self._loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
        self._sigs = []


async def _wait_for_stop(stop: _Stop, child: asyncio.subprocess.Process | None) -> int:
    """Until Ctrl-C / SIGTERM (→ 0) or OpenCode exits (→ its code)."""
    waiters = [asyncio.ensure_future(stop.event.wait())]
    if child is not None:
        waiters.append(asyncio.ensure_future(child.wait()))
    try:
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for w in waiters:
            w.cancel()
    if not stop.event.is_set() and child is not None and child.returncode is not None:
        _err(f"witbitz-code: OpenCode exited ({child.returncode}) — stopping")
        return child.returncode or 0
    return 0


async def _start_opencode(exe: str, port: int) -> asyncio.subprocess.Process:
    password = pp.read_env_password()
    env = {**os.environ, **({"OPENCODE_SERVER_PASSWORD": password} if password else {})}
    # The resolved path, not "opencode": on Windows the npm install is opencode.cmd, which a bare name does not find.
    # Its own process group there, so stopping it can take the whole tree (cmd.exe → node) with it.
    extra = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {}
    return await asyncio.create_subprocess_exec(exe, "serve", "--port", str(port), "--hostname", "127.0.0.1", env=env, **extra)


async def _stop_opencode(child: asyncio.subprocess.Process) -> None:
    if child.returncode is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(child.pid)], capture_output=True, check=False)
    else:
        child.terminate()
    try:
        await asyncio.wait_for(child.wait(), 5)
    except asyncio.TimeoutError:
        child.kill()
        await child.wait()


async def serve(args: list[str]) -> int:
    port_n = to_number(_flag(args, "--port", "4096"))
    port = int(port_n) if truthy(port_n) and port_n == port_n and float(port_n).is_integer() else 4096
    everything = pp.load_pairings(log=lambda _m: None)
    if not everything:
        _err("witbitz-code: this computer is not paired yet — run: witbitz-code pair")
        return 1
    # One OpenCode per port, one connector per OpenCode: two `serve`s (one per account) must never both answer a channel.
    pairings = pairings_for_port(everything, port)
    if not pairings:
        _err(f"witbitz-code: no pairing uses OpenCode on port {port} — pair with: witbitz-code pair --port {port}")
        return 1
    stop = _Stop()
    child = None
    try:
        if not await is_listening(port) and "--no-opencode" not in args:
            exe = shutil.which("opencode")
            if not exe:
                _err("witbitz-code: OpenCode is not installed (or not on PATH). Install it, then run serve again:")
                _err("  npm install -g opencode-ai        or        curl -fsSL https://opencode.ai/install | bash")
                return 1
            _err(f"witbitz-code: starting OpenCode on 127.0.0.1:{port}")
            child = await _start_opencode(exe, port)
            for _ in range(40):
                if stop.event.is_set() or child.returncode is not None or await is_listening(port):
                    break
                await asyncio.sleep(0.25)
        if stop.event.is_set():
            return 0
        connector = await start_connector(pairings)
        served = ", ".join(f'"{p.get("name")}" → {p.get("account") or "account"}' for p in pairings)
        _err(f"witbitz-code: serving {served} through the sealed relay (Ctrl-C to stop)")
        try:
            return await _wait_for_stop(stop, child)
        finally:
            await connector.aclose()
    finally:
        if child is not None:
            await _stop_opencode(child)
        stop.remove()


async def _main(argv: list[str]) -> int:
    cmd, rest = (argv[0], argv[1:]) if argv else ("", [])
    if cmd == "pair":
        return await pair_cmd.main(rest)
    if cmd == "serve":
        return await serve(rest)
    if cmd == "status":
        return await pair_cmd.main(["--status"])
    if cmd == "rotate":
        return await pair_cmd.main(["--rotate", *rest])
    if cmd == "unpair":
        return await pair_cmd.main(["--unpair", *rest])
    if cmd in ("version", "--version", "-v"):
        print(__version__)
        return 0
    print(HELP)
    return 2 if cmd and cmd not in ("help", "--help", "-h") else 0


def main(argv: list[str] | None = None) -> Any:
    try:
        code = asyncio.run(_main(sys.argv[1:] if argv is None else argv))
    except KeyboardInterrupt:
        code = 0
    except Exception as e:  # network failures in pair/rotate/unpair end here, as the JS FATAL does
        _err(f"witbitz-code: FATAL — {e}")
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
