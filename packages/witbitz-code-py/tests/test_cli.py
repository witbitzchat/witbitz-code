"""The `witbitz-code` command itself, run as a process (python -m witbitz_code), with no network and no pairing."""

from __future__ import annotations

import os
import site
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
USER_BASE = site.getuserbase()  # captured before the hermetic fixture moves HOME, so --user installs stay importable


def cli(*args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONUSERBASE": USER_BASE, **(env_extra or {})}
    return subprocess.run([sys.executable, "-m", "witbitz_code", *args], capture_output=True, text=True, env=env, timeout=60)


def test_help_version_and_unknown_commands():
    r = cli("--help")
    assert r.returncode == 0 and "pair [--name" in r.stdout and "wss://code-relay.witbitz.chat" in r.stdout
    r = cli("version")
    assert r.returncode == 0 and r.stdout.strip().count(".") == 2
    assert cli().returncode == 0
    r = cli("frobnicate")
    assert r.returncode == 2 and "serve [--port" in r.stdout


def test_status_and_serve_without_a_pairing():
    r = cli("status")
    assert r.returncode == 0 and "not paired" in r.stdout
    r = cli("serve", "--no-opencode")
    assert r.returncode == 1 and "not paired yet" in r.stderr
    r = cli("unpair")
    assert r.returncode == 1 and "no pairing" in r.stderr
    r = cli("rotate")
    assert r.returncode == 1 and "nothing to rotate" in r.stderr
    r = cli("pair", "--dry-run")
    assert r.returncode == 0 and "would show the QR" in r.stdout


def test_serve_without_opencode_on_path_says_how_to_install(tmp_path):
    from witbitz_code import pairings as pp

    pp.write_pairings({"v": 1, "pairings": [{"account": "me@x", "idx": {"room": "r", "mk": "m"}, "computerId": "cmp_1",
                                             "secret": "S" * 43, "name": "desk", "relay": "ws://127.0.0.1:1",
                                             "opencodeUrl": "http://127.0.0.1:4096"}]})
    if _free_port_is(4096):
        r = cli("serve", "--port", "4096", env_extra={"PATH": str(tmp_path)})
        assert r.returncode == 1 and "OpenCode is not installed" in r.stderr and "opencode-ai" in r.stderr
    port = _free_port()
    r = cli("serve", "--port", str(port), env_extra={"PATH": str(tmp_path)})
    assert r.returncode == 1, "one OpenCode per port: a serve for a port no pairing uses serves nothing"
    assert f"no pairing uses OpenCode on port {port} — pair with: witbitz-code pair --port {port}" in r.stderr


def _free_port_is(port: int) -> bool:
    import socket

    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


FAKE_OPENCODE = """#!{python}
import base64, json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port = int(sys.argv[sys.argv.index("--port") + 1])
assert sys.argv[1] == "serve" and sys.argv[sys.argv.index("--hostname") + 1] == "127.0.0.1"
pw = os.environ.get("OPENCODE_SERVER_PASSWORD", "")
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        ok = bool(pw) and self.headers.get("authorization") == "Basic " + base64.b64encode(("opencode:" + pw).encode()).decode()
        body = json.dumps({{"authorized": ok, "path": self.path}}).encode()
        self.send_response(200 if ok else 401)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
HTTPServer(("127.0.0.1", port), H).serve_forever()
"""


def test_serve_starts_opencode_with_the_local_password_runs_the_connector_and_stops_on_sigint(tmp_path):
    """The whole `serve` command: a fake `opencode` on PATH is started with the password from the env file, the connector
    answers a sealed request through a local relay with that password, and Ctrl-C stops both."""
    import asyncio
    import json
    import signal

    from fakes import fake_relay, until

    from witbitz_code import pairings as pp
    from witbitz_code.relay import RelayPeer, new_relay_secret

    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "opencode"
    fake.write_text(FAKE_OPENCODE.format(python=sys.executable))
    fake.chmod(0o755)
    pp.env_path().write_text("OPENCODE_SERVER_PASSWORD=from-the-env-file\n")
    port = _free_port()

    async def go():
        relay = await fake_relay()
        secret = new_relay_secret()
        pp.write_pairings({"v": 1, "pairings": [{"account": "me@x", "idx": {"room": "r", "mk": "m"}, "computerId": "cmp_1",
                                                 "secret": secret, "name": "desk", "relay": relay.url,
                                                 "opencodeUrl": f"http://127.0.0.1:{port}"}]})
        env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONUSERBASE": USER_BASE, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}
        proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "witbitz_code", "serve", "--port", str(port),
                                                    env=env, stderr=asyncio.subprocess.PIPE)
        got = []
        client = RelayPeer(secret=secret, role="client", relay=relay.url, on_message=got.append)
        try:
            await client.start()
            assert await until(lambda: client.is_open and client.peers == 2, 20), "serve joined the channel"
            await client.send({"t": "ping"})
            assert await until(lambda: any(m.get("t") == "hello" and m.get("k") for m in got), 10), "its sealed hello"
            nonce = [m for m in got if m.get("t") == "hello"][-1]["k"]
            assert await client.send({"t": "req", "id": "a1", "k": nonce, "m": "GET", "p": "/agent"})
            assert await until(lambda: any(m.get("id") == "a1" for m in got), 10)
            res = next(m for m in got if m.get("id") == "a1")
            assert res["st"] == 200 and json.loads(res["b"]) == {"authorized": True, "path": "/agent"}
            proc.send_signal(signal.SIGINT)
            code = await asyncio.wait_for(proc.wait(), 15)
            stderr = (await proc.stderr.read()).decode()
            assert code == 0, stderr
            assert f"starting OpenCode on 127.0.0.1:{port}" in stderr and 'serving "desk" → me@x through the sealed relay' in stderr
            assert "from-the-env-file" not in stderr and secret not in stderr, "never print a secret"
            assert await until(lambda: client.peers == 1, 10), "the connector left the channel"
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await client.aclose()
            await relay.close()
        # the fake OpenCode child was terminated with serve
        await asyncio.sleep(0.2)
        import socket
        with socket.socket() as s:
            assert s.connect_ex(("127.0.0.1", port)) != 0, "OpenCode was stopped with serve"

    asyncio.run(asyncio.wait_for(go(), 90))


def test_ctrl_c_while_opencode_is_still_starting_stops_it_too(tmp_path):
    import asyncio
    import signal

    from witbitz_code import pairings as pp

    bindir = tmp_path / "bin"
    bindir.mkdir()
    pidfile = tmp_path / "opencode.pid"
    fake = bindir / "opencode"
    fake.write_text(f"#!{sys.executable}\nimport os, time\nopen({str(pidfile)!r}, 'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    fake.chmod(0o755)
    port = _free_port()
    pp.write_pairings({"v": 1, "pairings": [{"account": "me@x", "idx": {"room": "r", "mk": "m"}, "computerId": "cmp_1",
                                             "secret": "S" * 43, "name": "desk", "relay": "ws://127.0.0.1:1",
                                             "opencodeUrl": f"http://127.0.0.1:{port}"}]})

    async def go():
        env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONUSERBASE": USER_BASE, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}
        proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "witbitz_code", "serve", "--port", str(port),
                                                    env=env, stderr=asyncio.subprocess.PIPE)
        try:
            for _ in range(200):
                if pidfile.exists() and pidfile.read_text():
                    break
                await asyncio.sleep(0.05)
            child_pid = int(pidfile.read_text())
            proc.send_signal(signal.SIGINT)  # before OpenCode ever listens
            assert await asyncio.wait_for(proc.wait(), 15) == 0, (await proc.stderr.read()).decode()
            await asyncio.sleep(0.2)
            gone = False
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                gone = True
            if not gone:  # reaped? a zombie still answers kill(0); check its state
                with open(f"/proc/{child_pid}/stat") as f:
                    gone = f.read().split(")")[-1].split()[0] == "Z"
            assert gone, "OpenCode was not left running"
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    asyncio.run(asyncio.wait_for(go(), 60))
