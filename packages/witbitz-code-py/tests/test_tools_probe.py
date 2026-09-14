""""Set up this computer" in the Python connector: which suggested tools this computer has (witbitz_code/tools_probe.py).

- PARITY: the binary names match spaces/public/codeTools.js, and generated filesystems get the same answers from this module
  and tools/code-tools-probe.mjs, for Linux, macOS, Windows and an unknown OS.
- THE WIRING: the page's nonce-checked `{t:'tools'}` is answered by BOTH connectors, and a stale nonce gets nothing.
"""

from __future__ import annotations

import asyncio
import random

import pytest
from conftest import requires_node, run_node
from test_connector_e2e import JsConnector, PyClient, PyConnector, Rig, run

from witbitz_code.tools_probe import PACKAGE_MANAGERS, TOOL_BINS, probe_tools

CATALOG_JS = """
  import { TOOLS, PACKAGE_MANAGERS } from '@PUBLIC@/codeTools.js'
  import { probeTools } from '@TOOLS@/code-tools-probe.mjs'
  const answers = INPUT.cases.map((c) => { const set = new Set(c.files); return probeTools({ env: c.env, platform: c.platform, home: c.home, isExecutable: (p) => set.has(p) }) })
  OUT({ bins: TOOLS.map((t) => [t.id, t.bins]), pms: PACKAGE_MANAGERS, answers })
"""

NAMES = sorted({b for _, bins in TOOL_BINS for b in bins} | {b for pms in PACKAGE_MANAGERS.values() for _, b in pms} | {"node", "ls"})


def _cases() -> list[dict]:
    rnd = random.Random(20260914)
    out = []
    for _ in range(300):
        platform = rnd.choice(["linux", "darwin", "win32", "freebsd"])
        win = platform == "win32"
        home = rnd.choice(["/home/u", "/Users/u/", "", "C:\\Users\\u"])
        pool = (["C:\\Tools", "C:\\Windows\\System32", "D:\\bin\\"] if win else ["/usr/bin", "/opt/homebrew/bin", "/x/y/", "/home/u/.local/bin", "/Users/u/.cargo/bin", "/snap/bin"])
        path_dirs = rnd.sample(pool, rnd.randint(0, len(pool)))
        env = {"PATH": (";" if win else ":").join(path_dirs + ([""] if rnd.random() < 0.2 else []))}
        if win and rnd.random() < 0.5:
            env["PATHEXT"] = rnd.choice([".EXE;.CMD", ".COM;.EXE;.BAT;.CMD", ".exe"])
        files = []
        for _ in range(rnd.randint(0, 12)):
            d = rnd.choice(pool)
            name = rnd.choice(NAMES) + (rnd.choice(["", ".exe", ".cmd", ".EXE"]) if win else "")
            files.append(f"{d.rstrip(chr(92) + '/')}\\{name}" if win else f"{d.rstrip('/')}/{name}")
        out.append({"env": env, "platform": platform, "home": home, "files": files})
    return out


@requires_node
def test_the_catalog_and_every_answer_match_the_javascript_probe():
    cases = _cases()
    js = run_node(CATALOG_JS, {"cases": cases})
    assert [[tid, bins] for tid, bins in TOOL_BINS] == js["bins"], "the same tools, the same names, the same order"
    assert {os_id: [list(x) for x in pms] for os_id, pms in PACKAGE_MANAGERS.items()} == js["pms"]
    found = 0
    for case, want in zip(cases, js["answers"]):
        files = set(case["files"])
        got = probe_tools(env=case["env"], platform=case["platform"], home=case["home"], is_executable=files.__contains__)
        assert got == want, case
        found += sum(got["tools"].values())
    assert found > 100, "the generator finds tools, not only their absence"


def test_a_real_folder_with_an_executable_counts_and_a_plain_file_does_not(tmp_path):
    (tmp_path / "ffmpeg").write_text("#!/bin/sh\n")
    (tmp_path / "ffmpeg").chmod(0o755)
    (tmp_path / "pandoc").write_text("not executable")
    r = probe_tools(env={"PATH": str(tmp_path)}, platform="linux", home="", is_executable=lambda p: p.startswith(str(tmp_path)) and __import__("os").access(p, __import__("os").X_OK))
    assert r["tools"]["ffmpeg"] is True and r["tools"]["pandoc"] is False


CONNECTORS = [pytest.param(PyConnector, id="python"), pytest.param(JsConnector, id="js", marks=requires_node)]


@pytest.mark.parametrize("make", CONNECTORS)
def test_the_connector_answers_tools_with_the_current_nonce_only(make, tmp_path):
    async def go():
        async with Rig() as rig:
            connector = make(rig, 30_000, autoDir=str(tmp_path / "auto"))
            await connector.start()
            client = PyClient(rig.secret, rig.relay.url)
            try:
                await client.start()
                await client.peer.send({"t": "tools", "k": "stale"})
                await asyncio.sleep(0.4)
                assert not [m for m in client.got if isinstance(m, dict) and m.get("t") == "tools"], "a recording gets no answer"
                await client.peer.send({"t": "tools", "k": client.nonce})
                for _ in range(200):
                    got = [m for m in client.got if isinstance(m, dict) and m.get("t") == "tools"]
                    if got:
                        break
                    await asyncio.sleep(0.025)
                assert got, "the computer answered"
                want = probe_tools()  # the same machine, the same PATH and HOME — and the JS probe gives the same answers
                assert {k: got[0][k] for k in ("tools", "platform")} == want
                assert set(got[0]) == {"t", "tools", "platform"}, "nothing else leaves the computer"
            finally:
                await client.peer.aclose()
                await connector.stop()

    run(go())
