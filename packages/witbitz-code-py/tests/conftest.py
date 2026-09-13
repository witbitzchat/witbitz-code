"""Shared test plumbing: run the JS reference modules in node, and keep every test hermetic (localhost only, temp HOME files).

The cross-implementation tests need the witbitz repo beside this package (spaces/public/*.js, tools/*.mjs) and `node`
≥ 22 on PATH. Set WITBITZ_REPO to point elsewhere; without either they are skipped, not failed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))  # run against the source tree without installing
sys.path.insert(0, str(HERE))

REPO = Path(os.environ.get("WITBITZ_REPO") or HERE.parents[2])
PUBLIC = REPO / "spaces" / "public"
TOOLS = REPO / "tools"
NODE = shutil.which("node")

requires_node = pytest.mark.skipif(
    not NODE or not (PUBLIC / "codeRelay.js").exists() or not (TOOLS / "opencode-pair.mjs").exists(),
    reason="needs node and the witbitz JS sources (set WITBITZ_REPO)",
)

_PRELUDE = """
const INPUT = JSON.parse(await new Promise((resolve) => {
  let s = ''; process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => { s += c }); process.stdin.on('end', () => resolve(s || 'null'))
}));
const OUT = (v) => process.stdout.write(JSON.stringify(v) + '\\n');
"""


def js_source(script: str) -> str:
    """@PUBLIC@ / @TOOLS@ → file URLs of the reference sources."""
    return script.replace("@PUBLIC@", PUBLIC.as_uri()).replace("@TOOLS@", TOOLS.as_uri())


def node_env(**extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env.update(extra)
    return env


def run_node(script: str, data: Any = None, timeout: float = 60, **env: str) -> Any:
    """Run an ES module in node with `INPUT` (JSON on stdin); it reports with OUT(value). Returns the last value."""
    proc = subprocess.run(
        [NODE, "--input-type=module", "-e", _PRELUDE + js_source(script)],
        input=json.dumps(data), capture_output=True, text=True, encoding="utf-8", timeout=timeout,
        cwd=str(HERE), env=node_env(**env),
    )
    if proc.returncode != 0:
        raise AssertionError(f"node failed ({proc.returncode}):\n{proc.stderr}")
    lines = [ln for ln in proc.stdout.split("\n") if ln.strip()]  # not splitlines(): U+2028 is not a line break to JSON
    assert lines, f"node printed nothing; stderr:\n{proc.stderr}"
    return json.loads(lines[-1])


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch):
    """No test may touch the real ~/.witbitz, ~/.opencode-server.env or a proxy."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("WITBITZ_CODE_PAIRINGS", str(tmp_path / "home" / ".witbitz" / "code" / "pairings.json"))
    monkeypatch.setenv("OPENCODE_ENV_FILE", str(tmp_path / "home" / ".opencode-server.env"))
    for k in list(os.environ):
        if "proxy" in k.lower():
            monkeypatch.delenv(k)
    for k in ("RC_BASE", "RC_ORIGIN", "RC_LINK_ORIGIN", "RC_LINK_WAIT_MS"):
        monkeypatch.delenv(k, raising=False)
