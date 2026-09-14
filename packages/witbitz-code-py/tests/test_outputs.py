"""Produced files for the page's preview — outputs.py, held to spaces/test/codeOutputs.vectors.json and to tools/code-outputs.mjs.

The JS module is the reference: the same folder tree and the same requests must get the same answers from both connectors,
so a page previews the same files whichever connector a computer runs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import REPO, requires_node, run_node

from witbitz_code.auto import _sensitive_path
from witbitz_code.outputs import output_kind, output_mime, serve_output, valid_output_path

VECTORS = json.loads((REPO / "spaces" / "test" / "codeOutputs.vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", VECTORS["kinds"], ids=lambda c: repr(c[0]))
def test_kind(case):
    assert output_kind(case[0]) == case[1]


@pytest.mark.parametrize("case", VECTORS["sensitive"], ids=lambda c: repr(c[0]))
def test_sensitive(case):
    assert _sensitive_path(case[0]) is case[1]


@pytest.mark.parametrize("case", VECTORS["paths"], ids=lambda c: repr(c[0]))
def test_path(case):
    assert valid_output_path(case[0]) is case[1]


def _tree(tmp: Path) -> tuple[Path, Path]:
    d, outside = tmp / "תיקייה 1", tmp / "elsewhere"
    (d / "out").mkdir(parents=True)
    outside.mkdir()
    (d / ".git").mkdir()
    for p, b in [(d / "out" / "דוח - 14.pdf", b"%PDF-1.4 test"), (d / "out" / "chart.png", b"PNG"), (d / "app.ts", b"code"),
                 (d / ".env", b"KEY=1"), (d / ".git" / "x.pdf", b"x"), (d / "my-credentials.pdf", b"x"),
                 (outside / "report.pdf", b"outside"), (d / "out" / "big.pdf", b"\0" * 2048)]:
        p.write_bytes(b)
        os.utime(p, (1789000000, 1789000000))
    (d / "out" / "link-out.pdf").symlink_to(outside / "report.pdf")
    (d / "out" / "folder-out").symlink_to(outside)
    (d / "out" / "env.pdf").symlink_to(d / ".env")
    (d / "out" / "alias.png").symlink_to(d / "out" / "chart.png")
    return d, outside


def _requests(d: Path, outside: Path, root: Path) -> list[dict]:
    paths = [d / "out" / "דוח - 14.pdf", d / "out" / "chart.png", d / "out" / "alias.png", outside / "report.pdf",
             d / "out" / "link-out.pdf", d / "out" / "folder-out" / "report.pdf", d / "out" / "env.pdf", d / "my-credentials.pdf",
             d / ".git" / "x.pdf", d / "app.ts", d / "out" / "missing.pdf"]
    reqs = [{"directory": str(d), "path": str(p), "stat": s} for p in paths for s in (False, True)]
    reqs += [{"directory": str(d), "path": f"{d}/out/../../elsewhere/report.pdf", "stat": False},
             {"directory": str(d), "path": f"{d}10/x.pdf", "stat": False},
             {"directory": str(d), "path": str(d / "out") + "/", "stat": False},
             {"directory": str(d), "path": "out/chart.png", "stat": False},
             {"directory": str(d), "path": f"{d}/out/a\nb.png", "stat": False},
             {"directory": "", "path": str(d / "out" / "chart.png"), "stat": False},
             {"directory": str(root / "gone"), "path": str(root / "gone" / "a.png"), "stat": False},
             {"directory": str(d) + "/", "path": str(d / "out" / "chart.png"), "stat": False},
             {"directory": str(d), "path": str(d / "out" / "big.pdf"), "stat": False, "maxBytes": 1024},
             {"directory": str(d), "path": str(d / "out" / "big.pdf"), "stat": True, "maxBytes": 1024},
             {"directory": str(d), "path": None, "stat": False}]
    return reqs


def _py(r: dict) -> list:
    kw = {"max_bytes": r["maxBytes"]} if "maxBytes" in r else {}
    st, b = serve_output(directory=r["directory"], path=r["path"], stat=r["stat"], **kw)
    return [st, json.loads(b)]


def test_what_the_python_connector_serves(tmp_path):
    d, outside = _tree(tmp_path)
    st, body = _py({"directory": str(d), "path": str(d / "out" / "דוח - 14.pdf"), "stat": False})
    assert st == 200 and {k: body[k] for k in ("name", "kind", "mime", "size", "mtime")} == {
        "name": "דוח - 14.pdf", "kind": "pdf", "mime": "application/pdf", "size": 13, "mtime": 1789000000000}
    assert _py({"directory": str(d), "path": str(d / "out" / "link-out.pdf"), "stat": False})[0] == 403, "a link out"
    assert _py({"directory": str(d), "path": str(d / "out" / "folder-out" / "report.pdf"), "stat": False})[0] == 403, "through a folder link out"
    assert _py({"directory": str(d), "path": str(d / "out" / "alias.png"), "stat": False})[0] == 200, "a link inside to a file inside"
    assert _py({"directory": str(d), "path": f"{d}10/x.pdf", "stat": False})[0] == 403, "a look-alike sibling, refused by name"
    big = _py({"directory": str(d), "path": str(d / "out" / "big.pdf"), "stat": False, "maxBytes": 1024})
    assert big[0] == 413 and "b64" not in big[1]


@requires_node
def test_parity_with_the_js_connector(tmp_path):
    d, outside = _tree(tmp_path)
    reqs = _requests(d, outside, tmp_path)
    js = run_node("""
      import { serveOutput } from '@TOOLS@/code-outputs.mjs'
      import { outputMime } from '@PUBLIC@/codeOutputs.js'
      OUT({
        served: INPUT.reqs.map((r) => { const o = serveOutput({ directory: r.directory, path: r.path, stat: r.stat, ...(r.maxBytes ? { maxBytes: r.maxBytes } : {}) }); return [o.st, JSON.parse(o.b)] }),
        mimes: INPUT.exts.map((e) => outputMime('/a/x.' + e)),
      })
    """, {"reqs": reqs, "exts": EXTS})
    for r, want in zip(reqs, js["served"]):
        assert _py(r) == want, f"{r!r}"
    assert [output_mime("/a/x." + e) for e in EXTS] == js["mimes"]


EXTS = ["pdf", "PNG", "jpg", "jpeg", "gif", "webp", "csv", "tsv", "md", "markdown", "txt", "docx", "doc", "xlsx", "xls", "pptx", "ppt",
        "odt", "ods", "odp", "rtf", "zip", "epub", "heic", "svg", "html", "htm", "mp3", "wav", "m4a", "mp4", "mov", "ts", "json", ""]
