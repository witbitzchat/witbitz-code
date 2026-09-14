"""The pairings file (shared with the JS tools), the env file, and the gzip wrap of account docs."""

from __future__ import annotations

import json
import os
from pathlib import Path

from conftest import requires_node, run_node

from witbitz_code import _js, compress
from witbitz_code import pairings as pp

IDX = {"room": "sp-idx", "mk": "MK"}
IDX2 = {"room": "sp-other", "mk": "MK2"}
SECRET = "S" * 43


def minted():
    n = [0]

    def mint_id():
        n[0] += 1
        return f"cmp_{n[0]}"

    def mint_secret():
        n[0] += 1
        return "x" * 40 + str(n[0]).zfill(3)

    return mint_id, mint_secret


# ── 6. the pairings file ──────────────────────────────────────────────────────────────────────────────────────────────
def _python_doc() -> dict:
    mid, msec = minted()
    a = pp.upsert_pairing(None, account="me@x", idx=IDX, name="desk ✓", mint_id=mid, mint_secret=msec)
    b = pp.upsert_pairing(a["doc"], account="work@y", idx=IDX2, name="desk", opencode_url="http://127.0.0.1:4097", mint_id=mid, mint_secret=msec)
    return b["doc"]


@requires_node
def test_a_file_written_by_python_is_read_by_both_js_loaders_and_serializes_identically(tmp_path):
    doc = _python_doc()
    path = tmp_path / "pairings.json"
    pp.write_pairings(doc, path)
    assert path.stat().st_mode & 0o777 == 0o600
    out = run_node("""
      import { readFileSync } from 'node:fs'
      import { normPairings } from '@TOOLS@/opencode-pair.mjs'
      import { loadPairings } from '@TOOLS@/opencode-connector.mjs'
      const text = readFileSync(INPUT.path, 'utf8')
      const norm = normPairings(JSON.parse(text))
      OUT({ norm, loaded: loadPairings(INPUT.path, () => {}), rewritten: JSON.stringify(norm, null, 1) + '\\n' })
    """, {"path": str(path)})
    assert out["norm"] == doc and len(out["loaded"]) == 2
    assert out["rewritten"] == path.read_text(encoding="utf-8"), "byte-for-byte what writePairings would have written"


@requires_node
def test_a_file_written_by_js_is_read_by_python(tmp_path):
    path = tmp_path / "pairings.json"
    out = run_node("""
      import { writeFileSync } from 'node:fs'
      import { upsertPairing } from '@TOOLS@/opencode-pair.mjs'
      let n = 0
      const mint = { mintId: () => 'cmp_' + (++n), mintSecret: () => 'x'.repeat(40) + String(++n).padStart(3, '0') }
      const a = upsertPairing(null, { account: 'me@x', idx: INPUT.idx, name: 'desk ✓' }, mint)
      const b = upsertPairing(a.doc, { account: 'work@y', idx: INPUT.idx2, name: 'desk', opencodeUrl: 'http://127.0.0.1:4097' }, mint)
      const text = JSON.stringify(b.doc, null, 1) + '\\n'
      writeFileSync(INPUT.path, text)
      OUT(text)
    """, {"idx": IDX, "idx2": IDX2, "path": str(path)})
    assert pp.read_pairings(path) == json.loads(out)
    assert len(pp.load_pairings(path, log=lambda m: None)) == 2
    assert pp.serialize_pairings(pp.read_pairings(path)) == out
    assert out == pp.serialize_pairings(_python_doc()), "the same inputs build the same file in either implementation"


@requires_node
def test_upsert_and_remove_semantics_match_js():
    out = run_node("""
      import { upsertPairing, removePairings, normPairings } from '@TOOLS@/opencode-pair.mjs'
      let n = 0
      const mint = { mintId: () => 'cmp_' + (++n), mintSecret: () => 'x'.repeat(40) + String(++n).padStart(3, '0') }
      const r = []
      const a = upsertPairing(null, { account: 'me@x', idx: INPUT.idx, name: 'desk' }, mint); r.push(a)
      const again = upsertPairing(a.doc, { idx: INPUT.idx, name: '' }, mint); r.push(again)
      const rot = upsertPairing(again.doc, { account: 'me@x', idx: INPUT.idx, name: 'n' }, { ...mint, rotate: true }); r.push(rot)
      const b = upsertPairing(rot.doc, { account: 'work@y', idx: INPUT.idx2, name: 'w', relay: 'ws://127.0.0.1:1' }, mint); r.push(b)
      const sep = upsertPairing(a.doc, { account: '', idx: INPUT.idx2, name: 'f', opencodeUrl: 'http://127.0.0.1:4097' }, mint); r.push(sep)
      const moved = upsertPairing(a.doc, { account: 'me@x', idx: INPUT.idx, opencodeUrl: 'http://127.0.0.1:4098' }, mint); r.push(moved)
      r.push(upsertPairing(moved.doc, { account: 'me@x', idx: INPUT.idx }, mint))
      r.push(removePairings(b.doc, 'work@y')); r.push(removePairings(b.doc, '')); r.push(removePairings(b.doc, 'nobody'))
      r.push(normPairings({ pairings: [{ account: 'no idx', secret: 's', computerId: 'c' }, null, { idx: { room: 'r', mk: 'm' }, secret: 's', computerId: 5 }, { idx: { room: 'r', mk: 'm' }, secret: 's', computerId: 'c' }] }))
      r.push(normPairings('junk'))
      OUT(r.map((x) => JSON.stringify(x)))
    """, {"idx": IDX, "idx2": IDX2})
    mid, msec = minted()
    m = {"mint_id": mid, "mint_secret": msec}
    r = []
    a = pp.upsert_pairing(None, account="me@x", idx=IDX, name="desk", **m); r.append(a)
    again = pp.upsert_pairing(a["doc"], idx=IDX, name="", **m); r.append(again)
    rot = pp.upsert_pairing(again["doc"], account="me@x", idx=IDX, name="n", rotate=True, **m); r.append(rot)
    b = pp.upsert_pairing(rot["doc"], account="work@y", idx=IDX2, name="w", relay="ws://127.0.0.1:1", **m); r.append(b)
    sep = pp.upsert_pairing(a["doc"], account="", idx=IDX2, name="f", opencode_url="http://127.0.0.1:4097", **m); r.append(sep)
    # an OpenCode asked for moves an account already paired; not asked, it keeps the one it had
    moved = pp.upsert_pairing(a["doc"], account="me@x", idx=IDX, opencode_url="http://127.0.0.1:4098", **m); r.append(moved)
    r.append(pp.upsert_pairing(moved["doc"], account="me@x", idx=IDX, **m))
    r += [pp.remove_pairings(b["doc"], "work@y"), pp.remove_pairings(b["doc"], ""), pp.remove_pairings(b["doc"], "nobody")]
    r.append(pp.norm_pairings({"pairings": [{"account": "no idx", "secret": "s", "computerId": "c"}, None,
                                            {"idx": {"room": "r", "mk": "m"}, "secret": "s", "computerId": 5},
                                            {"idx": {"room": "r", "mk": "m"}, "secret": "s", "computerId": "c"}]}))
    r.append(pp.norm_pairings("junk"))
    assert [_js.stringify(x) for x in r] == out
    assert b["sharedWith"] == ["me@x"] and sep["sharedWith"] == []
    assert moved["entry"]["opencodeUrl"] == "http://127.0.0.1:4098" and r[6]["entry"]["opencodeUrl"] == "http://127.0.0.1:4098"


ENV_CASES = [
    "OPENCODE_SERVER_USERNAME=opencode\nOPENCODE_SERVER_PASSWORD=old1\nTRUSTEDROUTER_API_KEY=tr-a\nTRUSTEDROUTER_API_KEY=tr-a\nOPENCODE_SERVER_PASSWORD=old2\n",
    "export OPENCODE_SERVER_PASSWORD=\"quoted\"\n", "OPENCODE_SERVER_PASSWORD='single' \n", "OPENCODE_SERVER_PASSWORD=crlf\r\n",
    "\ufeffOPENCODE_SERVER_PASSWORD=bom\n", "  OPENCODE_SERVER_PASSWORD=  spaced  \n", "OPENCODE_SERVER_PASSWORD=\"mismatch'\n",
    "OPENCODE_SERVER_PASSWORD=a\u2028b\n", "X=1\n", "", "OPENCODE_SERVER_PASSWORDX=no\n", "exportOPENCODE_SERVER_PASSWORD=no\n",
    "A=1\r\nOPENCODE_SERVER_PASSWORD=crlf-pass\r\nB=2\r\n", "OPENCODE_SERVER_PASSWORD=lone\rcr\n",
    "OPENCODE_SERVER_PASSWORD=\"q\"\r\n\r\n\r\n",
]


@requires_node
def test_env_file_reading_and_writing_match_js():
    out = run_node("""
      import { envGet, envSet } from '@TOOLS@/opencode-pair.mjs'
      import { parseEnvPassword } from '@TOOLS@/opencode-connector.mjs'
      OUT(INPUT.map((t) => [envGet(t, 'OPENCODE_SERVER_PASSWORD'), envSet(t, 'OPENCODE_SERVER_PASSWORD', 'new'), parseEnvPassword(t)]))
    """, ENV_CASES)
    got = [[pp.env_get(t, "OPENCODE_SERVER_PASSWORD"), pp.env_set(t, "OPENCODE_SERVER_PASSWORD", "new"), pp.parse_env_password(t)] for t in ENV_CASES]
    assert got == out


def test_env_file_units():
    env = ENV_CASES[0]
    assert pp.env_get(env, "OPENCODE_SERVER_PASSWORD") == "old2", "the LAST one wins, as when the file is sourced"
    assert pp.parse_env_password("A=1\r\nOPENCODE_SERVER_PASSWORD=crlf-pass\r\nB=2\r\n") == "crlf-pass", "a Windows-edited file"
    out = pp.env_set(env, "OPENCODE_SERVER_PASSWORD", "new-pass")
    assert pp.env_get(out, "OPENCODE_SERVER_PASSWORD") == "new-pass"
    assert out.count("OPENCODE_SERVER_PASSWORD=") == 1 and out.count("TRUSTEDROUTER_API_KEY=tr-a\n") == 2
    for mint in (pp.new_password, pp.new_computer_id):
        a, b = mint(), mint()
        assert len(a) >= 22 and a != b and all(c.isalnum() or c in "-_" for c in a)


def test_write_private_is_0600_atomic_and_leaves_no_temp(tmp_path):
    existing = tmp_path / "readable.json"
    existing.write_text("{}")
    existing.chmod(0o644)
    before = existing.stat().st_ino
    pp.write_pairings(_python_doc(), existing)
    assert existing.stat().st_mode & 0o777 == 0o600 and existing.stat().st_ino != before, \
        "the secret went into a new 0600 file that replaced the readable one — never into the readable one"
    path = tmp_path / "deep" / "dir" / "pairings.json"
    pp.write_pairings({"v": 1, "pairings": []}, path)
    pp.write_pairings(_python_doc(), path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert os.listdir(path.parent) == ["pairings.json"]
    assert pp.read_pairings(path) == _python_doc()
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    logs = []
    assert pp.read_pairings(bad) == {"v": 1, "pairings": []}
    assert pp.load_pairings(bad, log=logs.append) == [] and "not valid JSON" in logs[0]
    assert pp.load_pairings(Path(tmp_path / "absent.json")) == []
    skipped = tmp_path / "skip.json"
    skipped.write_text(json.dumps({"pairings": [{"secret": "short"}, {"secret": SECRET}]}))
    logs = []
    assert len(pp.load_pairings(skipped, log=logs.append)) == 1 and logs == ["witbitz-code: skipping a pairing with no secret"]


# ── 8. compress ───────────────────────────────────────────────────────────────────────────────────────────────────────
DOC = {"v": 1, "computers": {f"cmp_{i:08d}": {"name": f"box ✓ {i} 😀", "secret": "A" * 43, "mod": i + 0.5} for i in range(300)}}


@requires_node
def test_gzip_wrap_opens_across_implementations_and_sizes_agree():
    py_wrap = compress.gzip_b64(DOC)
    out = run_node("""
      import { gzipB64, gunzipB64, _jsonBytes } from '@PUBLIC@/compress.js'
      OUT({ opened: await gunzipB64(INPUT.z), wrapped: await gzipB64(INPUT.doc), bytes: _jsonBytes(INPUT.doc), nul: _jsonBytes(undefined) })
    """, {"z": py_wrap, "doc": DOC})
    assert out["opened"] == DOC
    assert compress.gunzip_b64(out["wrapped"]) == DOC
    assert compress.json_bytes(DOC) == out["bytes"] > 24000
    assert compress.json_bytes(_js.UNDEFINED) == out["nul"] == 4


def test_minting_the_password_into_an_existing_world_readable_or_symlinked_env_file(tmp_path):
    from witbitz_code import pair

    real = tmp_path / "real.env"
    real.write_text("OTHER=1\n")
    real.chmod(0o644)
    pp.env_path().symlink_to(real)
    pair.ensure_local_password(out=lambda m: None)
    assert pp.env_path().is_symlink(), "the user's symlink is kept"
    assert real.stat().st_mode & 0o777 == 0o600 and real.read_text().startswith("OTHER=1\nOPENCODE_SERVER_PASSWORD=")
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".real.env")] == [], "no temp file left behind"
