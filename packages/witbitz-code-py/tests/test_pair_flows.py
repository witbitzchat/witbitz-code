"""Pairing a computer with an account (tools/opencode-pair.test.mjs, in Python) — against a mock account API with the
server's semantics — and the command flows: pair, status, rotate, unpair."""

from __future__ import annotations

import asyncio
import json
import os

from conftest import requires_node, run_node
from fakes import MockApi

from witbitz_code import account as acct
from witbitz_code import pair
from witbitz_code import pairings as pp
from witbitz_code.computers import norm_registry, with_computer

IDX = {"room": "sp-idx", "mk": "MK"}
IDX2 = {"room": "sp-other", "mk": "MK2"}
SECRET = "S" * 43
RELAY = "wss://code-relay.witbitz.chat"


def run(coro):
    return asyncio.run(coro)


def test_publish_refuses_without_a_definitive_read_and_writes_nothing():
    api = MockApi(read_status=503)
    r = run(acct.publish_computer(call=api.call, idx=IDX, computer_id="cmp_desk_01", name="desk", relay=RELAY, secret=SECRET, now=1000))
    assert r["ok"] is False and "503" in r["why"] and "NOT writing" in r["why"]
    assert api.writes == []


def test_publish_adds_beside_the_others_and_verifies():
    other = with_computer(None, "cmp_laptop_1", {"name": "laptop", "relay": RELAY, "secret": "L" * 43}, 500)
    api = MockApi(docs={"computers": other})
    r = run(acct.publish_computer(call=api.call, idx=IDX, computer_id="cmp_desk_01", name="desk", relay=RELAY, secret=SECRET, now=1000))
    assert r["ok"], r
    assert len(api.writes) == 1 and api.writes[0]["name"] == "computers" and api.writes[0]["room"] == "sp-idx"
    assert api.writes[0]["summary"] == "computer paired" and api.writes[0]["by"] == "node"
    reg = norm_registry(api.plain("computers"))
    assert sorted(reg["computers"]) == ["cmp_desk_01", "cmp_laptop_1"], "the laptop survived"
    assert reg["computers"]["cmp_desk_01"]["secret"] == SECRET
    assert [c["name"] for c in r["computers"]] == ["laptop", "desk"]


def test_publish_detects_a_read_back_that_does_not_match():
    api = MockApi()
    real = api.call

    async def lossy(body):
        if "patch" in body:
            return await real({**body, "patch": {"v": 1, "computers": {}}})
        return await real(body)

    r = run(acct.publish_computer(call=lossy, idx=IDX, computer_id="cmp_desk_01", name="desk", relay=RELAY, secret=SECRET, now=1))
    assert r["ok"] is False and "read-back" in r["why"]


def test_unpublish_tombstones_and_a_second_unpair_writes_nothing():
    api = MockApi(docs={"computers": with_computer(None, "cmp_desk_01", {"name": "desk", "relay": RELAY, "secret": SECRET}, 500)})
    r = run(acct.unpublish_computer(call=api.call, idx=IDX, computer_id="cmp_desk_01", now=1000))
    assert r["ok"], r
    e = norm_registry(api.plain("computers"))["computers"]["cmp_desk_01"]
    assert e["removed"] is True and "secret" not in e
    assert run(acct.unpublish_computer(call=api.call, idx=IDX, computer_id="cmp_desk_01", now=2000))["noop"] is True
    assert len(api.writes) == 1
    assert run(acct.unpublish_computer(call=MockApi(read_status=500).call, idx=IDX, computer_id="x"))["ok"] is False


def test_clear_legacy_direct_keeps_contacts_and_the_model():
    api = MockApi(docs={"index2": {"v": 2, "contacts": [{"kind": "person", "email": "dana@example.com"}],
                                   "code": {"base": "https://old.example", "pass": "p", "model": "m", "agent": "build", "mod": 50}}})
    assert run(acct.clear_legacy_direct(call=api.call, idx=IDX, now=9))["ok"]
    d = api.plain("index2")
    assert (d["code"]["base"], d["code"]["pass"], d["code"]["model"]) == ("", "", "m") and d["code"]["mod"] > 50
    assert d["contacts"] == [{"kind": "person", "email": "dana@example.com"}]
    assert run(acct.clear_legacy_direct(call=api.call, idx=IDX, now=10))["noop"] is True
    assert len(api.writes) == 1
    assert run(acct.clear_legacy_direct(call=MockApi(read_status=500).call, idx=IDX))["ok"] is False


@requires_node
def test_a_large_registry_is_gzip_wrapped_and_the_js_side_reads_and_extends_it():
    docs = {"computers": None}
    for i in range(200):
        docs["computers"] = with_computer(docs["computers"], f"cmp_{i:08d}", {"name": f"box {i}", "relay": RELAY, "secret": SECRET}, 1000 + i)
    api = MockApi(docs=dict(docs))
    r = run(acct.publish_computer(call=api.call, idx=IDX, computer_id="cmp_python_1", name="py", relay=RELAY, secret="P" * 43, now=5000))
    assert r["ok"], r
    wrapped = api.docs["computers"]
    assert set(wrapped) == {"z"}, "above 24 KB the doc travels as {z}"
    out = run_node("""
      import { gunzipB64 } from '@PUBLIC@/compress.js'
      import { liveComputers, withComputer } from '@PUBLIC@/codeComputers.js'
      const reg = await gunzipB64(INPUT.z)
      const next = withComputer(reg, 'cmp_js_00001', { name: 'js', relay: INPUT.relay, secret: 'J'.repeat(43) }, 6000)
      OUT({ live: liveComputers(reg).length, last: liveComputers(reg).at(-1), next })
    """, {"z": wrapped["z"], "relay": RELAY})
    assert out["live"] == 201 and out["last"]["id"] == "cmp_python_1"
    api.docs["computers"] = out["next"]
    back = run(acct.read_doc(api.call, IDX, "computers"))
    assert "cmp_js_00001" in norm_registry(back["state"])["computers"]


# ── the command flows ─────────────────────────────────────────────────────────────────────────────────────────────────
class Capture:
    def __init__(self):
        self.out, self.err = [], []

    def kw(self):
        return {"out": self.out.append, "err": self.err.append}

    def text(self):
        return "\n".join(self.out + self.err)


def test_pair_status_rotate_unpair_end_to_end():
    api = MockApi()
    cap = Capture()

    async def link_fn():
        return {"email": "me@x", "idx": IDX, "master": "M" * 43}

    assert run(pair.main(["--name", "desk"], call=api.call, link_fn=link_fn, **cap.kw())) == 0, cap.text()
    doc = pp.read_pairings()
    assert len(doc["pairings"]) == 1 and doc["pairings"][0]["name"] == "desk" and doc["pairings"][0]["account"] == "me@x"
    assert os.stat(pp.pairings_path()).st_mode & 0o777 == 0o600
    assert pp.read_env_password(), "a local OpenCode password was minted"
    assert os.stat(pp.env_path()).st_mode & 0o777 == 0o600
    first_secret = doc["pairings"][0]["secret"]
    assert first_secret not in cap.text() and pp.read_env_password() not in cap.text(), "never print a secret"
    reg = norm_registry(api.plain("computers"))
    assert reg["computers"][doc["pairings"][0]["computerId"]]["secret"] == first_secret

    cap = Capture()
    assert run(pair.main(["--status"], **cap.kw())) == 0
    assert '"desk" → me@x · OpenCode http://127.0.0.1:4096 · relay wss://code-relay.witbitz.chat' in cap.text()
    assert first_secret not in cap.text()

    async def link_fn2():
        return {"email": "work@y", "idx": IDX2, "master": "M" * 43}

    cap = Capture()
    assert run(pair.main([], call=api.call, link_fn=link_fn2, **cap.kw())) == 0
    assert "reachable from work@y AND me@x" in cap.text(), "the shared-OpenCode warning"
    assert "start OpenCode and the connector:  witbitz-code serve" in cap.text()

    cap = Capture()
    assert run(pair.main(["--rotate", "--account", "me@x", "--dry-run"], call=api.call, **cap.kw())) == 0
    assert "would rotate 1 pairing(s)" in cap.text(), "--dry-run honours --account"
    cap = Capture()
    assert run(pair.main(["--rotate", "--dry-run"], call=api.call, **cap.kw())) == 0 and "would rotate 2 pairing(s)" in cap.text()
    cap = Capture()
    assert run(pair.main(["--rotate", "--account", "me@x"], call=api.call, **cap.kw())) == 0, cap.text()
    rotated = next(p for p in pp.read_pairings()["pairings"] if p["account"] == "me@x")
    assert rotated["secret"] != first_secret and rotated["computerId"] == doc["pairings"][0]["computerId"]

    cap = Capture()
    assert run(pair.main(["--unpair"], call=api.call, **cap.kw())) == 1
    assert "paired with 2 accounts" in cap.text()
    cap = Capture()
    assert run(pair.main(["--unpair", "--account", "me@x", "--dry-run"], call=api.call, **cap.kw())) == 0
    assert len(pp.read_pairings()["pairings"]) == 2
    cap = Capture()
    assert run(pair.main(["--unpair", "--account", "me@x"], call=api.call, **cap.kw())) == 0
    assert "restart the connector (witbitz-code serve)" in cap.text()
    assert [p["account"] for p in pp.read_pairings()["pairings"]] == ["work@y"]
    assert norm_registry(api.plain("computers"))["computers"][rotated["computerId"]] == {"removed": True, "mod": norm_registry(api.plain("computers"))["computers"][rotated["computerId"]]["mod"]}


def test_pair_flow_failures_change_nothing_locally():
    cap = Capture()

    async def no_scan():
        return None

    assert run(pair.main([], call=MockApi().call, link_fn=no_scan, **cap.kw())) == 1
    assert not pp.pairings_path().exists() and "nothing changed" in cap.text()

    async def no_idx():
        return {"email": "me@x", "idx": None, "master": "m"}

    cap = Capture()
    assert run(pair.main([], call=MockApi().call, link_fn=no_idx, **cap.kw())) == 1
    assert "no index-room pointer" in cap.text()

    async def ok_scan():
        return {"email": "me@x", "idx": IDX, "master": "m"}

    cap = Capture()
    assert run(pair.main([], call=MockApi(read_status=503).call, link_fn=ok_scan, **cap.kw())) == 1
    assert not pp.pairings_path().exists() and "nothing saved locally" in cap.text()
    assert run(pair.main(["--bogus"], **Capture().kw())) == 2
    assert run(pair.main(["--rotate"], call=MockApi().call, **Capture().kw())) == 1
    assert run(pair.main(["--unpair"], call=MockApi().call, **Capture().kw())) == 1
    assert run(pair.main(["--dry-run"], **Capture().kw())) == 0


def test_parse_args_mirrors_the_js_flags():
    a = pair.parse_args(["--port", "4097", "--name", "box", "--account", "a@b", "--dry-run"])
    assert (a.opencode_url, a.name, a.account, a.dry) == ("http://127.0.0.1:4097", "box", "a@b", True)
    assert pair.parse_args(["--port", "nope"]).opencode_url == ""
    assert pair.parse_args(["--name"]).name == ""


def test_an_existing_env_file_keeps_its_other_lines(tmp_path):
    pp.env_path().write_text("OTHER=1\n")
    pair.ensure_local_password(out=lambda m: None)
    text = pp.env_path().read_text()
    assert text.startswith("OTHER=1\nOPENCODE_SERVER_PASSWORD=") and len(pp.read_env_password()) == 32
    before = text
    pair.ensure_local_password(out=lambda m: None)
    assert pp.env_path().read_text() == before, "an existing password is never replaced"


def test_status_output_is_json_free_of_secrets_even_for_js_written_files():
    pp.write_pairings({"v": 1, "pairings": [{"account": "me@x", "idx": IDX, "computerId": "cmp_1", "secret": SECRET,
                                             "name": "desk", "relay": RELAY, "opencodeUrl": "http://127.0.0.1:4096"}]})
    cap = Capture()
    run(pair.main(["--status"], **cap.kw()))
    assert SECRET not in cap.text() and "MK" not in cap.text()
    assert json.loads(pp.pairings_path().read_text())["pairings"][0]["secret"] == SECRET
