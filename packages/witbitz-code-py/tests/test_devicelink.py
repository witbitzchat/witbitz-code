"""Device link (deviceLink.js), the backup keys (recovery.js), the QR (qrRender.js) and the link poll (rc-link.mjs)."""

from __future__ import annotations

import asyncio
import json
import subprocess

import pytest
from conftest import NODE, js_source, node_env, requires_node, run_node

from witbitz_code import _js, devicelink, link, qr

PAYLOAD_ARGS = {
    "vault": {"master": "TUFTVEVSX0IyNA", "code": "ABCD-EFGH"}, "email": "someone@example.com",
    "idx": {"room": "sp-idx-abc", "mk": "idxmk"}, "anchor": {"method": "google", "email": "someone@example.com", "exp": 99},
    "rel": {"gid": "g1", "token": "REL"},
}


@requires_node
def test_python_challenge_js_seals_python_opens():
    ch = devicelink.new_link_challenge()
    assert ch.text.startswith("wbzlink1:") and len(ch.pub) == 44
    out = run_node("""
      import { parseChallenge, sealToChallenge, linkPayload } from '@PUBLIC@/deviceLink.js'
      const parsed = parseChallenge(INPUT.text)
      OUT({ parsed, sealed: await sealToChallenge(parsed, linkPayload(INPUT.args)), expected: linkPayload(INPUT.args) })
    """, {"text": ch.text, "args": PAYLOAD_ARGS})
    assert out["parsed"] == {"ref": ch.ref, "pub": ch.pub}, "the JS scanner accepts the Python QR text"
    opened = devicelink.open_link_reply(ch.priv, out["sealed"])
    assert opened == out["expected"]
    pay = devicelink.read_link_payload(opened)
    account = link.account_from_payload(pay)
    assert account["master"] == "TUFTVEVSX0IyNA" and account["email"] == "someone@example.com"
    assert account["idx"] == {"room": "sp-idx-abc", "mk": "idxmk"}
    assert pay["anchor"] == {"method": "google", "email": "someone@example.com", "exp": 99}
    other = devicelink.new_link_challenge()
    with pytest.raises(Exception):
        devicelink.open_link_reply(other.priv, out["sealed"])  # a different key cannot open it


@requires_node
def test_js_challenge_python_seals_js_opens():
    script = js_source("""
      import { newLinkChallenge, openLinkReply, readLinkPayload } from '@PUBLIC@/deviceLink.js'
      import { createInterface } from 'node:readline'
      const ch = await newLinkChallenge()
      console.log(JSON.stringify({ ref: ch.ref, pub: ch.pub, text: ch.text }))
      const rl = createInterface({ input: process.stdin })
      for await (const line of rl) {
        const reply = JSON.parse(line)
        let res
        try { res = { ok: true, pay: readLinkPayload(await openLinkReply(ch.priv, reply)) } } catch (e) { res = { ok: false, err: String(e) } }
        console.log(JSON.stringify(res))
      }
    """)
    proc = subprocess.Popen([NODE, "--input-type=module", "-e", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", env=node_env())
    try:
        ch = json.loads(proc.stdout.readline())
        assert devicelink.parse_challenge(ch["text"]) == {"ref": ch["ref"], "pub": ch["pub"]}
        payload = {"v": 1, "master": "M" * 43, "email": "a@b.c", "idx": {"room": "r", "mk": "m"}, "note": "ünï 😀"}
        proc.stdin.write(json.dumps(devicelink.seal_to_challenge(ch, payload)) + "\n")
        proc.stdin.flush()
        got = json.loads(proc.stdout.readline())
        assert got["ok"], got
        assert got["pay"]["master"] == "M" * 43 and got["pay"]["idx"] == {"room": "r", "mk": "m"}
        wrong = devicelink.seal_to_challenge({"ref": "0" * 32, "pub": ch["pub"]}, payload)  # bound to another ref
        proc.stdin.write(json.dumps({**wrong, "ref": ch["ref"]}) + "\n")
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["ok"] is False
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


def test_parse_challenge_and_read_payload_edges():
    ch = devicelink.new_link_challenge()
    assert devicelink.parse_challenge(ch.text) == {"ref": ch.ref, "pub": ch.pub}
    for bad in [None, "", "wbzlink1:", "wbzlink1:abc.def", ch.text + ".x", ch.text.upper(), "wbzlink2:" + ch.text[9:]]:
        assert devicelink.parse_challenge(bad) is None, bad
    assert devicelink.read_link_payload({"email": "x"}) is None
    assert devicelink.read_link_payload({"master": "m", "rel": {"gid": "g"}})["rel"] is None, "half a release is no release"
    assert devicelink.read_link_payload({"master": "m", "anchor": {"method": "email", "email": "e"}})["anchor"] is None
    with pytest.raises(ValueError):
        devicelink._import_pub(_js.b64u(b"\x04" + bytes(32)))


@requires_node
def test_link_payload_reader_agrees_with_js():
    cases = [None, {}, {"master": ""}, {"master": "m"}, {"master": "m", "code": 5, "email": ["x"], "rel": {"token": "t", "gid": 0},
             "idx": {"room": "r", "mk": ""}, "pipes": {"room": "p", "mk": "k"}, "anchor": {"method": "email", "email": "e", "token": "t", "exp": 0}},
             {"master": "m", "anchor": {"method": "google", "email": "g", "token": ""}}, {"master": "m", "rel": {"token": "t", "gid": "7"}}]
    out = run_node("""
      import { readLinkPayload } from '@PUBLIC@/deviceLink.js'
      OUT(INPUT.map((p) => JSON.stringify(readLinkPayload(p))))
    """, cases)
    assert [_js.stringify(devicelink.read_link_payload(c)) for c in cases] == out


@requires_node
def test_backup_keys_and_unseal_agree_with_recovery_js():
    master = bytes(range(32))
    out = run_node("""
      import { deriveKeysFromSecret, seal, unseal } from '@PUBLIC@/recovery.js'
      const loc = await deriveKeysFromSecret(new Uint8Array(INPUT.master))
      OUT({ id: loc.id, wt: loc.wt, blob: await seal(loc.key, { v: 1, indexRoom: { room: 'sp-idx-9', mk: 'idxmk9' } }),
            opened: await unseal(loc.key, INPUT.pyBlob) })
    """, {"master": list(master), "pyBlob": devicelink.seal(devicelink.derive_keys_from_secret(master)["key"], {"from": "python ✓"})})
    loc = devicelink.derive_keys_from_secret(master)
    assert (loc["id"], loc["wt"]) == (out["id"], out["wt"])
    assert devicelink.unseal(loc["key"], out["blob"]) == {"v": 1, "indexRoom": {"room": "sp-idx-9", "mk": "idxmk9"}}
    assert out["opened"] == {"from": "python ✓"}


@requires_node
def test_link_node_end_to_end_with_a_js_sealed_reply_and_the_backup_fallback(tmp_path):
    """The whole poll: /api/link answers with a reply a JS device sealed; the payload has no idx, so the index room is
    recovered from a JS-sealed backup through /api/backup/release."""
    master = bytes([9] * 32)
    ch = devicelink.new_link_challenge()
    out = run_node("""
      import { sealToChallenge, linkPayload } from '@PUBLIC@/deviceLink.js'
      import { deriveKeysFromSecret, seal } from '@PUBLIC@/recovery.js'
      const loc = await deriveKeysFromSecret(new Uint8Array(INPUT.master))
      OUT({
        reply: await sealToChallenge({ ref: INPUT.ref, pub: INPUT.pub }, linkPayload({ vault: { master: INPUT.masterB64 }, email: 'me@x', rel: { gid: 'g', token: 'REL' } })),
        blob: await seal(loc.key, { v: 1, indexRoom: { room: 'sp-idx-9', mk: 'idxmk9' } }), id: loc.id,
      })
    """, {"master": list(master), "masterB64": _js.btoa(master), "ref": ch.ref, "pub": ch.pub})
    polls = []

    async def get_json(url):
        polls.append(url)
        if len(polls) < 3:
            return {"ok": False, "reason": "unavailable"} if len(polls) == 1 else {"ok": False}
        return {"ok": True, **out["reply"]}

    async def post_json(url, body):
        return {"ok": True, "blob": out["blob"]} if body == {"token": "REL", "id": out["id"]} else {"ok": False}

    lines = []
    account = asyncio.run(link.link_node(life_ms=5000, poll_s=0.01, origins=["https://a.test"], get_json=get_json,
                                         post_json=post_json, challenge=ch, svg_path=tmp_path / "qr.svg",
                                         out=lambda *a, **k: lines.append(" ".join(map(str, a))), err=lines.append))
    assert account and account["email"] == "me@x"
    assert account["idx"] == {"room": "sp-idx-9", "mk": "idxmk9"}
    assert polls[0] == f"https://a.test/api/link?ref={ch.ref}"
    assert (tmp_path / "qr.svg").stat().st_mode & 0o777 == 0o600
    assert not any(_js.btoa(master) in ln for ln in lines), "the master never reaches the terminal"


def test_link_node_expires_and_refuses_a_reply_that_does_not_open(tmp_path):
    ch = devicelink.new_link_challenge()
    quiet = dict(origins=["https://a.test"], svg_path=tmp_path / "q.svg", out=lambda *a, **k: None, err=lambda *a: None)

    async def never(url):
        return {"ok": False}

    async def junk(url):
        return {"ok": True, "epk": ch.pub, "blob": _js.b64u(bytes(40))}

    async def nopost(url, body):
        return {}

    assert asyncio.run(link.link_node(life_ms=50, poll_s=0.01, get_json=never, post_json=nopost, challenge=ch, **quiet)) is None
    assert asyncio.run(link.link_node(life_ms=5000, poll_s=0.01, get_json=junk, post_json=nopost, challenge=ch, **quiet)) is None


def test_parse_origins():
    assert link.parse_origins("https://a.test/, https://b.test") == ["https://a.test", "https://b.test"]
    d = link.parse_origins("")
    assert "https://spaces.witbitz.chat" in d and "https://witbitz-spaces.pages.dev" in d


@requires_node
def test_the_phone_decoder_reads_the_python_qr_back_to_the_exact_challenge():
    """What matters about a QR is whether the phone can read it: encode with segno, decode with the vendored jsQR the app
    runs (spaces/test/qrRender.test.mjs does the same for the JS encoder)."""
    texts = [devicelink.new_link_challenge().text for _ in range(4)]
    out = run_node("""
      import { readFileSync } from 'node:fs'
      import vm from 'node:vm'
      import { parseChallenge } from '@PUBLIC@/deviceLink.js'
      const sandbox = { self: {} }
      vm.createContext(sandbox)
      vm.runInContext(readFileSync(new URL('@PUBLIC@/vendor/jsQR.js'), 'utf8'), sandbox)
      const jsQR = sandbox.self.jsQR
      OUT(INPUT.map((rows) => {
        const quiet = 4, scale = 4, dim = (rows.length + quiet * 2) * scale
        const data = new Uint8ClampedArray(dim * dim * 4).fill(255)
        rows.forEach((row, r) => [...row].forEach((d, c) => {
          if (d !== '1') return
          for (let y = (r + quiet) * scale; y < (r + quiet + 1) * scale; y++)
            for (let x = (c + quiet) * scale; x < (c + quiet + 1) * scale; x++) { const i = (y * dim + x) * 4; data[i] = data[i + 1] = data[i + 2] = 0 }
        }))
        const got = jsQR(data, dim, dim, { inversionAttempts: 'dontInvert' })
        return { text: got && got.data, parsed: got && parseChallenge(got.data) }
      }))
    """, [["".join("1" if d else "0" for d in row) for row in qr.qr_modules(t)] for t in texts])
    for t, got in zip(texts, out):
        assert got["text"] == t, "what the camera reads must be exactly what was drawn"
        assert got["parsed"] == devicelink.parse_challenge(t)


@requires_node
def test_qr_ansi_and_svg_output_are_byte_identical_to_rc_qr():
    """Same module matrix in → the same terminal and SVG bytes out as tools/rc-qr.mjs."""
    text = devicelink.new_link_challenge().text
    out = run_node("""
      import { qrAnsi, qrSvg } from '@TOOLS@/rc-qr.mjs'
      import { qrModules } from '@PUBLIC@/qrRender.js'
      const { size, isDark } = qrModules(INPUT)
      OUT({ ansi: qrAnsi(INPUT), svg: qrSvg(INPUT), rows: Array.from({ length: size }, (_, r) => Array.from({ length: size }, (_, c) => isDark(r, c))) })
    """, text)
    assert qr.render_ansi(out["rows"]) == out["ansi"]
    assert qr.render_svg(out["rows"]) == out["svg"]
    assert len(qr.qr_modules(text)) == len(out["rows"]), "and the same version: the smallest that fits at level M"
