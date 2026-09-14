"""The frame codec against codeRelay.js: derivation vectors, frames both ways, replay/tamper, chunking, allowlists."""

from __future__ import annotations

import hashlib
import json
import random
import re

import pytest
from conftest import PUBLIC, requires_node, run_node

from witbitz_code import _js
from witbitz_code.relay import (
    CHUNK,
    Opener,
    Reassembler,
    Sealer,
    allowed_event_path,
    allowed_request,
    chunk_message,
    derive_relay,
    derive_relay_bytes,
    new_relay_secret,
    peers_of,
    project_response,
    unb64u,
)

PINNED = {
    "secret": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "channel": "BKIqulmwCTX1BBrhuxWGIuqXw-lNfZiLKecQX_b351I",
    "c2s": "a85ab9bf21f9d47f0c6b5698e721cb29da068336e72b3e6f8dac7ec97b5994b7",
    "s2c": "269f9541f33e3bd46c61a46d9462070de56f7392ebfa76dcb1aa2c954c6ff31d",
}


def shared_vectors() -> dict:
    """The VECTORS block of spaces/test/codeRelay.test.mjs, read from the file so the two suites pin the same values."""
    path = PUBLIC.parent / "test" / "codeRelay.test.mjs"
    if not path.exists():
        return PINNED
    block = re.search(r"export const VECTORS = \{(.*?)\n\}", path.read_text(), re.S).group(1)
    return dict(re.findall(r"(\w+): '([^']+)'", block))


# ── 1. derivation ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_derivation_matches_the_shared_vectors():
    v = shared_vectors()
    assert v == PINNED, "the JS suite changed its vectors — update PINNED only if the change is intended"
    channel, c2s, s2c = derive_relay_bytes(v["secret"])
    assert channel == v["channel"] and len(channel) == 43
    assert c2s.hex() == v["c2s"]
    assert s2c.hex() == v["s2c"]


@requires_node
def test_js_derives_the_same_channel_and_keys():
    out = run_node("""
      import { deriveRelay, makeSealer } from '@PUBLIC@/codeRelay.js'
      const r = await deriveRelay(INPUT.secret)
      const frames = {}
      for (const dir of ['c2s', 's2c']) frames[dir] = await makeSealer(r[dir]).seal({ t: 'probe', dir })
      OUT({ channel: r.channel, frames })
    """, {"secret": PINNED["secret"]})
    assert out["channel"] == PINNED["channel"]
    for d in ("c2s", "s2c"):  # the JS keys are non-extractable; prove them by opening with the raw vector key
        assert Opener(bytes.fromhex(PINNED[d])).open(out["frames"][d]) == {"t": "probe", "dir": d}


def test_a_secret_that_is_not_32_bytes_is_refused():
    with pytest.raises(ValueError, match="32 bytes"):
        derive_relay(_js.b64u(bytes(31)))
    a, b = new_relay_secret(), new_relay_secret()
    assert len(unb64u(a)) == 32 and a != b


# ── 2. frames ─────────────────────────────────────────────────────────────────────────────────────────────────────────
MESSAGES = [
    {"t": "req", "id": "x", "m": "GET", "p": "/agent"},
    {"t": "res", "id": "x", "st": 200, "b": "ünïcødé 😀   \"quoted\" \\ \x01"},
    {"t": "evts", "p": "/event?directory=%2Fhome%2Fu", "b": json.dumps(["{\"type\":\"a\"}"])},
    {"n": 1.5, "big": 12345678901, "neg": -0.000001, "nested": {"10": 1, "a": [None, True, False]}},
]


@requires_node
def test_frames_sealed_in_js_open_in_python_both_directions():
    secret = new_relay_secret()
    out = run_node("""
      import { deriveRelay, makeSealer } from '@PUBLIC@/codeRelay.js'
      const r = await deriveRelay(INPUT.secret)
      const c2s = makeSealer(r.c2s), s2c = makeSealer(r.s2c)
      OUT({
        c2s: await Promise.all(INPUT.msgs.map((m) => c2s.seal(m))),  // a concurrent burst, as the page fires at boot
        s2c: [await s2c.seal(INPUT.msgs[0]), await s2c.seal(INPUT.msgs[1])],
      })
    """, {"secret": secret, "msgs": MESSAGES})
    keys = derive_relay(secret)
    opener = Opener(keys.c2s)
    assert [opener.open(f) for f in out["c2s"]] == MESSAGES
    assert [Opener(keys.s2c).open(f) for f in out["s2c"]] == MESSAGES[:2]
    assert Opener(keys.s2c).open(out["c2s"][0]) is None, "a frame reflected to its sender does not open"
    assert Opener(keys.c2s).open(out["s2c"][0]) is None
    assert opener.open(out["c2s"][0]) is None, "a replay is dropped"


@requires_node
def test_frames_sealed_in_python_open_in_js_both_directions():
    secret = new_relay_secret()
    keys = derive_relay(secret)
    c2s, s2c = Sealer(keys.c2s), Sealer(keys.s2c)
    frames = {"c2s": [c2s.seal(m) for m in MESSAGES], "s2c": [s2c.seal(m) for m in MESSAGES]}
    out = run_node("""
      import { deriveRelay, makeOpener } from '@PUBLIC@/codeRelay.js'
      const r = await deriveRelay(INPUT.secret)
      const open = async (key, frames) => { const o = makeOpener(key); const got = []; for (const f of frames) got.push(await o.open(f)); return got }
      const c2s = makeOpener(r.c2s)
      const first = await c2s.open(INPUT.frames.c2s[1])
      OUT({
        c2s: await open(r.c2s, INPUT.frames.c2s),
        s2c: await open(r.s2c, INPUT.frames.s2c),
        wrongDirection: await open(r.s2c, INPUT.frames.c2s),
        replayOlder: [first, await c2s.open(INPUT.frames.c2s[0]), await c2s.open(INPUT.frames.c2s[1])],
      })
    """, {"secret": secret, "frames": frames})
    assert out["c2s"] == MESSAGES
    assert out["s2c"] == MESSAGES
    assert out["wrongDirection"] == [None] * len(MESSAGES)
    assert out["replayOlder"] == [MESSAGES[1], None, None], "older and repeated sequence numbers are dropped in JS too"


def test_tamper_replay_and_junk_open_to_none():
    keys = derive_relay(PINNED["secret"])
    sealer = Sealer(keys.c2s)
    frame = sealer.seal({"t": "req", "id": "x", "m": "GET", "p": "/agent"})
    assert "/agent" not in frame, "nothing of the plaintext is visible on the wire"
    assert Opener(keys.c2s).open(frame) == {"t": "req", "id": "x", "m": "GET", "p": "/agent"}
    f = json.loads(frame)
    assert Opener(keys.c2s).open(json.dumps({**f, "q": f["q"] + 1})) is None, "the sequence number is authenticated"
    assert Opener(keys.c2s).open(json.dumps({**f, "s": _js.b64u(bytes(12))})) is None, "so is the sender id"
    c = bytearray(unb64u(f["c"]))
    c[0] ^= 1
    assert Opener(keys.c2s).open(json.dumps({**f, "c": _js.b64u(bytes(c))})) is None, "and the ciphertext"
    for junk in ["", "not json", '{"t":"peers","n":2}', '{"v":2}', None, "[1]", '{"v":true,"s":"a","q":1,"n":"","c":""}']:
        assert Opener(keys.c2s).open(junk) is None
    # JSON.parse("1.0") === 1 in JS, so a header written with 1.0 / 42.0 is the same header there — and here.
    assert Opener(keys.c2s).open(json.dumps({**f, "v": 1.0, "q": float(f["q"])})) is not None


def test_replay_window_per_sender_and_lru():
    keys = derive_relay(PINNED["secret"])
    one, two = Sealer(keys.c2s), Sealer(keys.c2s)
    f1, f2, g1 = one.seal({"n": 1}), one.seal({"n": 2}), two.seal({"n": "g"})
    opener = Opener(keys.c2s)
    assert opener.open(f2) == {"n": 2}
    assert opener.open(f2) is None
    assert opener.open(f1) is None, "an older frame after a newer one"
    assert opener.open(g1) == {"n": "g"}, "a second socket has its own counter"
    small = Opener(keys.c2s, max_senders=2)
    s = [Sealer(keys.c2s) for _ in range(3)]
    firsts = [x.seal({"i": i}) for i, x in enumerate(s)]
    seconds = [x.seal({"i": i}) for i, x in enumerate(s)]
    for fr in seconds:
        small.open(fr)
    assert small.open(firsts[0]) is not None, "the oldest sender was evicted, so its window restarted"
    assert small.open(firsts[2]) is None


@requires_node
def test_the_opener_reports_the_sender_it_forgets_for_js_sealed_frames():
    out = run_node("""
      import { deriveRelay, makeSealer } from '@PUBLIC@/codeRelay.js'
      const { c2s } = await deriveRelay(INPUT)
      const s = [makeSealer(c2s), makeSealer(c2s), makeSealer(c2s)]
      OUT({ senders: s.map((x) => x.sender), frames: await Promise.all(s.map((x, i) => x.seal({ n: i }))) })
    """, PINNED["secret"])
    evicted = []
    opener = Opener(derive_relay(PINNED["secret"]).c2s, max_senders=2, on_evict=evicted.append)
    assert [opener.open(f) for f in out["frames"][:2]] == [{"n": 0}, {"n": 1}] and evicted == []
    assert opener.open(out["frames"][2]) == {"n": 2}
    assert evicted == [out["senders"][0]], "the oldest sender left the window — and said so"
    assert opener.open(out["frames"][0]) == {"n": 0}, "which is exactly why: its old frame opens again"
    assert evicted == [out["senders"][0], out["senders"][1]]
    broken = Opener(derive_relay(PINNED["secret"]).c2s, max_senders=1, on_evict=lambda s: 1 / 0)
    assert broken.open(out["frames"][0]) and broken.open(out["frames"][1]) == {"n": 1}, "a failing callback does not lose the frame"


def test_peers_of_reads_only_the_relay_count():
    assert peers_of('{"t":"peers","n":3}') == 3
    assert peers_of('{"t":"peers","n":3.0}') == 3
    assert peers_of('{"t":"peers","n":"3"}') is None
    assert peers_of('{"v":1,"s":"x"}') is None
    assert peers_of(None) is None


# ── 3. chunking ───────────────────────────────────────────────────────────────────────────────────────────────────────
@requires_node
def test_chunk_boundaries_are_identical_to_js_even_through_surrogate_pairs():
    cases = [("ab😀cd😀😀e" * 7, 5), ("😀" * 11, 3), ("x" * 20, 20), ("x" * 21, 20), ("ü" * 9, 4)]
    msgs = [{"t": "res", "id": f"r{i}", "st": 200, "b": b} for i, (b, _) in enumerate(cases)]
    out = run_node("""
      import { chunkMessage } from '@PUBLIC@/codeRelay.js'
      OUT(INPUT.map(([m, size]) => JSON.stringify(chunkMessage(m, size))))
    """, [[m, size] for m, (_, size) in zip(msgs, cases)])
    for m, (_, size), js in zip(msgs, cases, out):
        assert _js.stringify(chunk_message(m, size)) == js


def _sha(s: str) -> str:
    return hashlib.sha256(_js.utf8(s)).hexdigest()


@requires_node
def test_a_js_chunked_message_reassembles_in_python():
    body = ("y" * (CHUNK - 1) + "😀") * 3 + "tail"
    secret = new_relay_secret()
    out = run_node("""
      import { deriveRelay, makeSealer, chunkMessage } from '@PUBLIC@/codeRelay.js'
      const r = await deriveRelay(INPUT.secret)
      const s = makeSealer(r.s2c)
      const frames = []
      for (const part of chunkMessage({ t: 'res', id: 'r1', st: 200, b: INPUT.body })) frames.push(await s.seal(part))
      OUT(frames)
    """, {"secret": secret, "body": body})
    assert len(out) == 4
    opener, reasm = Opener(derive_relay(secret).s2c), Reassembler()
    parts = [opener.open(f) for f in out]  # opened in arrival order (the replay window requires it)…
    order = [2, 0, 0, 3, 1]  # …and reassembled in any order, duplicates harmless
    results = [reasm.push(parts[i]) for i in order]
    assert results[:4] == [None] * 4
    assert results[4]["b"] == body and results[4] == {"t": "res", "id": "r1", "st": 200, "b": body}


@requires_node
def test_a_python_chunked_message_reassembles_in_js():
    body = "é" * (CHUNK * 2) + "😀" * 1000
    secret = new_relay_secret()
    sealer = Sealer(derive_relay(secret).c2s)
    frames = [sealer.seal(p) for p in chunk_message({"t": "req", "id": "q1", "m": "POST", "p": "/session", "b": body})]
    assert len(frames) == 3
    out = run_node("""
      import { deriveRelay, makeOpener, makeReassembler } from '@PUBLIC@/codeRelay.js'
      const r = await deriveRelay(INPUT.secret)
      const o = makeOpener(r.c2s), re = makeReassembler()
      let whole = null
      for (const f of INPUT.frames) whole = re.push(await o.open(f)) || whole
      const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('')
      OUT({ len: whole.b.length, sha: hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(whole.b))), rest: { ...whole, b: undefined } })
    """, {"secret": secret, "frames": frames})
    assert out["len"] == _js.utf16_len(body)
    assert out["sha"] == _sha(body)
    assert out["rest"] == {"t": "req", "id": "q1", "m": "POST", "p": "/session"}


def test_reassembly_caps_and_junk():
    r = Reassembler(max_total=10)
    assert r.push({"t": "res", "id": "a", "b": "123456", "part": 0, "of": 2}) is None
    assert r.push({"t": "res", "id": "a", "b": "789012", "part": 1, "of": 2}) is None
    r = Reassembler()
    assert r.push({"t": "evts", "d": []}) == {"t": "evts", "d": []}, "an unchunked message passes straight through"
    assert r.push({"t": "res", "id": "z", "b": "a", "part": 5, "of": 2}) is None
    assert r.push({"t": "res", "id": "z", "b": "a", "part": 0, "of": 10**12}) is None
    assert r.push({"t": "res", "id": "z", "b": "a", "part": 0, "of": None}) is None
    now = [0.0]
    r = Reassembler(timeout_ms=1000, clock=lambda: now[0])
    assert r.push({"t": "res", "id": "t", "b": "a", "part": 0, "of": 2}) is None
    now[0] = 5000
    assert r.push({"t": "res", "id": "t", "b": "b", "part": 1, "of": 2}) is None, "a stale half was dropped"
    assert chunk_message({"t": "res", "id": "s", "b": "small"}) == [{"t": "res", "id": "s", "b": "small"}]


# ── the allowlist ─────────────────────────────────────────────────────────────────────────────────────────────────────
YES = [
    ["GET", "/experimental/session?archived=true"], ["GET", "/agent"], ["GET", "/api/model"], ["GET", "/config"], ["GET", "/config/providers"],
    ["POST", "/session"], ["GET", "/session/ses_abc123/message?directory=%2Fhome%2Fu"], ["POST", "/session/ses_abc/message"],
    ["POST", "/session/ses_abc/abort"], ["POST", "/session/ses_abc/permissions/per_1"], ["POST", "/permission/per_1/reply"], ["PATCH", "/session/ses_abc"],
    ["DELETE", "/session/ses_abc?directory=%2Fx"], ["get", "/agent"], ["GET", "/session/ses.with.dots_1/message"],
    # the New-session folder picker: the computer's home, and a folder listing (names only)
    ["GET", "/path"], ["GET", "/file?directory=%2Fhome%2Fu&path=witbitz"],
    # the agent's question tool: pending questions, and the answer (or the dismissal)
    ["GET", "/session/ses_abc/todo?directory=%2Fx"],  # the live todo list
    ["POST", "/session/ses_abc/revert"], ["POST", "/session/ses_abc/unrevert"], ["POST", "/session/ses_abc/summarize"],  # /undo /redo /compact
    ["GET", "/session/status?directory=%2Fx"],  # which sessions are running, for the list
    ["GET", "/command?directory=%2Fx"],  # the "/" menu reads commands; running one is an ordinary message
    ["GET", "/question?directory=%2Fx"], ["POST", "/question/que_09acc14a40015iMUb0LeM04Edd/reply"], ["POST", "/question/que_1/reject"],
]
NO = [
    ["GET", "/event"], ["POST", "/session/ses_abc/shell"], ["POST", "/session/ses_abc/command"], ["GET", "/file/content?path=%2Fetc%2Fpasswd"],
    ["POST", "/file"], ["GET", "/file/status"], ["GET", "/path/x"],
    ["POST", "/session/ses_abc/todo"], ["GET", "/session/./todo"], ["GET", "/session/ses_abc/revert"], ["POST", "/session/ses_abc/revert/x"], ["GET", "/session/ses_abc/unrevert"], ["POST", "/session/ses_abc/summarize/x"], ["POST", "/session/status"], ["GET", "/session/status/x"], ["POST", "/session/ses_abc/share"],
    ["POST", "/session/ses_abc/command"], ["GET", "/command/review"],  # the command route runs !`…` from its arguments
    ["POST", "/question"], ["GET", "/question/que_1/reply"], ["POST", "/question/que_1"], ["POST", "/question/./reply"], ["POST", "/question/que_1/reply/x"],
    ["PUT", "/session/ses_abc"], ["GET", "/session/../config"], ["GET", "//agent"], ["GET", "agent"], ["DELETE", "/session"],
    ["POST", "/session/ses_abc/permissions/per_1/extra"], ["GET", "/permission"], ["POST", "/permission"], ["GET", "/permission/per_1/reply"], ["POST", "/permission/per_1/reply/x"], ["GET", "/agent#x"], ["GET", "/agent\n"], ["GET", None], [None, "/agent"],
    ["GET", "/session/" + "a" * 129 + "/message"],
    # a segment may contain dots but never START with one: fetch/httpx collapse '.' and '..' onto an unlisted route
    ["POST", "/session/./message"], ["DELETE", "/session/."], ["GET", "/session/../message"], ["PATCH", "/session/.."],
    ["POST", "/session/ses_1/permissions/."], ["POST", "/permission/./reply"], ["GET", "/session/.hidden/message"],
]
EVENT_PATHS = ["/event", "/event?directory=%2Fhome%2Fu", "/event?directory=x&other=1", "/session", "/event?directory=a\n",
               "/event?directory=", "/event#", None, "/event?dir=x"]


def test_the_allowlist_admits_exactly_the_calls_the_code_section_makes():
    for m, p in YES:
        assert allowed_request(m, p), f"{m} {p}"
    for m, p in NO:
        assert not allowed_request(m, p), f"{m} {p}"
    assert allowed_event_path("/event") and allowed_event_path("/event?directory=%2Fhome%2Fu")
    assert not allowed_event_path("/event?directory=x&other=1") and not allowed_event_path("/session")


@requires_node
def test_the_allowlists_agree_with_js_on_every_case():
    rng = random.Random(7)
    fuzz = [[rng.choice(["GET", "POST", "PATCH", "DELETE", "PUT", "post"]),
             "/" + "/".join(rng.choice(["session", "ses_1", "message", "abort", "..", "", "a.b", ".", ".x", "x.", "permissions", "p?x=1", "agent"])
                            for _ in range(rng.randint(1, 5)))] for _ in range(300)]
    cases = YES + NO + fuzz
    out = run_node("""
      import { allowedRequest, allowedEventPath } from '@PUBLIC@/codeRelay.js'
      OUT({ req: INPUT.cases.map(([m, p]) => allowedRequest(m, p)), ev: INPUT.events.map((p) => allowedEventPath(p)) })
    """, {"cases": cases, "events": EVENT_PATHS})
    assert out["req"] == [allowed_request(m, p) for m, p in cases]
    assert out["ev"] == [allowed_event_path(p) for p in EVENT_PATHS]


@requires_node
def test_config_answers_are_projected_exactly_like_js_and_no_secret_survives():
    """relay.project_response == codeRelay.js projectResponse on the fixtures that plant a credential everywhere."""
    cases = run_node("""
      import { LEAKY_PROVIDERS, LEAKY_CONFIG } from '@PUBLIC@/../test/leakyOpenCode.mjs'
      import { projectResponse } from '@PUBLIC@/codeRelay.js'
      const inputs = [
        ['GET', '/config/providers?directory=%2Fhome%2Fu', 200, JSON.stringify(LEAKY_PROVIDERS)],
        ['GET', '/config', 200, JSON.stringify(LEAKY_CONFIG)],
        ['GET', '/config/providers', 500, 'boom SECRET'],
        ['GET', '/config', 200, 'not json SECRET'],
        ['GET', '/config', 200, '[1]'],
        ['GET', '/agent', 200, '[{"name":"build"}]'],
      ]
      OUT(inputs.map(([m, p, st, b]) => ({ in: [m, p, st, b], out: projectResponse(m, p, st, b) })))
    """)
    for c in cases:
        m, p, st, b = c["in"]
        py_st, py_b = project_response(m, p, st, b)
        assert (py_st, py_b) == (c["out"]["st"], c["out"]["b"]), p
        if p.startswith("/config"):
            assert "SECRET" not in py_b
