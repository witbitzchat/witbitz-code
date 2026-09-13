"""The computers registry against codeComputers.js — every result compared as the exact JSON the JS side produces."""

from __future__ import annotations

import pytest
from conftest import requires_node, run_node

from witbitz_code import _js
from witbitz_code.computers import (
    live_computers,
    merge_registry,
    norm_entry,
    norm_registry,
    ok_relay,
    same_registry,
    with_computer,
    without_computer,
)

S1, S2, S3 = "A" * 43, "B" * 43, "C" * 43
R = "wss://code-relay.witbitz.chat"


def entry(**kw):
    return {"name": "desk", "relay": R, "secret": S1, "pairedAt": 100, "mod": 100, **kw}


DOCS = [
    None, 5, "x", [], {"computers": []}, {"computers": None}, {"computers": {"short": entry()}},
    {"v": 1, "computers": {
        "cmp_desk_01": entry(),
        "cmp_laptop1": entry(name="laptop", secret=S2, pairedAt=50, mod=200),
        "cmp_gone_001": {"removed": True, "mod": 300, "secret": S3},
        "cmp_badsec1": entry(secret="short"),
        "cmp_badrel1": entry(relay="https://code-relay.witbitz.chat"),
        "cmp_nomod01": entry(mod=0),
        "cmp_strmod1": entry(mod="150", pairedAt=" 12 "),
        "cmp_boolmod": entry(mod=True),
        "cmp_arrmod1": entry(mod=[7]),
        "cmp_hexmod1": entry(mod="0x10"),
        "cmp_fltmod1": entry(mod=1.5, pairedAt=None),
        "cmp_namenum": entry(name=42),
        "cmp_namearr": entry(name=["a", None, 3]),
        "cmp_nameobj": entry(name={"x": 1}),
        "cmp_nameemp": entry(name=""),
        "cmp_longnam": entry(name="n" * 79 + "😀" + "tail"),
        "cmp_relarr1": entry(relay=[R]),
        "12345678": entry(),
        "__proto__": entry(),
        "constructor": entry(name="ctor"),
        "toString": {"removed": True, "mod": 9},
        "hasOwnProperty": entry(mod=1e3),
        "bad id with spaces": entry(),
        "cmp_removed_str": {"removed": "false", "mod": 5},
        "cmp_removed_zero": {"removed": 0, "mod": 5, "secret": S1, "relay": R},
    }},
]

RELAYS = [
    R, "WSS://Code-Relay.Witbitz.Chat/", "wss:code-relay.witbitz.chat", "wss:///code-relay.witbitz.chat", "wss://",
    "ws://127.0.0.1:8787", "ws://localhost", "ws://LOCALHOST:1/x", "ws://127.1", "ws://0x7f.0.0.1", "ws://2130706433",
    "ws://example.com", "ws://127.0.0.2", "ws://[::1]:8787", "wss://[::1]", "wss://[zz]", "ws://localhost.",
    "http://localhost", "wss://exa mple.com", "wss://host:99999", "wss://host:", "wss://user:pw@host", "wss://h:1:2",
    " wss://host ", "wss://ho\tst", "wss://%68ost", "ws://%6cocalhost", "wss://a..b", "wss://256.0.0.1.2", "wss://1.2.3.256",
    "wss://09.1.1.1", "wss://host\\path", "javascript:alert(1)", "", None, 5, ["wss://x"], {"a": 1},
]


def test_norm_entry_and_merge_rules():
    assert norm_entry({"mod": 0, "secret": S1, "relay": R}) is None
    for not_a_number in (True, "150", "0x10", [7], None, float("inf"), -1):
        assert norm_entry(entry(mod=not_a_number)) is None, not_a_number
    assert norm_entry(entry(pairedAt="12"))["pairedAt"] == 100, "a pairedAt that is not a real number falls back to mod"
    assert norm_entry(entry(name="n" * 79 + "😀tail"))["name"] == "n" * 79 + "😀", "cut by character, never mid-emoji"
    assert "constructor" in norm_registry({"computers": {"constructor": entry()}})["computers"], "built-in names are ids too"
    assert norm_entry({"removed": True, "mod": 9, "secret": S1}) == {"removed": True, "mod": 9}
    assert norm_entry(entry(name=None))["name"] == "computer"
    a = {"computers": {"cmp_desk_01": entry(mod=10)}}
    b = {"computers": {"cmp_desk_01": {"removed": True, "mod": 10}}}
    assert merge_registry(a, b)["computers"]["cmp_desk_01"]["removed"] is True, "on a tie the removal wins"
    assert merge_registry(b, a)["computers"]["cmp_desk_01"]["removed"] is True, "whichever side it is on"
    c = {"computers": {"cmp_desk_01": entry(mod=11)}}
    assert "removed" not in merge_registry(b, c)["computers"]["cmp_desk_01"], "a newer pairing beats an older tombstone"


def test_with_and_without_computer():
    reg = with_computer(None, "cmp_desk_01", {"name": "desk", "relay": R, "secret": S1}, 1000)
    assert reg["computers"]["cmp_desk_01"] == {"name": "desk", "relay": R, "secret": S1, "pairedAt": 1000, "mod": 1000}
    again = with_computer(reg, "cmp_desk_01", {"name": "desk2", "relay": R, "secret": S2}, 500)
    assert again["computers"]["cmp_desk_01"]["mod"] == 1001 and again["computers"]["cmp_desk_01"]["pairedAt"] == 1000
    gone = without_computer(again, "cmp_desk_01", 900)
    assert gone["computers"]["cmp_desk_01"] == {"removed": True, "mod": 1002}
    back = with_computer(gone, "cmp_desk_01", {"name": "desk", "relay": R, "secret": S3}, 2000)
    assert back["computers"]["cmp_desk_01"]["pairedAt"] == 2000, "re-pairing after a removal starts a new pairedAt"
    assert same_registry(back, {"v": 1, "computers": dict(back["computers"])})


def _registry_ops():
    """(label, JS expression over INPUT, Python thunk) — the same operation on both sides."""
    base = DOCS[7]
    return [
        *[(f"norm{i}", f"normRegistry(INPUT.docs[{i}])", lambda i=i: norm_registry(DOCS[i])) for i in range(len(DOCS))],
        *[(f"live{i}", f"liveComputers(INPUT.docs[{i}])", lambda i=i: live_computers(DOCS[i])) for i in range(len(DOCS))],
        ("merge", "mergeRegistry(INPUT.docs[7], INPUT.other)", lambda: merge_registry(base, OTHER)),
        ("merge-rev", "mergeRegistry(INPUT.other, INPUT.docs[7])", lambda: merge_registry(OTHER, base)),
        ("with-new", "withComputer(INPUT.docs[7], 'cmp_new_0001', { name: 'new', relay: INPUT.R, secret: INPUT.S3 }, 250)",
         lambda: with_computer(base, "cmp_new_0001", {"name": "new", "relay": R, "secret": S3}, 250)),
        ("with-existing", "withComputer(INPUT.docs[7], 'cmp_laptop1', { name: 'lap2', relay: 'ws://localhost:1', secret: INPUT.S1 }, 10)",
         lambda: with_computer(base, "cmp_laptop1", {"name": "lap2", "relay": "ws://localhost:1", "secret": S1}, 10)),
        ("with-gone", "withComputer(INPUT.docs[7], 'cmp_gone_001', { name: 'back', relay: INPUT.R, secret: INPUT.S2 }, 300)",
         lambda: with_computer(base, "cmp_gone_001", {"name": "back", "relay": R, "secret": S2}, 300)),
        ("with-noname", "withComputer(null, 'cmp_noname1', { relay: INPUT.R, secret: INPUT.S2 }, 7)",
         lambda: with_computer(None, "cmp_noname1", {"relay": R, "secret": S2}, 7)),
        ("with-invalid", "withComputer(INPUT.docs[7], 'cmp_invalid', { name: 'x', relay: 'ws://evil.example', secret: INPUT.S2 }, 7)",
         lambda: with_computer(base, "cmp_invalid", {"name": "x", "relay": "ws://evil.example", "secret": S2}, 7)),
        ("without", "withoutComputer(INPUT.docs[7], 'cmp_desk_01', 50)", lambda: without_computer(base, "cmp_desk_01", 50)),
        ("without-absent", "withoutComputer(INPUT.docs[7], 'cmp_absent1', 50)", lambda: without_computer(base, "cmp_absent1", 50)),
        ("with-builtin-id", "withComputer(INPUT.docs[7], 'constructor', { name: 'c2', relay: INPUT.R, secret: INPUT.S3 }, 250)",
         lambda: with_computer(base, "constructor", {"name": "c2", "relay": R, "secret": S3}, 250)),
        ("with-proto-id", "withComputer(null, '__proto__', { name: 'p', relay: INPUT.R, secret: INPUT.S3 }, 250)",
         lambda: with_computer(None, "__proto__", {"name": "p", "relay": R, "secret": S3}, 250)),
        ("without-builtin-id", "withoutComputer(INPUT.docs[7], 'toString', 50)", lambda: without_computer(base, "toString", 50)),
        ("merge-builtin", "mergeRegistry(null, { computers: { valueOf: { name: 'v', relay: INPUT.R, secret: INPUT.S1, mod: 5 } } })",
         lambda: merge_registry(None, {"computers": {"valueOf": {"name": "v", "relay": R, "secret": S1, "mod": 5}}})),
        ("same", "sameRegistry(INPUT.docs[7], mergeRegistry(INPUT.docs[7], {}))", lambda: same_registry(base, merge_registry(base, {}))),
        ("same-no", "sameRegistry(INPUT.docs[7], INPUT.other)", lambda: same_registry(base, OTHER)),
    ]


OTHER = {"computers": {
    "cmp_desk_01": {"removed": True, "mod": 100},
    "cmp_laptop1": entry(name="older", mod=199),
    "cmp_gone_001": entry(mod=301, name="revived"),
    "cmp_third01": entry(name="third", secret=S3, pairedAt=50, mod=50),
}}


@requires_node
def test_registry_results_are_byte_identical_to_js():
    ops = _registry_ops()
    script = """
      import { normRegistry, mergeRegistry, withComputer, withoutComputer, liveComputers, sameRegistry } from '@PUBLIC@/codeComputers.js'
      OUT([%s].map((f) => JSON.stringify(f())))
    """ % ",\n".join(f"() => {expr}" for _, expr, _ in ops)
    out = run_node(script, {"docs": DOCS, "other": OTHER, "R": R, "S1": S1, "S2": S2, "S3": S3})
    for (label, _, thunk), js in zip(ops, out):
        assert _js.stringify(thunk()) == js, label


@requires_node
def test_ok_relay_agrees_with_the_browser_url_parser():
    out = run_node("""
      import { normEntry } from '@PUBLIC@/codeComputers.js'
      OUT(INPUT.relays.map((relay) => !!normEntry({ mod: 1, secret: INPUT.S, relay })))
    """, {"relays": RELAYS, "S": S1})
    mismatches = [(r, js) for r, js in zip(RELAYS, out) if ok_relay(r) != js]
    assert not mismatches, mismatches


@pytest.mark.parametrize("u,ok", [(R, True), ("ws://127.0.0.1:8787", True), ("ws://127.1", True), ("ws://example.com", False),
                                  ("http://localhost", False), ("wss://", False)])
def test_ok_relay_units(u, ok):
    assert ok_relay(u) is ok
