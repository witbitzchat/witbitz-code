"""The OpenCode config the Code section's approvals depend on — twin of tools/code-opencode-policy.mjs.

Read that file's header for the two findings (OpenCode 1.18.30): a subagent does NOT inherit its parent session's `ask`
rules, so the built-in subagents are told to ask here, per agent and only for what each one ALLOWS (never loosening a
deny); and a denied tool call ends the turn unless `experimental.continue_loop_on_deny` is set. tests/test_policy.py
holds this object identical to the JS one.
"""
from __future__ import annotations

import copy
import json
from typing import Any

SUBAGENT_ASK: dict[str, dict[str, str]] = {
    "explore": {"bash": "ask", "webfetch": "ask", "websearch": "ask"},
    "general": {"bash": "ask", "edit": "ask", "webfetch": "ask", "websearch": "ask", "task": "ask", "skill": "ask"},
}

SUBAGENT_GATED: tuple[str, ...] = ("bash", "edit", "webfetch", "websearch")


def policy_config() -> dict[str, Any]:
    """The config object, fresh each call."""
    return {
        "experimental": {"continue_loop_on_deny": True},
        "agent": {name: {"permission": dict(perms)} for name, perms in SUBAGENT_ASK.items()},
    }


def merge_config(a: dict, b: dict | None) -> dict:
    """Deep-merge plain dicts (b wins), without mutating either."""
    out = copy.deepcopy(a)
    for k, v in (b or {}).items():
        out[k] = merge_config(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else copy.deepcopy(v)
    return out


def config_content(existing: str | None = None) -> str:
    """OPENCODE_CONFIG_CONTENT for the OpenCode `serve` starts: the policy, under anything the environment already set."""
    base: dict = {}
    if existing:
        try:
            parsed = json.loads(existing)
            base = parsed if isinstance(parsed, dict) else {}
        except ValueError:
            base = {}
    return json.dumps(merge_config(base, policy_config()))
