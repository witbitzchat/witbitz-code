"""policy.py — the OpenCode config the approvals depend on, held identical to tools/code-opencode-policy.mjs."""
from __future__ import annotations

import json

from conftest import requires_node, run_node
from witbitz_code import policy


def test_a_refusal_does_not_end_the_turn():
    assert policy.policy_config()["experimental"]["continue_loop_on_deny"] is True


def test_explore_never_has_a_deny_loosened():
    assert policy.policy_config()["agent"]["explore"]["permission"] == {"bash": "ask", "webfetch": "ask", "websearch": "ask"}
    for loosened in ("edit", "task", "skill", "*"):
        assert loosened not in policy.SUBAGENT_ASK["explore"]


def test_config_content_keeps_what_the_environment_set_and_policy_wins_on_conflict():
    env = json.dumps({"provider": {"x": {"name": "X"}}, "agent": {"explore": {"permission": {"bash": "allow"}}}})
    out = json.loads(policy.config_content(env))
    assert out["provider"] == {"x": {"name": "X"}}
    assert out["agent"]["explore"]["permission"]["bash"] == "ask"
    assert json.loads(policy.config_content("not json")) == policy.policy_config()
    assert json.loads(policy.config_content(None)) == policy.policy_config()


def test_each_call_is_fresh():
    a = policy.policy_config()
    a["agent"]["explore"]["permission"]["bash"] = "allow"
    assert policy.policy_config()["agent"]["explore"]["permission"]["bash"] == "ask"


@requires_node
def test_parity_with_the_js_policy():
    js = run_node("""
      const m = await import('@TOOLS@/code-opencode-policy.mjs')
      OUT({ config: m.policyConfig(), gated: m.SUBAGENT_GATED })
    """)
    assert js["config"] == policy.policy_config()
    assert js["gated"] == list(policy.SUBAGENT_GATED)
