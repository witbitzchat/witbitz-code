// code-opencode-policy: the OpenCode config the Code section depends on for its approvals to mean anything.
//
// Merged into every OpenCode the Code section drives: the owner's global config (tools/opencode-config.mjs) and the
// server `witbitz-code serve` starts (OPENCODE_CONFIG_CONTENT). The Python twin carries the same object
// (packages/witbitz-code-py/src/witbitz_code/policy.py) and a parity test holds them together.
//
// Two findings, both read out of OpenCode 1.18.30's own code (2026-09-14) after a session's subagents ran 60 shell
// commands that nobody approved and its turn stopped dead:
//
//  1. ★ A SUBAGENT DOES NOT INHERIT ITS PARENT'S `ask` RULES. The task tool builds the child session's ruleset from the
//     parent's `external_directory` and `deny` rules only (`lt()` in the task tool). The session ruleset the Code section
//     sets (bash/edit/webfetch… → ask) therefore stops at the parent, and the child runs on its AGENT's defaults — for
//     `explore` that is bash/webfetch/websearch ALLOW, for `general` everything ALLOW. Approving "start an explore agent"
//     approved every command it would then run. The fix is per agent, in config: `agent.<name>.permission` is merged
//     LAST into that agent's rules, so it wins. It must stay PER AGENT and only turn what the agent ALLOWS into ask — a
//     blanket `edit: ask` would LOOSEN explore's built-in edit deny (its rules start with `"*": deny`).
//     A subagent this list does not name (a project's own .opencode/agent) is not covered: Auto checks the agent's actual
//     rules before it lets one start (tools/code-auto-runner.mjs `subagentAsks`).
//
//  2. ★ A DENIED TOOL CALL ENDS THE TURN. The processor sets `blocked = shouldBreak` on a rejection, and shouldBreak is
//     `experimental.continue_loop_on_deny !== true`. So a refusal — Auto's, or one that OpenCode CASCADES onto every
//     other pending ask in the session — left the tools that did run with results nobody read. With the flag on, the
//     model is told why and carries on; a person's own Deny tells it to stop and ask (spaces/public/opencodeApp.js).

/** What each built-in subagent allows by default that the Code section's sessions ask for. */
export const SUBAGENT_ASK = Object.freeze({
  explore: Object.freeze({ bash: 'ask', webfetch: 'ask', websearch: 'ask' }),
  general: Object.freeze({ bash: 'ask', edit: 'ask', webfetch: 'ask', websearch: 'ask', task: 'ask', skill: 'ask' }),
})

/** The permissions a subagent must ASK for (not allow) before Auto treats starting it as safe. */
export const SUBAGENT_GATED = Object.freeze(['bash', 'edit', 'webfetch', 'websearch'])

/** The config object, fresh each call (callers merge into it). */
export function policyConfig() {
  return {
    experimental: { continue_loop_on_deny: true },
    agent: Object.fromEntries(Object.entries(SUBAGENT_ASK).map(([name, perms]) => [name, { permission: { ...perms } }])),
  }
}

/** Deep-merge plain objects (b wins), for putting the policy together with another config fragment. */
export function mergeConfig(a, b) {
  const out = { ...a }
  for (const [k, v] of Object.entries(b || {})) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && out[k] && typeof out[k] === 'object' && !Array.isArray(out[k]) ? mergeConfig(out[k], v) : v
  }
  return out
}
