// code-opencode-policy.mjs — the OpenCode config the Code section's approvals depend on. The unit half pins the object;
// the live half (skipped without `opencode` on PATH) asks a REAL OpenCode, started with the policy, what each agent now
// resolves — the check that caught finding 1, and the one that will catch an OpenCode release that changes the merge.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:net'
import { policyConfig, mergeConfig, SUBAGENT_ASK, SUBAGENT_GATED } from './code-opencode-policy.mjs'
import { buildConfig } from './opencode-config.mjs'

test('a refused call does not end the turn', () => {
  assert.equal(policyConfig().experimental.continue_loop_on_deny, true)
})

test('explore only has what it ALLOWS turned into ask — never its denies loosened', () => {
  // explore's built-in rules start with "*": deny and then allow grep/glob/list/bash/webfetch/websearch/read. An
  // edit/task/skill rule here would merge LAST and turn those denies into asks.
  assert.deepEqual(policyConfig().agent.explore.permission, { bash: 'ask', webfetch: 'ask', websearch: 'ask' })
  for (const loosened of ['edit', 'task', 'skill', '*']) assert.ok(!(loosened in SUBAGENT_ASK.explore), `explore must not name ${loosened}`)
})

test('general asks for everything the parent session asks for', () => {
  assert.deepEqual(Object.keys(policyConfig().agent.general.permission).sort(), ['bash', 'edit', 'skill', 'task', 'webfetch', 'websearch'])
  for (const p of SUBAGENT_GATED) assert.equal(policyConfig().agent.general.permission[p], 'ask')
})

test('primary agents are left alone — the Code section sets their rules per session', () => {
  const names = Object.keys(policyConfig().agent)
  assert.ok(!names.includes('build') && !names.includes('plan'))
})

test('each call is a fresh object, and mergeConfig merges deeply without mutating', () => {
  const a = policyConfig(); a.agent.explore.permission.bash = 'allow'
  assert.equal(policyConfig().agent.explore.permission.bash, 'ask')
  const base = policyConfig()
  const merged = mergeConfig(base, { provider: { trustedrouter: { options: { baseURL: 'x' } } }, experimental: { other: 1 } })
  assert.equal(merged.experimental.continue_loop_on_deny, true)
  assert.equal(merged.experimental.other, 1)
  assert.equal(merged.provider.trustedrouter.options.baseURL, 'x')
  assert.equal(base.experimental.other, undefined)
})

test('the owner\'s generated config carries the policy', () => {
  const c = buildConfig({ proxyPort: 4196 })
  assert.deepEqual(c.agent, policyConfig().agent)
  assert.equal(c.experimental.continue_loop_on_deny, true)
})

const hasOpencode = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['opencode']).status === 0
const freePort = () => new Promise((res) => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })
/** Last matching rule wins — OpenCode's own evaluation, for pattern "*". */
const resolve = (rules, perm) => { let r = null; for (const x of rules) if ((x.permission === perm || x.permission === '*') && x.pattern === '*') r = x.action; return r }

test('LIVE: an OpenCode started with the policy resolves subagents to ask, and leaves the rest as it was', { skip: !hasOpencode && 'opencode is not installed', timeout: 60_000 }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'wb-policy-'))
  const port = await freePort()
  const env = { ...process.env, OPENCODE_CONFIG_CONTENT: JSON.stringify(policyConfig()) }
  delete env.OPENCODE_SERVER_PASSWORD; delete env.OPENAI_API_KEY
  const child = spawn('opencode', ['serve', '--port', String(port), '--hostname', '127.0.0.1'], { cwd: dir, env, stdio: 'ignore' })
  t.after(() => child.kill())
  let agents = null
  for (let i = 0; i < 100 && !agents; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/agent?directory=${encodeURIComponent(dir)}`); if (r.ok) agents = await r.json() } catch { await new Promise((r) => setTimeout(r, 300)) }
  }
  assert.ok(Array.isArray(agents), 'OpenCode answered /agent')
  const get = (n) => agents.find((a) => a.name === n)
  for (const p of ['bash', 'webfetch', 'websearch']) assert.equal(resolve(get('explore').permission, p), 'ask', `explore ${p}`)
  assert.equal(resolve(get('explore').permission, 'edit'), 'deny', 'explore still cannot edit at all')
  for (const p of ['bash', 'edit', 'webfetch', 'websearch', 'task', 'skill']) assert.equal(resolve(get('general').permission, p), 'ask', `general ${p}`)
  assert.equal(resolve(get('plan').permission, 'edit'), 'deny', 'plan mode keeps its edit deny')
})
