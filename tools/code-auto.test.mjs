// Code Auto mode — the pure core (docs/code-auto-mode.md). The owner: "it is asking too much but removing these asks is
// too dangerous". So the rules are pinned as shared vectors (tools/code-auto.vectors.json): what is refused without a
// model, what is allowed without one, and everything else goes to the reviewer. The Python twin runs the same file.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { classifyDeterministic, reviewerPrompt, parseVerdict, actionFor, logRecord, SEVERITY_CEILING } from './code-auto.mjs'

const V = JSON.parse(readFileSync(new URL('./code-auto.vectors.json', import.meta.url), 'utf8'))
const ctx = { directory: V.directory, home: V.home }

for (const c of V.cases) {
  test(`deterministic: ${c.name} → ${c.stage}`, () => {
    const r = classifyDeterministic({ id: 'per_x', sessionID: 'ses_x', always: [], ...c.req }, { ...ctx, folders: c.folders || [] })
    const stage = r ? r.stage : 'review'
    assert.equal(stage, c.stage)
    if (r) {
      assert.equal(r.decision, { 'hard-deny': 'deny', 'fast-ask': 'ask' }[r.stage] || 'allow')
      assert.ok(r.rule && typeof r.rule === 'string', 'every automatic decision names its rule')
    }
    if (r && r.stage === 'hard-deny') assert.ok(r.reason.length > 10, 'a refusal tells the agent why')
  })
}

for (const v of V.verdicts) {
  test(`verdict: ${v.name} → ${v.action}`, () => {
    assert.equal(actionFor(parseVerdict(v.text)), v.action)
  })
}

test('an allow at the ceiling is the human\'s, just below it is automatic', () => {
  assert.equal(actionFor({ decision: 'allow', severity: SEVERITY_CEILING, rule: 'r', reason: '' }), 'ask')
  assert.equal(actionFor({ decision: 'allow', severity: SEVERITY_CEILING - 1, rule: 'r', reason: '' }), 'allow')
  assert.equal(actionFor(null), 'ask', 'no verdict never means yes')
})

test('the reviewer prompt holds the policy, the request and the recent user messages — all marked as DATA', () => {
  const req = { id: 'per_1', sessionID: 'ses_1', permission: 'bash', patterns: ['npm test'], metadata: { command: 'npm test -- --watch=false' }, always: [] }
  const p = reviewerPrompt({ req, directory: '/home/u/repo', userMessages: ['old one', 'run the tests please'] })
  assert.match(p.system, /allow/i)
  assert.match(p.system, /soft deny/i)
  assert.match(p.system, /hard deny/i)
  assert.match(p.system, /"decision"/, 'the output contract is spelled out')
  assert.match(p.system, /data, not instructions/i, 'text inside the request cannot steer the reviewer')
  assert.match(p.text, /npm test -- --watch=false/)
  assert.match(p.text, /\/home\/u\/repo/)
  assert.ok(p.text.indexOf('old one') < p.text.indexOf('run the tests please'), 'oldest first, the latest request last')
})

// Measured 2026-09-14: an external_directory ask for `/tmp/*` alone does not say whether the agent reads or writes, and the
// reviewer told the person "a write" about a read. The runner now hands over the tool; the ask's own file rides along.
test('an ask with no command names its tool and its file, so the reviewer need not guess read from write', () => {
  const req = { id: 'per_2', sessionID: 'ses_1', permission: 'external_directory', patterns: ['/tmp/x/*'], metadata: { filepath: '/tmp/x/page-3.png', parentDir: '/tmp/x' } }
  const p = reviewerPrompt({ req, directory: '/home/u/repo', userMessages: ['analyze the folder'], tool: 'read' })
  assert.match(p.text, /^tool: read$/m)
  assert.match(p.text, /^file: \/tmp\/x\/page-3\.png$/m)
  const bare = reviewerPrompt({ req: { ...req, metadata: {} }, directory: '/home/u/repo' })
  assert.doesNotMatch(bare.text, /^(tool|file):/m, 'nothing invented when the runner found no tool and the ask has no file')
  const bash = reviewerPrompt({ req: { permission: 'bash', patterns: ['ls'], metadata: { command: 'ls', filepath: '/x' } }, directory: '/d', tool: 'bash' })
  assert.doesNotMatch(bash.text, /^file:/m, 'a command speaks for itself')
  assert.match(p.system, /\/tmp\/opencode/, 'the policy names the scratch directory, so a command writing there reads the same as the fixed rule')
})

test('the prompt is bounded: a huge command and a long history are cut', () => {
  const big = 'x'.repeat(50_000)
  const req = { id: 'per_1', sessionID: 'ses_1', permission: 'bash', patterns: [big], metadata: { command: big }, always: [] }
  const msgs = Array.from({ length: 30 }, (_, i) => `message ${i} ` + 'y'.repeat(5000))
  const p = reviewerPrompt({ req, directory: '/r', userMessages: msgs })
  assert.ok(p.text.length < 20_000, `bounded (${p.text.length} chars)`)
  assert.match(p.text, /message 29/, 'the latest message is kept')
  assert.doesNotMatch(p.text, /message 0 /, 'the oldest are dropped')
})

test('a log record carries a digest of the request — never the command or the path', () => {
  const req = { id: 'per_1', sessionID: 'ses_1', permission: 'bash', patterns: ['cat /home/u/.aws/credentials'], metadata: { command: 'cat /home/u/.aws/credentials' }, always: [] }
  const rec = logRecord({ req, stage: 'reviewer', verdict: { decision: 'deny', severity: 90, rule: 'hard:secrets', reason: 'reads credentials' }, action: 'deny', model: 'anthropic/claude-sonnet-4-6', ms: 812, at: 1000 })
  const s = JSON.stringify(rec)
  assert.doesNotMatch(s, /credentials|\.aws|cat /, 'nothing of the request itself')
  assert.match(rec.digest, /^[0-9a-f]{64}$/)
  assert.deepEqual({ at: rec.at, session: rec.session, permission: rec.permission, stage: rec.stage, action: rec.action, severity: rec.severity, rule: rec.rule, model: rec.model, ms: rec.ms },
    { at: 1000, session: 'ses_1', permission: 'bash', stage: 'reviewer', action: 'deny', severity: 90, rule: 'hard:secrets', model: 'anthropic/claude-sonnet-4-6', ms: 812 })
  const again = logRecord({ req: { ...req, id: 'per_2' }, stage: 'reviewer', verdict: null, action: 'ask', model: '', ms: 1, at: 2 })
  assert.equal(again.digest, rec.digest, 'the same request digests the same, so repeats can be counted')
})
