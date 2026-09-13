// Pairing a computer with a Spaces account for the Code section over the sealed relay (tools/opencode-pair.mjs,
// docs/opencode-relay.md §3, §10). The account API is a mock with the server's semantics: op:'state' reads when there is no
// patch and REPLACES the doc when there is one.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  envGet, envSet, newPassword, newComputerId, upsertPairing, removePairings, normPairings,
  publishComputer, unpublishComputer, clearLegacyDirect,
} from './opencode-pair.mjs'
import { normRegistry, withComputer } from '../spaces/public/codeComputers.js'
import { gunzipB64 } from '../spaces/public/compress.js'

const IDX = { room: 'sp-idx', mk: 'MK' }
const IDX2 = { room: 'sp-other', mk: 'MK2' }
const SECRET = 'S'.repeat(43)
const RELAY = 'wss://code-relay.witbitz.chat'

function mockApi({ readStatus = 200, docs = {} } = {}) {
  const writes = []
  const call = async (body) => {
    if (body.op !== 'state') return { status: 400, j: { error: 'unexpected op' } }
    if (body.patch === undefined) return readStatus === 200 ? { status: 200, j: { state: docs[body.name] ?? null } } : { status: readStatus, j: { error: 'nope' } }
    writes.push(body)
    docs[body.name] = JSON.parse(JSON.stringify(body.patch))
    return { status: 200, j: { ok: true } }
  }
  const plain = async (name) => { const d = docs[name]; return d && typeof d.z === 'string' ? gunzipB64(d.z) : d }
  return { call, writes, docs, plain }
}

test('the env file: only the password line changes — every other line, duplicates included, is kept', () => {
  const env = 'OPENCODE_SERVER_USERNAME=opencode\nOPENCODE_SERVER_PASSWORD=old1\nTRUSTEDROUTER_API_KEY=tr-a\nTRUSTEDROUTER_API_KEY=tr-a\nOPENCODE_SERVER_PASSWORD=old2\n'
  assert.equal(envGet(env, 'OPENCODE_SERVER_PASSWORD'), 'old2', 'the LAST one wins, as when the file is sourced')
  const out = envSet(env, 'OPENCODE_SERVER_PASSWORD', 'new-pass')
  assert.equal(envGet(out, 'OPENCODE_SERVER_PASSWORD'), 'new-pass')
  assert.equal((out.match(/^OPENCODE_SERVER_PASSWORD=/gm) || []).length, 1)
  assert.equal((out.match(/^TRUSTEDROUTER_API_KEY=tr-a$/gm) || []).length, 2)
  assert.ok(out.endsWith('\n'))
  assert.equal(envGet(envSet('', 'K', 'v'), 'K'), 'v')
})

test('minted passwords and computer ids are long, URL-safe and never repeat', () => {
  for (const mint of [newPassword, newComputerId]) {
    const a = mint(), b = mint()
    assert.match(a, /^[A-Za-z0-9_-]{22,}$/); assert.notEqual(a, b)
  }
})

test('pairing an account adds an entry with its own id and secret; pairing it again keeps both', () => {
  let n = 0
  const mint = { mintId: () => 'cmp_' + (++n), mintSecret: () => 'x'.repeat(40) + String(++n).padStart(3, '0') }
  const first = upsertPairing(null, { account: 'me@x', idx: IDX, name: 'desk' }, mint)
  assert.equal(first.isNew, true)
  assert.equal(first.entry.computerId, 'cmp_1'); assert.equal(first.entry.relay, RELAY); assert.equal(first.entry.opencodeUrl, 'http://127.0.0.1:4096')
  const again = upsertPairing(first.doc, { account: 'me@x', idx: IDX }, mint)
  assert.equal(again.isNew, false)
  assert.equal(again.entry.computerId, 'cmp_1'); assert.equal(again.entry.secret, first.entry.secret); assert.equal(again.entry.name, 'desk')
  assert.equal(again.doc.pairings.length, 1)
  const rotated = upsertPairing(again.doc, { account: 'me@x', idx: IDX }, { ...mint, rotate: true })
  assert.equal(rotated.entry.computerId, 'cmp_1', 'rotation keeps the computer'); assert.notEqual(rotated.entry.secret, first.entry.secret, 'and replaces the secret')
})

test('a second account is a SEPARATE pairing — and the tool knows when both reach the same OpenCode', () => {
  const a = upsertPairing(null, { account: 'me@x', idx: IDX })
  const b = upsertPairing(a.doc, { account: 'work@y', idx: IDX2 })
  assert.equal(b.doc.pairings.length, 2)
  assert.notEqual(b.entry.secret, a.entry.secret); assert.notEqual(b.entry.computerId, a.entry.computerId)
  assert.deepEqual(b.sharedWith, ['me@x'], 'same OpenCode URL → shared, and said')
  const separate = upsertPairing(a.doc, { account: 'friend@z', idx: IDX2, opencodeUrl: 'http://127.0.0.1:4097' })
  assert.deepEqual(separate.sharedWith, [], 'a separate instance shares nothing')
})

test('unpairing locally removes only that account (or all), and broken entries never load', () => {
  const two = upsertPairing(upsertPairing(null, { account: 'me@x', idx: IDX }).doc, { account: 'work@y', idx: IDX2 }).doc
  const r = removePairings(two, 'work@y')
  assert.deepEqual(r.doc.pairings.map((p) => p.account), ['me@x']); assert.equal(r.removed.length, 1)
  assert.equal(removePairings(two, '').doc.pairings.length, 0)
  assert.equal(normPairings({ pairings: [{ account: 'no idx', secret: SECRET, computerId: 'c' }, null] }).pairings.length, 0)
})

test('publishComputer REFUSES without a definitive read, and writes nothing', async () => {
  const api = mockApi({ readStatus: 503 })
  const r = await publishComputer({ call: api.call, idx: IDX, computerId: 'cmp_desk_01', name: 'desk', relay: RELAY, secret: SECRET, now: 1000 })
  assert.equal(r.ok, false); assert.match(r.why, /503/)
  assert.equal(api.writes.length, 0)
})

test('publishComputer adds this computer beside the others already paired, and verifies it', async () => {
  const other = withComputer(null, 'cmp_laptop_1', { name: 'laptop', relay: RELAY, secret: 'L'.repeat(43) }, 500)
  const api = mockApi({ docs: { computers: other } })
  const r = await publishComputer({ call: api.call, idx: IDX, computerId: 'cmp_desk_01', name: 'desk', relay: RELAY, secret: SECRET, now: 1000 })
  assert.equal(r.ok, true, r.why)
  assert.equal(api.writes.length, 1); assert.equal(api.writes[0].name, 'computers'); assert.equal(api.writes[0].room, 'sp-idx')
  const reg = normRegistry(await api.plain('computers'))
  assert.deepEqual(Object.keys(reg.computers).sort(), ['cmp_desk_01', 'cmp_laptop_1'], 'the laptop survived')
  assert.equal(reg.computers.cmp_desk_01.secret, SECRET)
  assert.deepEqual(r.computers.map((c) => c.name), ['laptop', 'desk'])
})

test('unpublishComputer tombstones this computer (its secret leaves the account); absent → nothing written', async () => {
  const api = mockApi({ docs: { computers: withComputer(null, 'cmp_desk_01', { name: 'desk', relay: RELAY, secret: SECRET }, 500) } })
  const r = await unpublishComputer({ call: api.call, idx: IDX, computerId: 'cmp_desk_01', now: 1000 })
  assert.equal(r.ok, true, r.why)
  const e = normRegistry(await api.plain('computers')).computers.cmp_desk_01
  assert.equal(e.removed, true); assert.equal(e.secret, undefined)
  const again = await unpublishComputer({ call: api.call, idx: IDX, computerId: 'cmp_desk_01', now: 2000 })
  assert.equal(again.noop, true)
  assert.equal(api.writes.length, 1, 'a second unpair writes nothing')
  const refused = await unpublishComputer({ call: mockApi({ readStatus: 500 }).call, idx: IDX, computerId: 'x' })
  assert.equal(refused.ok, false)
})

test('clearLegacyDirect empties the old server address but keeps contacts and the chosen model', async () => {
  const api = mockApi({ docs: { index2: { v: 2, contacts: [{ kind: 'person', email: 'dana@example.com' }], code: { base: 'https://devbox.example.ts.net', pass: 'p', model: 'm', agent: 'build', mod: 50 } } } })
  const r = await clearLegacyDirect({ call: api.call, idx: IDX, now: 9 })
  assert.equal(r.ok, true, r.why)
  const d = await api.plain('index2')
  assert.equal(d.code.base, ''); assert.equal(d.code.pass, ''); assert.equal(d.code.model, 'm'); assert.ok(d.code.mod > 50)
  assert.deepEqual(d.contacts, [{ kind: 'person', email: 'dana@example.com' }])
  const none = await clearLegacyDirect({ call: api.call, idx: IDX, now: 10 })
  assert.equal(none.noop, true); assert.equal(api.writes.length, 1)
  assert.equal((await clearLegacyDirect({ call: mockApi({ readStatus: 500 }).call, idx: IDX })).ok, false)
})

test('secret files are written atomically: 0600, whole, and no temp file left behind', async () => {
  const { writeSecret } = await import('./opencode-pair.mjs')
  const { mkdtempSync, writeFileSync, readFileSync, statSync, readdirSync, rmSync } = await import('node:fs')
  const { join } = await import('node:path')
  const { tmpdir } = await import('node:os')
  const dir = mkdtempSync(join(tmpdir(), 'ws-'))
  try {
    const f = join(dir, 'pairings.json')
    writeFileSync(f, 'old-readable', { mode: 0o644 })
    writeSecret(f, 'new-secret-contents')
    assert.equal(readFileSync(f, 'utf8'), 'new-secret-contents')
    assert.equal(statSync(f).mode & 0o777, 0o600)
    assert.deepEqual(readdirSync(dir), ['pairings.json'], 'the temp file was renamed into place')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
