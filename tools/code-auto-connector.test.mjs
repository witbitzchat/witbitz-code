// Code Auto mode, wired into the connector (docs/code-auto-mode.md §5): the page sees `auto` in the computer's hello,
// switches a session with a nonce-checked `auto` message over the sealed relay, and receives each automatic decision as
// `autoverdict`. The loop itself is tested in code-auto-runner.test.mjs; this pins the wiring.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fakeRelay } from '../spaces/test/fakeRelay.mjs'
import { RelayPeer, newRelaySecret } from '../spaces/public/codeRelay.js'
import { startConnector } from './opencode-connector.mjs'

const until = async (fn, ms = 5000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { const v = await fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)) } return null }

async function fakeOpenCode() {
  const seen = [], pending = []
  const srv = createServer(async (q, r) => {
    const url = new URL(q.url, 'http://x')
    let body = ''
    for await (const c of q) body += c
    seen.push({ method: q.method, path: url.pathname, dir: url.searchParams.get('directory'), body: body ? JSON.parse(body) : undefined })
    const json = (o, st = 200) => { r.writeHead(st, { 'content-type': 'application/json' }); r.end(JSON.stringify(o)) }
    if (q.method === 'GET' && url.pathname === '/permission') return json(pending)
    const m = url.pathname.match(/^\/permission\/([^/]+)\/reply$/)
    if (q.method === 'POST' && m) { const i = pending.findIndex((p) => p.id === m[1]); if (i >= 0) pending.splice(i, 1); return json(true) }
    return json({ error: 'nope' }, 404)
  })
  await new Promise((res) => srv.listen(0, '127.0.0.1', res))
  return { url: `http://127.0.0.1:${srv.address().port}`, seen, pending, close: () => { srv.closeAllConnections(); srv.close() } }
}

async function rig(t) {
  const relay = await fakeRelay()
  const oc = await fakeOpenCode()
  const secret = newRelaySecret()
  const autoDir = mkdtempSync(join(tmpdir(), 'code-auto-conn-'))
  const connector = await startConnector({ pairings: [{ name: 'test-box', computerId: 'cmp_test', secret, relay: relay.url(), opencodeUrl: oc.url, password: 'pw' }], flushMs: 40, log: () => {}, autoDir, autoPollMs: 40 })
  const got = []
  const page = new RelayPeer({ secret, role: 'client', relay: relay.url(), onMessage: (m) => got.push(m) })
  t.after(async () => { page.stop(); connector.stop(); await relay.close(); oc.close() })
  await page.start()
  assert.ok(await until(() => got.some((m) => m.t === 'hello' && m.k)), 'hello')
  const nonce = () => got.filter((m) => m.t === 'hello').at(-1).k
  return { oc, page, got, nonce, autoDir }
}

test('the computer says it can do Auto, and which sessions are in it', async (t) => {
  const { got } = await rig(t)
  const h = got.filter((m) => m.t === 'hello').at(-1)
  assert.ok(Array.isArray(h.caps) && h.caps.includes('auto'), 'caps carry auto — an older connector without it hides the switch')
  assert.deepEqual(h.auto, [])
})

test('the page switches a session to Auto; the next ask is decided on the computer and the verdict comes back', async (t) => {
  const { oc, page, got, nonce, autoDir } = await rig(t)
  await page.send({ t: 'auto', k: nonce(), sid: 'ses_main', dir: '/home/u/repo', on: true })
  assert.ok(await until(() => got.some((m) => m.t === 'hello' && Array.isArray(m.auto) && m.auto.includes('ses_main'))), 'a fresh hello lists the session')
  assert.ok(existsSync(join(autoDir, 'auto-cmp_test.json')), 'remembered on the computer, per pairing')

  oc.pending.push({ id: 'per_1', sessionID: 'ses_main', permission: 'edit', patterns: ['src/a.ts'], metadata: {}, always: [] })
  const v = await until(() => got.find((m) => m.t === 'autoverdict'))
  assert.ok(v, 'the verdict reaches the page')
  assert.deepEqual({ sessionID: v.sessionID, permission: v.permission, action: v.action, stage: v.stage, rule: v.rule }, { sessionID: 'ses_main', permission: 'edit', action: 'allow', stage: 'fast-allow', rule: 'fast:edit-in-project' })
  const reply = oc.seen.find((s) => s.method === 'POST' && s.path === '/permission/per_1/reply')
  assert.deepEqual(reply.body, { reply: 'once' })
  assert.equal(reply.dir, '/home/u/repo')
  const log = readFileSync(join(autoDir, 'auto-log.jsonl'), 'utf8')
  assert.match(log, /"fast-allow"/)
  assert.doesNotMatch(log, /src\/a\.ts/, 'the log holds a digest, not the path')

  await page.send({ t: 'auto', k: nonce(), sid: 'ses_main', dir: '/home/u/repo', on: false })
  assert.ok(await until(() => got.filter((m) => m.t === 'hello').at(-1).auto.length === 0), 'switched off again')
})

test('an Auto switch with a stale nonce is ignored — a recording cannot turn Auto on', async (t) => {
  const { page, got } = await rig(t)
  await page.send({ t: 'auto', k: 'not-the-nonce', sid: 'ses_main', dir: '/home/u/repo', on: true })
  await new Promise((r) => setTimeout(r, 300))
  assert.equal(got.some((m) => m.t === 'hello' && (m.auto || []).includes('ses_main')), false)
})
