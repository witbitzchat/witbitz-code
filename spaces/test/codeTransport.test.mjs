// The Code section's transports (spaces/public/codeTransport.js) — the relay one driven end to end through the REAL
// connector (tools/opencode-connector.mjs) and a fake relay + fake OpenCode, the way the page uses it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { fakeRelay } from './fakeRelay.mjs'
import { newRelaySecret } from '../public/codeRelay.js'
import { relayTransport, directTransport } from '../public/codeTransport.js'
import { startConnector } from '../../tools/opencode-connector.mjs'

const until = async (fn, ms = 6000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 20)) } return false }

async function fakeOpenCode() {
  const streams = new Set()
  const srv = createServer(async (req, res) => {
    let body = ''
    for await (const c of req) body += c
    const path = req.url.split('?')[0]
    const json = (o) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)) }
    if (path === '/experimental/session') return json([{ id: 'ses_1', title: 'one' }])
    if (path === '/session/ses_1/message' && req.method === 'POST') return json({ info: { id: 'm1' }, got: JSON.parse(body) })
    if (path === '/event') { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write(': hi\n\n'); streams.add(res); res.on('close', () => streams.delete(res)); return }
    return json({ ok: true })
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${srv.address().port}`, streams, emit: (o) => { for (const s of streams) s.write(`data: ${JSON.stringify(o)}\n\n`) }, close: () => new Promise((r) => { for (const s of streams) s.destroy(); srv.closeAllConnections(); srv.close(() => r()) }) }
}

async function rig(t) {
  const relay = await fakeRelay()
  const oc = await fakeOpenCode()
  const secret = newRelaySecret()
  const computer = { id: 'cmp1', name: 'desk', relay: relay.url(), secret }
  const pairing = { name: 'desk', computerId: 'cmp1', secret, relay: relay.url(), opencodeUrl: oc.url, password: 'pw' }
  let connector = await startConnector({ pairings: [pairing], flushMs: 30, log: () => {} })
  const tr = relayTransport({ computer })
  t.after(async () => { tr.close(); connector.stop(); await relay.close(); await oc.close() })
  return { relay, oc, tr, pairing, stopComputer: () => connector.stop(), startComputer: async () => { connector = await startConnector({ pairings: [pairing], flushMs: 30, log: () => {} }) } }
}

test('relay: online once the computer says hello; requests and a turn POST go through', async (t) => {
  const { tr } = await rig(t)
  assert.ok(await until(() => tr.status() === 'online'), `status ${tr.status()}`)
  const list = await tr.request('GET', '/experimental/session?archived=true')
  assert.equal(list.ok, true); assert.deepEqual(list.json, [{ id: 'ses_1', title: 'one' }])
  const turn = await tr.request('POST', '/session/ses_1/message?directory=%2Fx', { parts: [{ type: 'text', text: 'hi' }] })
  assert.equal(turn.status, 200); assert.deepEqual(turn.json.got, { parts: [{ type: 'text', text: 'hi' }] })
  assert.equal(tr.kind, 'relay'); assert.equal(tr.label, 'desk')
})

test('relay: subscribe delivers parsed OpenCode events; stop() ends the delivery', async (t) => {
  const { tr, oc } = await rig(t)
  assert.ok(await until(() => tr.status() === 'online'))
  const got = []
  const stop = tr.subscribe('/event?directory=%2Fx', (ev) => got.push(ev))
  assert.ok(await until(() => oc.streams.size === 1), 'the connector opened the local stream')
  oc.emit({ type: 'session.idle', properties: { sessionID: 'ses_1' } })
  oc.emit({ type: 'message.part.delta', properties: { delta: 'a' } })
  assert.ok(await until(() => got.length === 2))
  assert.deepEqual(got.map((e) => e.type), ['session.idle', 'message.part.delta'])
  stop()
  assert.ok(await until(() => oc.streams.size === 0), 'unsub closes the local stream')
})

// The owner, opening Code: "I get this brief red warning. It is transient and shouldnt show up" — "my laptop is offline —
// start it…" for a moment on every open. The socket opened before the relay said who else was on the channel, so the page
// counted itself alone and said offline; the computer's hello came a moment later.
test('relay: opening onto a running computer goes connecting → online, never through offline', async (t) => {
  const { relay, pairing } = await rig(t)
  for (let i = 0; i < 5; i++) {
    const seen = []
    const tr = relayTransport({ computer: { id: 'cmp1', name: 'desk', relay: relay.url(), secret: pairing.secret } })
    tr.onChange((st) => seen.push(st))
    const first = tr.status()
    assert.ok(await until(() => tr.status() === 'online'), `online: ${tr.status()}`)
    tr.close()
    assert.equal(first, 'connecting')
    assert.ok(!seen.includes('offline'), `open #${i + 1} never said offline — ${JSON.stringify(seen)}`)
  }
})

test('relay: the computer going away reads as offline, a request then fails fast; it comes back online by itself', async (t) => {
  const { tr, stopComputer, startComputer } = await rig(t)
  assert.ok(await until(() => tr.status() === 'online'))
  const seen = []
  tr.onChange((s) => seen.push(s))
  stopComputer()
  assert.ok(await until(() => tr.status() === 'offline'), `went offline: ${tr.status()}`)
  const t0 = Date.now()
  const r = await tr.request('GET', '/agent')
  assert.equal(r.ok, false); assert.equal(r.text, 'offline')
  assert.ok(Date.now() - t0 < 9000, 'it waited only the short online grace, not the request timeout')
  await startComputer()
  assert.ok(await until(() => tr.status() === 'online'), 'back online without a reload')
  assert.ok(seen.includes('offline') && seen.at(-1) === 'online', JSON.stringify(seen))
  assert.equal((await tr.request('GET', '/agent')).ok, true)
})

test('relay: nobody on the channel at all → offline, not an endless "connecting"', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  const tr = relayTransport({ computer: { id: 'x', name: 'gone', relay: relay.url(), secret: newRelaySecret() } })
  t.after(() => tr.close())
  assert.ok(await until(() => tr.status() === 'offline'), tr.status())
})

test('direct: the development path still speaks plain HTTP with the password', async (t) => {
  const seen = []
  const srv = createServer((req, res) => { seen.push(req.headers.authorization); res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}') })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  t.after(() => new Promise((r) => { srv.closeAllConnections(); srv.close(() => r()) }))
  const tr = directTransport({ base: `http://127.0.0.1:${srv.address().port}/`, pass: 'pw' })
  const r = await tr.request('GET', '/agent')
  assert.deepEqual(r.json, { ok: true })
  assert.equal(seen[0], 'Basic ' + Buffer.from('opencode:pw').toString('base64'))
  assert.equal(tr.status(), 'online')
})

test('relay: a replayed OLD hello (earlier ts) does not move the page to a stale nonce', async (t) => {
  const { tr } = await rig(t)
  assert.ok(await until(() => tr.status() === 'online'))
  const before = tr._nonce()
  tr._hello({ t: 'hello', k: 'an-old-nonce', ts: 1 })
  assert.equal(tr._nonce(), before, 'a hello older than the last one is ignored')
  assert.equal((await tr.request('GET', '/agent')).ok, true, 'requests keep working')
})

// ── Auto mode (docs/code-auto-mode.md §5) ──
test('relay: hello says whether the computer can do Auto and which sessions are in it; an old connector says nothing', async (t) => {
  const { tr } = await rig(t)
  assert.ok(await until(() => tr.status() === 'online'))
  const seen = []
  tr.onAuto((e) => seen.push(e))
  tr._hello({ t: 'hello', k: tr._nonce(), ts: Date.now() + 1000, caps: ['auto'], auto: ['ses_1', 7, 'bad id'] })
  assert.equal(tr.can('auto'), true)
  assert.deepEqual(tr.autoSessions(), ['ses_1'], 'only well-formed session ids')
  assert.ok(seen.some((e) => e.kind === 'sessions'), 'listeners hear the change')
  tr._hello({ t: 'hello', k: tr._nonce(), ts: Date.now() + 2000 })
  assert.equal(tr.can('auto'), false, 'a hello without caps is a connector that predates Auto')
  assert.deepEqual(tr.autoSessions(), [])
})
