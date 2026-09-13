// The connector beside OpenCode (tools/opencode-connector.mjs, docs/opencode-relay.md §4–§5), driven exactly as the Code
// page drives it: a client RelayPeer on a (fake) relay, against a fake OpenCode that checks the password.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { fakeRelay } from '../spaces/test/fakeRelay.mjs'
import { RelayPeer, newRelaySecret, CHUNK } from '../spaces/public/codeRelay.js'
import { startConnector, parseEnvPassword, pairingsForPort } from './opencode-connector.mjs'

const PASSWORD = 'local-only-password'
const until = async (fn, ms = 4000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 15)) } return false }

async function fakeOpenCode() {
  const seen = []
  const streams = new Set()
  const big = 'z'.repeat(CHUNK * 2 + 123)
  const srv = createServer(async (req, res) => {
    let body = ''
    for await (const c of req) body += c
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization || '', body })
    const ok = req.headers.authorization === 'Basic ' + Buffer.from('opencode:' + PASSWORD).toString('base64')
    if (!ok) { res.writeHead(401); return res.end('unauthorized') }
    const json = (o, st = 200) => { res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)) }
    const path = req.url.split('?')[0]
    if (path === '/agent') return json([{ name: 'build' }])
    if (path === '/session/ses_big/message') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(big) }
    if (path === '/session/ses_1/message' && req.method === 'POST') return json({ echoed: JSON.parse(body) })
    if (path === '/session/ses_slow/message') { res.on('close', () => seen.push({ aborted: '/session/ses_slow/message' })); return } // never answers; res 'close' = the caller went away (req 'close' already fired once the body was read)
    if (path === '/event') {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.write(': open\n\n')
      streams.add(res)
      res.on('close', () => streams.delete(res))
      return
    }
    return json({ ok: true })
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${srv.address().port}`,
    seen, big, streams,
    emit: (obj) => { for (const s of streams) s.write(`data: ${JSON.stringify(obj)}\n\n`) },
    close: () => new Promise((r) => { for (const s of streams) s.destroy(); srv.closeAllConnections(); srv.close(() => r()) }),
  }
}

async function rig(t, { opencodeUrl, connectorOptions = {} } = {}) {
  const relay = await fakeRelay()
  const oc = await fakeOpenCode()
  const secret = newRelaySecret()
  const connector = await startConnector({
    pairings: [{ name: 'test-box', computerId: 'cmp_test', secret, relay: relay.url(), opencodeUrl: opencodeUrl || oc.url, password: PASSWORD }],
    flushMs: 40, log: () => {}, ...connectorOptions,
  })
  const got = []
  const client = new RelayPeer({ secret, role: 'client', relay: relay.url(), onMessage: (m) => got.push(m) })
  t.after(async () => { client.stop(); connector.stop(); await relay.close(); await oc.close() })
  await client.start()
  assert.ok(await until(() => client.isOpen && client.peers === 2), 'client and connector are on the channel')
  assert.ok(await until(() => got.some((m) => m.t === 'hello' && typeof m.k === 'string')), 'the connector announces its nonce')
  const nonce = () => got.filter((m) => m.t === 'hello').at(-1).k
  let n = 0
  const call = async (m, p, b, k = nonce()) => {
    const id = 'r' + (++n)
    await client.send({ t: 'req', id, k, m, p, ...(b === undefined ? {} : { b: JSON.stringify(b) }) })
    assert.ok(await until(() => got.some((x) => x.t === 'res' && x.id === id)), `a response to ${m} ${p}`)
    return got.find((x) => x.t === 'res' && x.id === id)
  }
  return { relay, oc, secret, client, got, call, connector, nonce, restart: async () => { connector.stop(); await new Promise((r) => setTimeout(r, 100)) ; const c2 = await startConnector({ pairings: [{ name: 'test-box', computerId: 'cmp_test', secret, relay: relay.url(), opencodeUrl: opencodeUrl || oc.url, password: PASSWORD }], flushMs: 40, log: () => {} }); t.after(() => c2.stop()); return c2 } }
}

test('the env file password is read the way a shell would read it', () => {
  assert.equal(parseEnvPassword('A=1\nOPENCODE_SERVER_PASSWORD=first\nexport OPENCODE_SERVER_PASSWORD="second"\n'), 'second')
  assert.equal(parseEnvPassword('X=1\n'), '')
  assert.equal(parseEnvPassword('A=1\r\nOPENCODE_SERVER_PASSWORD=crlf-pass\r\nB=2\r\n'), 'crlf-pass', 'a CRLF file (edited on Windows) still yields the password')
})

test('the computer says hello when a client arrives', async (t) => {
  const { got } = await rig(t)
  assert.ok(await until(() => got.some((m) => m.t === 'hello' && m.name === 'test-box' && m.computerId === 'cmp_test')), JSON.stringify(got))
})

test('a request is forwarded to OpenCode with the LOCAL password and the answer comes back sealed', async (t) => {
  const { oc, call } = await rig(t)
  const r = await call('GET', '/agent')
  assert.equal(r.st, 200)
  assert.deepEqual(JSON.parse(r.b), [{ name: 'build' }])
  const hit = oc.seen.find((s) => s.url === '/agent')
  assert.equal(hit.auth, 'Basic ' + Buffer.from('opencode:' + PASSWORD).toString('base64'), 'the password never travels — the connector adds it')
})

test('a POST carries its body and the query string survives', async (t) => {
  const { oc, call } = await rig(t)
  const r = await call('POST', '/session/ses_1/message?directory=%2Fhome%2Fu', { parts: [{ type: 'text', text: 'hi' }] })
  assert.equal(r.st, 200)
  assert.deepEqual(JSON.parse(r.b), { echoed: { parts: [{ type: 'text', text: 'hi' }] } })
  assert.ok(oc.seen.some((s) => s.url === '/session/ses_1/message?directory=%2Fhome%2Fu' && s.method === 'POST'))
})

test('the New-session folder picker\'s two reads are forwarded, with their query intact', async (t) => {
  const { oc, call } = await rig(t)
  for (const p of ['/path', '/file?path=witbitz%2Fspaces&directory=%2Fhome%2Fu']) {
    const r = await call('GET', p)
    assert.equal(r.st, 200, p)
    assert.ok(oc.seen.some((s) => s.method === 'GET' && s.url === p), `OpenCode received ${p}`)
  }
})

test('anything outside the allowlist is refused with 403 and never reaches OpenCode', async (t) => {
  const { oc, call } = await rig(t)
  // (GET /file — a folder LISTING — is allowed for the New-session picker; reading a file's CONTENT is not.)
  for (const [m, p] of [['POST', '/session/ses_1/shell'], ['GET', '/file/content?path=%2Fetc%2Fpasswd'], ['GET', '/event']]) {
    const r = await call(m, p)
    assert.equal(r.st, 403, `${m} ${p}`)
  }
  assert.equal(oc.seen.filter((s) => /shell|file\/content|event/.test(s.url || '')).length, 0)
})

test('a response larger than one frame arrives whole', async (t) => {
  const { oc, call } = await rig(t)
  const r = await call('GET', '/session/ses_big/message')
  assert.equal(r.st, 200)
  assert.equal(r.b.length, oc.big.length)
})

test('events: sub opens the local stream (with its directory), deltas arrive batched and in order, and it closes when the client leaves', async (t) => {
  const { oc, client, got, nonce } = await rig(t)
  await client.send({ t: 'sub', c: 'dev1', k: nonce(), p: '/event?directory=%2Fhome%2Fu' })
  assert.ok(await until(() => oc.streams.size === 1), 'the connector opened OpenCode\'s event stream')
  assert.ok(oc.seen.some((s) => s.url === '/event?directory=%2Fhome%2Fu'))
  for (let i = 0; i < 30; i++) oc.emit({ type: 'message.part.delta', properties: { delta: 'tok' + i } })
  const events = () => got.filter((m) => m.t === 'evts').flatMap((m) => JSON.parse(m.b).map((d) => ({ p: m.p, d })))
  assert.ok(await until(() => events().length === 30), `all 30 events arrive — got ${events().length}`)
  assert.deepEqual(events().map((e) => JSON.parse(e.d).properties.delta), Array.from({ length: 30 }, (_, i) => 'tok' + i))
  assert.ok(events().every((e) => e.p === '/event?directory=%2Fhome%2Fu'), 'each batch names its stream')
  const frames = got.filter((m) => m.t === 'evts').length
  assert.ok(frames < 30, `batched: ${frames} frames for 30 events (the relay allows 200 messages per 10 s)`)
  client.stop()
  assert.ok(await until(() => oc.streams.size === 0), 'nobody is watching → the local stream is closed')
})

test('a cancelled request aborts the local call', async (t) => {
  const { oc, client, nonce } = await rig(t)
  await client.send({ t: 'req', id: 'slow', k: nonce(), m: 'GET', p: '/session/ses_slow/message' })
  assert.ok(await until(() => oc.seen.some((s) => s.url === '/session/ses_slow/message')))
  await client.send({ t: 'cancel', id: 'slow', k: nonce() })
  assert.ok(await until(() => oc.seen.some((s) => s.aborted)), 'OpenCode saw the call go away')
})

test('OpenCode not running → a 502 the page can explain, not silence', async (t) => {
  const { call } = await rig(t, { opencodeUrl: 'http://127.0.0.1:9' })
  const r = await call('GET', '/agent')
  assert.equal(r.st, 502)
  assert.match(JSON.parse(r.b).error, /OpenCode/)
})

test('REPLAY: a request without the connector\'s current nonce is refused (409) and never reaches OpenCode', async (t) => {
  const { oc, call } = await rig(t)
  const r = await call('GET', '/agent', undefined, 'not-the-nonce')
  assert.equal(r.st, 409)
  const none = await call('GET', '/agent', undefined, null)
  assert.equal(none.st, 409, 'no nonce at all')
  assert.equal(oc.seen.filter((x) => x.url === '/agent').length, 0)
})

test('REPLAY: a sealed request recorded before a connector restart does nothing after it', async (t) => {
  const { oc, relay, client, got, nonce, restart } = await rig(t)
  const recorded = []
  // record what the client puts on the wire (as the relay operator could)
  const set = [...relay.channels.values()][0]
  for (const s of set) s.on('message', (d) => recorded.push(d.toString()))
  await client.send({ t: 'req', id: 'orig', k: nonce(), m: 'POST', p: '/session/ses_1/message', b: JSON.stringify({ parts: [{ type: 'text', text: 'rm -rf' }] }) })
  assert.ok(await until(() => oc.seen.filter((x) => x.url === '/session/ses_1/message').length === 1))
  const frames = recorded.filter((x) => x.includes('"q"'))
  await restart()
  assert.ok(await until(() => got.filter((m) => m.t === 'hello').length >= 2), 'the new connector said hello')
  const fresh = [...relay.channels.values()][0]
  const replayer = [...fresh][0] // any socket on the channel can inject bytes
  for (const f of frames) replayer.emit('message', Buffer.from(f), false)
  await new Promise((r) => setTimeout(r, 400))
  assert.equal(oc.seen.filter((x) => x.url === '/session/ses_1/message').length, 1, 'the replayed turn never ran again')
})

test('one device unsubscribing does not close the stream another device is still watching', async (t) => {
  const { oc, client, nonce } = await rig(t)
  await client.send({ t: 'sub', c: 'phone', k: nonce(), p: '/event' })
  await client.send({ t: 'sub', c: 'desk', k: nonce(), p: '/event' })
  assert.ok(await until(() => oc.streams.size === 1))
  await client.send({ t: 'unsub', c: 'phone', k: nonce(), p: '/event' })
  await new Promise((r) => setTimeout(r, 300))
  assert.equal(oc.streams.size, 1, 'the desk is still watching')
  await client.send({ t: 'unsub', c: 'desk', k: nonce(), p: '/event' })
  assert.ok(await until(() => oc.streams.size === 0), 'the last watcher leaving closes it')
})

test('a request id longer than 64 characters is refused, not silently truncated (cancel must find what it cancels)', async (t) => {
  const { oc, client, got, nonce } = await rig(t)
  const long = 'x'.repeat(65)
  await client.send({ t: 'req', id: long, k: nonce(), m: 'GET', p: '/agent' })
  assert.ok(await until(() => got.some((m) => m.t === 'res' && m.id === long)))
  assert.equal(got.find((m) => m.t === 'res' && m.id === long).st, 400)
  assert.equal(oc.seen.filter((x) => x.url === '/agent').length, 0)
})

test('REPLAY: once enough later sockets push a sender out of the window, the nonce rotates — its recorded request is refused', async (t) => {
  const { oc, relay, client, got, nonce, secret } = await rig(t, { connectorOptions: { maxSenders: 2 } })
  const recorded = []
  for (const s of [...relay.channels.values()][0]) s.on('message', (d) => recorded.push(d.toString()))
  await client.send({ t: 'req', id: 'orig', k: nonce(), m: 'POST', p: '/session/ses_1/message', b: JSON.stringify({ parts: [] }) })
  assert.ok(await until(() => oc.seen.filter((x) => x.url === '/session/ses_1/message').length === 1))
  const frames = recorded.filter((x) => x.includes('"q"'))
  const hellosBefore = got.filter((m) => m.t === 'hello').length
  // three later page sockets (iOS reconnecting), each heard by the connector
  for (let i = 0; i < 3; i++) {
    const later = new RelayPeer({ secret, role: 'client', relay: relay.url() })
    t.after(() => later.stop())
    await later.start()
    assert.ok(await until(() => later.isOpen))
    await later.send({ t: 'ping' })
    await new Promise((r) => setTimeout(r, 120))
  }
  assert.ok(await until(() => got.filter((m) => m.t === 'hello').length > hellosBefore), 'the connector announced a new nonce')
  // inject from a PAGE socket (the relay never echoes to the sender, so injecting from the connector's own would prove nothing)
  const injector = [...[...relay.channels.values()][0]].at(-1)
  for (const f of frames) injector.emit('message', Buffer.from(f), false)
  await new Promise((r) => setTimeout(r, 400))
  assert.equal(oc.seen.filter((x) => x.url === '/session/ses_1/message').length, 1, 'the replay never ran')
})

test('an answer over the size cap is refused WHILE reading (413), not after holding all of it', async (t) => {
  const { oc, call } = await rig(t, { connectorOptions: { maxResponseBytes: 50_000 } })
  const r = await call('GET', '/session/ses_big/message')
  assert.equal(r.st, 413)
  assert.match(JSON.parse(r.b).error, /too large/)
})

test('an unsub without a client id removes only that anonymous interest', async (t) => {
  const { oc, client, nonce } = await rig(t)
  await client.send({ t: 'sub', c: 'desk', k: nonce(), p: '/event' })
  await client.send({ t: 'sub', k: nonce(), p: '/event' })
  assert.ok(await until(() => oc.streams.size === 1))
  await client.send({ t: 'unsub', k: nonce(), p: '/event' })
  await new Promise((r) => setTimeout(r, 300))
  assert.equal(oc.streams.size, 1, 'the desk still watches')
})

test('pairingsForPort uses the scheme\'s default port', () => {
  const P = [{ name: 'a', opencodeUrl: 'https://127.0.0.1' }, { name: 'b', opencodeUrl: 'http://127.0.0.1' }, { name: 'c' }]
  assert.deepEqual(pairingsForPort(P, 443).map((p) => p.name), ['a'])
  assert.deepEqual(pairingsForPort(P, 80).map((p) => p.name), ['b'])
  assert.deepEqual(pairingsForPort(P, 4096).map((p) => p.name), ['c'])
})
