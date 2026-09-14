// The connector beside OpenCode (tools/opencode-connector.mjs, docs/opencode-relay.md §4–§5), driven exactly as the Code
// page drives it: a client RelayPeer on a (fake) relay, against a fake OpenCode that checks the password.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { fakeRelay } from '../spaces/test/fakeRelay.mjs'
import { RelayPeer, newRelaySecret, CHUNK } from '../spaces/public/codeRelay.js'
import { LEAKY_PROVIDERS, LEAKY_CONFIG } from '../spaces/test/leakyOpenCode.mjs'
import { startConnector, parseEnvPassword, pairingsForPort, watchParent } from './opencode-connector.mjs'

const PASSWORD = 'local-only-password'
const until = async (fn, ms = 4000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 15)) } return false }

async function fakeOpenCode() {
  const seen = []
  const streams = new Set()
  const big = 'z'.repeat(CHUNK * 2 + 123)
  const rules = new Map() // session path → its permission rules (PATCH appends)
  const srv = createServer(async (req, res) => {
    let body = ''
    for await (const c of req) body += c
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization || '', body })
    const ok = req.headers.authorization === 'Basic ' + Buffer.from('opencode:' + PASSWORD).toString('base64')
    if (!ok) { res.writeHead(401); return res.end('unauthorized') }
    const json = (o, st = 200) => { res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)) }
    const path = req.url.split('?')[0]
    if (path === '/agent') return json([{ name: 'build' }])
    if (path === '/config/providers') return json(LEAKY_PROVIDERS)
    if (path === '/config') return json(LEAKY_CONFIG)
    if (path === '/session/ses_big/message') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(big) }
    if (path === '/session/ses_1/message' && req.method === 'POST') return json({ echoed: JSON.parse(body) })
    if (path === '/session/ses_nope' && req.method === 'GET') return json({ name: 'NotFoundError' }, 404) // measured shape aside, a 404
    // Notes sessions keep their rules like OpenCode does: PATCH APPENDS (measured, 1.18.30). A git project's session (its
    // path is the subfolder) and a plain folder's (path = directory without the leading "/", worktree "/").
    const notesSession = { ses_notes: { directory: '/home/u/repo/web', path: 'web' }, ses_plain: { directory: '/home/u/scratch', path: 'home/u/scratch' } }[path.split('/')[2]]
    if (notesSession && path.split('/').length === 3 && req.method === 'GET') return json({ id: path.split('/')[2], ...notesSession, permission: rules.get(path) || [] })
    if (notesSession && path.split('/').length === 3 && req.method === 'PATCH') { rules.set(path, [...(rules.get(path) || []), ...JSON.parse(body).permission]); return json({}) }
    if (notesSession && path.endsWith('/message') && req.method === 'POST') return json({ echoed: JSON.parse(body) })
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
    seen, big, streams, rules,
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
    flushMs: 40, log: () => {}, notesPluginPath: '/nonexistent/witbitz-notes.js', ...connectorOptions, // this computer's installed plugin must not change these tests
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

test('watchParent: a re-parented connector stops itself (its supervisor was killed with -9, so no trap ran)', async () => {
  let ppid = 4242, gone = 0
  const stop = watchParent({ parent: 4242, getPpid: () => ppid, onGone: () => gone++, everyMs: 10 })
  await new Promise((r) => setTimeout(r, 40))
  assert.equal(gone, 0, 'still under its parent')
  ppid = 1 // re-parented to init (or a subreaper)
  assert.ok(await until(() => gone === 1), 'noticed')
  await new Promise((r) => setTimeout(r, 40))
  assert.equal(gone, 1, 'once, not on every tick')
  stop()
  // no --parent (a connector started by hand) → no watch at all
  let called = false
  watchParent({ parent: 0, getPpid: () => 1, onGone: () => { called = true }, everyMs: 10 })()
  await new Promise((r) => setTimeout(r, 40))
  assert.equal(called, false)
})

test('the env file password is read the way a shell would read it', () => {
  assert.equal(parseEnvPassword('A=1\nOPENCODE_SERVER_PASSWORD=first\nexport OPENCODE_SERVER_PASSWORD="second"\n'), 'second')
  assert.equal(parseEnvPassword('X=1\n'), '')
  assert.equal(parseEnvPassword('A=1\r\nOPENCODE_SERVER_PASSWORD=crlf-pass\r\nB=2\r\n'), 'crlf-pass', 'a CRLF file (edited on Windows) still yields the password')
})

test('the computer says hello when a client arrives', async (t) => {
  const { got } = await rig(t)
  assert.ok(await until(() => got.some((m) => m.t === 'hello' && m.name === 'test-box' && m.computerId === 'cmp_test')), JSON.stringify(got))
})

test('the confidential proxy\'s progress reaches the phones, sealed (what a slow confidential model is doing)', async (t) => {
  const { got, connector } = await rig(t)
  connector.progress({ sessionID: 'ses_1', model: 'moonshotai/kimi-k3', label: 'Kimi K3', phase: 'writing', attempt: 1, tool: 'write', subject: '/home/u/a.md', chars: 1200 })
  assert.ok(await until(() => got.some((m) => m.t === 'progress' && m.phase === 'writing' && m.subject === '/home/u/a.md' && typeof m.ts === 'number')), JSON.stringify(got))
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

test('KEYS: /config and /config/providers reach the page without a single credential in them', async (t) => {
  const { call } = await rig(t)
  for (const p of ['/config', '/config/providers', '/config/providers?directory=%2Fhome%2Fu']) {
    const r = await call('GET', p)
    assert.equal(r.st, 200, p)
    assert.ok(!r.b.includes('SECRET'), `${p}: ${r.b}`)
  }
  const prov = JSON.parse((await call('GET', '/config/providers')).b)
  assert.deepEqual(prov.providers.map((x) => x.id), ['anthropic', 'trustedrouter'])
  assert.equal(prov.default.anthropic, 'claude-sonnet-4-6')
})

// ── attachments, the Claude Code way (docs/code-attachments.md) ──────────────────────────────────────────────────────
// Measured (opencode 1.18.30): OpenCode refuses an Excel or Word file part for every model; PATCH /session/:id APPENDS a
// permission rule to a session that already exists.
test('ATTACHMENTS: files in a message are saved on the computer and OpenCode gets a note — plus, once, the folder rule', async (t) => {
  const { mkdtempSync, existsSync, readFileSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const { parseAttachmentNote } = await import('../spaces/public/codeAttachments.js')
  const attachRoot = mkdtempSync(join(tmpdir(), 'wb-conn-att-'))
  const { call, oc, got } = await rig(t, { connectorOptions: { attachRoot, readTextFor: () => async () => '| Q3 | ZUCCHINI-771 |' } })
  assert.ok(got.filter((m) => m.t === 'hello').at(-1).caps.includes('attachments'), 'the page learns this connector saves files')
  const XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  const turn = { parts: [{ type: 'text', text: 'Q3?' }, { type: 'file', mime: XLSX, filename: 'budget.xlsx', url: `data:${XLSX};base64,${Buffer.from('PK-xlsx').toString('base64')}` }] }
  const r = await call('POST', '/session/ses_1/message?directory=%2Fw', turn)
  assert.equal(r.st, 200)
  const sent = JSON.parse(r.b).echoed
  assert.equal(sent.parts.some((p) => p.type === 'file'), false, 'no file part reaches OpenCode')
  const [entry] = parseAttachmentNote(sent.parts.at(-1).text)
  assert.equal(sent.parts.at(-1).synthetic, true)
  assert.equal(readFileSync(join(attachRoot, 'ses_1', entry.file), 'utf8'), 'PK-xlsx')
  assert.match(readFileSync(join(attachRoot, 'ses_1', entry.copy), 'utf8'), /ZUCCHINI-771/)
  const patches = () => oc.seen.filter((s) => s.method === 'PATCH' && s.url.startsWith('/session/ses_1'))
  assert.equal(patches().length, 1)
  assert.deepEqual(JSON.parse(patches()[0].body), { permission: [{ permission: 'external_directory', pattern: `${attachRoot}/ses_1/*`, action: 'allow' }] })
  assert.match(patches()[0].url, /directory=%2Fw/, 'scoped to the session\'s project like every other call')
  await call('POST', '/session/ses_1/message?directory=%2Fw', turn)
  assert.equal(patches().length, 1, 'the rule is added once per session')

  // the page gets the file back from the connector itself — OpenCode never sees the route
  const back = await call('GET', `/witbitz/attachment?session=ses_1&file=${encodeURIComponent(entry.file)}`)
  assert.equal(back.st, 200)
  assert.equal(Buffer.from(JSON.parse(back.b).b64, 'base64').toString(), 'PK-xlsx')
  assert.equal((await call('GET', '/witbitz/attachment?session=ses_1&file=..%2F..%2Fpairings.json')).st, 400)
  assert.equal(oc.seen.some((s) => s.url.startsWith('/witbitz')), false)

  // deleting the session takes its files along
  assert.equal((await call('DELETE', '/session/ses_1?directory=%2Fw')).st, 200)
  assert.ok(await until(() => !existsSync(join(attachRoot, 'ses_1'))), 'the session folder is gone')
})

test('ATTACHMENTS: a turn for a session OpenCode does not have saves nothing (an invented id must not get a folder)', async (t) => {
  const { mkdtempSync, readdirSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const attachRoot = mkdtempSync(join(tmpdir(), 'wb-conn-att-'))
  const { call, oc } = await rig(t, { connectorOptions: { attachRoot } })
  const r = await call('POST', '/session/ses_nope/message', { parts: [{ type: 'file', mime: 'text/plain', filename: 'a.txt', url: `data:text/plain;base64,${Buffer.from('x').toString('base64')}` }] })
  assert.equal(r.st, 404)
  assert.deepEqual(readdirSync(attachRoot), [])
  assert.equal(oc.seen.some((s) => s.url.startsWith('/session/ses_nope/message')), false)
})

test('ATTACHMENTS: a file over the limit refuses the turn with a reason, and OpenCode never gets it', async (t) => {
  const { mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const { call, oc } = await rig(t, { connectorOptions: { attachRoot: mkdtempSync(join(tmpdir(), 'wb-conn-att-')), attachMaxFileBytes: 4 } })
  const r = await call('POST', '/session/ses_1/message', { parts: [{ type: 'file', mime: 'text/plain', filename: 'notes.txt', url: `data:text/plain;base64,${Buffer.from('too long').toString('base64')}` }] })
  assert.equal(r.st, 413)
  assert.match(JSON.parse(r.b).error, /notes\.txt is over/)
  assert.equal(oc.seen.some((s) => s.url.startsWith('/session/ses_1/message')), false)
})

// ── project notes (tools/opencode-plugins/witbitz-notes.js) ─────────────────────────────────────────────────────────
// Notes writes asked FOUR times per note (external_directory + edit, for the note and its INDEX.md) — measured 2026-09-14,
// and a model that already writes notes reluctantly gave up. Now: writes into notes/ ask nothing; confidential/ follows the
// TURN's model (allowed for a confidential model, asked for any other, so a regular model still cannot read confidential
// notes unasked); AGENTS.md — injected as INSTRUCTIONS — still asks. The edit pattern is relative to the project's worktree:
// the git root for a git project, "/" for a plain folder (measured: "../notes/notes/a.md" vs "tmp/…/notes/a.md").
async function notesRig(t) {
  const { mkdtempSync, writeFileSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const dir = mkdtempSync(join(tmpdir(), 'wb-conn-notes-'))
  writeFileSync(join(dir, 'witbitz-notes.js'), '// installed')
  writeFileSync(join(dir, 'confidential.json'), JSON.stringify(['trustedrouter/deepseek/deepseek-v4-flash']))
  return rig(t, { connectorOptions: { notesRoot: '/n', notesPluginPath: join(dir, 'witbitz-notes.js'), notesConfidentialList: join(dir, 'confidential.json') } })
}
const keyOf = async (root) => { const { createHash } = await import('node:crypto'); const b = root.split('/').pop(); return `${b}-${createHash('sha1').update(root).digest('hex').slice(0, 8)}` }
const effective = (rules, permission, pattern) => { let a = null; for (const r of rules) if (r.permission === permission && r.pattern === pattern) a = r.action; return a }
const CONF = { providerID: 'trustedrouter', modelID: 'deepseek/deepseek-v4-flash' }
const PLAIN = { providerID: 'trustedrouter', modelID: 'x-ai/grok-4.6' }

test('NOTES: writes into the project\'s notes folder ask nothing; confidential notes follow the turn\'s model; AGENTS.md still asks', async (t) => {
  const { call, oc } = await notesRig(t)
  const key = await keyOf('/home/u/repo')
  const rel = `../../../n/${key}` // from the git root /home/u/repo
  const rulesNow = async () => oc.rules.get('/session/ses_notes') || []
  await call('POST', '/session/ses_notes/message?directory=%2Fhome%2Fu%2Frepo%2Fweb', { model: PLAIN, parts: [{ type: 'text', text: 'hi' }] })
  let r = await rulesNow()
  assert.equal(effective(r, 'external_directory', `/n/${key}/*`), 'allow', 'reads of the notes folder')
  assert.equal(effective(r, 'edit', `${rel}/notes/*`), 'allow', 'writes into notes/')
  assert.equal(effective(r, 'external_directory', `/n/${key}/confidential/*`), 'ask', 'a regular model: confidential notes ask')
  assert.equal(effective(r, 'edit', `${rel}/confidential/*`), 'ask')
  assert.ok(!r.some((x) => x.permission === 'edit' && x.action === 'allow' && /AGENTS\.md|\/\*$/.test(x.pattern) && !/\/(notes|confidential)\/\*$/.test(x.pattern)), 'nothing allows AGENTS.md')
  const patchesBefore = oc.seen.filter((s) => s.method === 'PATCH').length
  await call('POST', '/session/ses_notes/message?directory=%2Fhome%2Fu%2Frepo%2Fweb', { model: PLAIN, parts: [{ type: 'text', text: 'again' }] })
  assert.equal(oc.seen.filter((s) => s.method === 'PATCH').length, patchesBefore, 'nothing changed — nothing is sent')
  await call('POST', '/session/ses_notes/message?directory=%2Fhome%2Fu%2Frepo%2Fweb', { model: CONF, parts: [{ type: 'text', text: 'confidential now' }] })
  r = await rulesNow()
  assert.equal(effective(r, 'external_directory', `/n/${key}/confidential/*`), 'allow', 'a confidential model: its notes ask nothing')
  assert.equal(effective(r, 'edit', `${rel}/confidential/*`), 'allow')
  // …and it cannot put them in notes/, which regular models read: the owner's Witbitz 1 did, when asked for "project notes"
  assert.equal(effective(r, 'edit', `${rel}/notes/*`), 'deny', 'a confidential turn writes confidential/ only')
  await call('POST', '/session/ses_notes/message?directory=%2Fhome%2Fu%2Frepo%2Fweb', { model: PLAIN, parts: [{ type: 'text', text: 'back to a regular model' }] })
  r = await rulesNow()
  assert.equal(effective(r, 'external_directory', `/n/${key}/confidential/*`), 'ask', 'closed again for a regular model')
  assert.equal(effective(r, 'edit', `${rel}/confidential/*`), 'ask')
  assert.equal(effective(r, 'edit', `${rel}/notes/*`), 'allow', 'and notes/ is its folder again')
  const lastConfidentialRead = r.map((x) => x.pattern).lastIndexOf(`/n/${key}/confidential/*`)
  assert.ok(lastConfidentialRead > r.map((x) => x.pattern).lastIndexOf(`/n/${key}/*`), 'the confidential rule stays AFTER the folder allow — last match wins')
})

test('NOTES: a plain folder\'s edit rule is relative to "/", and a turn with no model keeps confidential notes closed', async (t) => {
  const { call, oc } = await notesRig(t)
  const key = await keyOf('/home/u/scratch')
  await call('POST', '/session/ses_plain/message?directory=%2Fhome%2Fu%2Fscratch', { parts: [{ type: 'text', text: 'hi' }] })
  const r = oc.rules.get('/session/ses_plain') || []
  assert.equal(effective(r, 'edit', `n/${key}/notes/*`), 'allow', 'relative to the worktree "/" — no leading slash')
  assert.equal(effective(r, 'external_directory', `/n/${key}/confidential/*`), 'ask', 'unknown model → closed')
})

test('NOTES: without the plugin installed the connector adds nothing', async (t) => {
  const { call, oc } = await rig(t, { connectorOptions: { notesRoot: '/n', notesPluginPath: '/nonexistent/witbitz-notes.js' } })
  await call('POST', '/session/ses_notes/message', { parts: [{ type: 'text', text: 'hi' }] })
  assert.equal(oc.seen.some((s) => s.method === 'PATCH' || (s.method === 'GET' && s.url.split('?')[0] === '/session/ses_notes')), false)
})
