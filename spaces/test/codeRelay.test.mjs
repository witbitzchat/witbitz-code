// The sealed wire between the Code section and the connector (spaces/public/codeRelay.js, docs/opencode-relay.md §3–§4).
// The VECTORS pin the derivation so a second implementation (the witbitz-code Python package) can prove it matches; they
// were cross-checked against an independent RFC 5869 HKDF in Python when written.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fakeRelay } from './fakeRelay.mjs'
import {
  deriveRelay, newRelaySecret, b64u, unb64u, makeSealer, makeOpener, peersOf, chunkMessage, makeReassembler,
  RelayPeer, allowedRequest, allowedEventPath, CHUNK,
} from '../public/codeRelay.js'

export const VECTORS = {
  secret: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', // bytes 0x00..0x1f
  channel: 'BKIqulmwCTX1BBrhuxWGIuqXw-lNfZiLKecQX_b351I',
  c2s: 'a85ab9bf21f9d47f0c6b5698e721cb29da068336e72b3e6f8dac7ec97b5994b7',
  s2c: '269f9541f33e3bd46c61a46d9462070de56f7392ebfa76dcb1aa2c954c6ff31d',
}

test('derivation matches the pinned vectors (channel + both direction keys)', async () => {
  const r = await deriveRelay(VECTORS.secret)
  assert.equal(r.channel, VECTORS.channel)
  assert.equal(r.channel.length, 43)
  // The keys are non-extractable; prove them by decrypting a frame sealed with the raw vector key.
  for (const [dir, hex] of [['c2s', VECTORS.c2s], ['s2c', VECTORS.s2c]]) {
    const raw = await crypto.subtle.importKey('raw', Buffer.from(hex, 'hex'), 'AES-GCM', false, ['encrypt'])
    const frame = await makeSealer(raw).seal({ t: 'probe', dir })
    assert.deepEqual(await makeOpener(r[dir]).open(frame), { t: 'probe', dir }, `${dir} is HKDF(S, "${dir === 'c2s' ? 'client-to-computer' : 'computer-to-client'}")`)
  }
})

test('a secret that is not 32 bytes is refused, and fresh secrets are 32 random bytes', async () => {
  await assert.rejects(deriveRelay(b64u(new Uint8Array(31))), /32 bytes/)
  const a = newRelaySecret(), b = newRelaySecret()
  assert.equal(unb64u(a).length, 32); assert.notEqual(a, b)
})

test('seal → open round-trips; the other direction, a tampered header or ciphertext, and junk all open to null', async () => {
  const { c2s, s2c } = await deriveRelay(VECTORS.secret)
  const sealer = makeSealer(c2s)
  const frame = await sealer.seal({ t: 'req', id: 'x', m: 'GET', p: '/agent' })
  assert.deepEqual(await makeOpener(c2s).open(frame), { t: 'req', id: 'x', m: 'GET', p: '/agent' })
  assert.equal(await makeOpener(s2c).open(frame), null, 'a frame reflected to its sender does not open')
  const f = JSON.parse(frame)
  assert.equal(await makeOpener(c2s).open(JSON.stringify({ ...f, q: f.q + 1 })), null, 'the sequence number is authenticated')
  assert.equal(await makeOpener(c2s).open(JSON.stringify({ ...f, s: b64u(new Uint8Array(12)) })), null, 'so is the sender id')
  const c = unb64u(f.c); c[0] ^= 1
  assert.equal(await makeOpener(c2s).open(JSON.stringify({ ...f, c: b64u(c) })), null, 'and the ciphertext')
  for (const junk of ['', 'not json', '{"t":"peers","n":2}', '{"v":2}', null]) assert.equal(await makeOpener(c2s).open(junk), null)
  assert.ok(!frame.includes('/agent'), 'nothing of the plaintext is visible on the wire')
})

test('replay: a frame opens once; an older sequence from the same sender is dropped; another sender is independent', async () => {
  const { c2s } = await deriveRelay(VECTORS.secret)
  const one = makeSealer(c2s), two = makeSealer(c2s)
  const f1 = await one.seal({ n: 1 }), f2 = await one.seal({ n: 2 }), g1 = await two.seal({ n: 'g' })
  const opener = makeOpener(c2s)
  assert.deepEqual(await opener.open(f2), { n: 2 })
  assert.equal(await opener.open(f2), null, 'the same frame twice')
  assert.equal(await opener.open(f1), null, 'an older frame after a newer one')
  assert.deepEqual(await opener.open(g1), { n: 'g' }, 'a second socket has its own counter')
})

test('a BURST sealed concurrently: every frame carries its own sequence number and every one opens', async () => {
  // The page fires several requests at once at boot. The counter used to be read after the encrypt await, so the whole
  // burst went out stamped with the last number — header ≠ AAD — and every frame was dropped.
  const { c2s } = await deriveRelay(VECTORS.secret)
  const sealer = makeSealer(c2s)
  const frames = await Promise.all(Array.from({ length: 8 }, (_, i) => sealer.seal({ n: i })))
  assert.deepEqual(frames.map((f) => JSON.parse(f).q).sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8])
  const opener = makeOpener(c2s)
  const opened = []
  for (const f of frames.sort((a, b) => JSON.parse(a).q - JSON.parse(b).q)) opened.push(await opener.open(f))
  assert.deepEqual(opened.map((m) => m && m.n), [0, 1, 2, 3, 4, 5, 6, 7])
})

test('peersOf reads only the relay count', () => {
  assert.equal(peersOf('{"t":"peers","n":3}'), 3)
  assert.equal(peersOf('{"v":1,"s":"x"}'), null)
  assert.equal(peersOf(null), null)
})

test('chunking splits a large body below the relay cap and reassembles it in any order; duplicates and junk are harmless', () => {
  const big = 'x'.repeat(CHUNK * 3 + 17)
  const parts = chunkMessage({ t: 'res', id: 'r1', st: 200, b: big })
  assert.equal(parts.length, 4)
  assert.ok(parts.every((p) => p.b.length <= CHUNK && p.of === 4 && p.st === 200))
  const r = makeReassembler()
  const order = [2, 0, 0, 3]
  for (const i of order) assert.equal(r.push(parts[i]), null)
  const whole = r.push(parts[1])
  assert.deepEqual(whole, { t: 'res', id: 'r1', st: 200, b: big })
  assert.deepEqual(chunkMessage({ t: 'res', id: 's', b: 'small' }), [{ t: 'res', id: 's', b: 'small' }])
  assert.deepEqual(r.push({ t: 'evts', d: [] }), { t: 'evts', d: [] }, 'an unchunked message passes straight through')
  assert.equal(r.push({ t: 'res', id: 'z', b: 'a', part: 5, of: 2 }), null, 'an impossible part is dropped')
})

test('reassembly refuses a message larger than the total cap', () => {
  const r = makeReassembler({ maxTotal: 10 })
  assert.equal(r.push({ t: 'res', id: 'a', b: '123456', part: 0, of: 2 }), null)
  assert.equal(r.push({ t: 'res', id: 'a', b: '789012', part: 1, of: 2 }), null)
})

test('the allowlist admits exactly the calls the Code section makes, and nothing that looks like them', () => {
  const yes = [
    ['GET', '/experimental/session?archived=true'], ['GET', '/agent'], ['GET', '/api/model'], ['GET', '/config'],
    ['POST', '/session'], ['GET', '/session/ses_abc123/message?directory=%2Fhome%2Fu'], ['POST', '/session/ses_abc/message'],
    ['POST', '/session/ses_abc/abort'], ['POST', '/session/ses_abc/permissions/per_1'], ['PATCH', '/session/ses_abc'],
    ['DELETE', '/session/ses_abc?directory=%2Fx'],
    // the New-session folder picker: the computer's home, and a folder listing (names only). Neither raises the
    // ceiling — a session the page can already create reads files with `read`/`list` allowed.
    ['GET', '/path'], ['GET', '/file?directory=%2Fhome%2Fu&path=witbitz'],
  ]
  for (const [m, p] of yes) assert.equal(allowedRequest(m, p), true, `${m} ${p}`)
  const no = [
    ['GET', '/event'], ['POST', '/session/ses_abc/shell'], ['POST', '/session/ses_abc/command'], ['GET', '/file/content?path=%2Fetc%2Fpasswd'],
    ['POST', '/file'], ['GET', '/file/status'], ['GET', '/path/x'],
    ['PUT', '/session/ses_abc'], ['GET', '/session/../config'], ['GET', '//agent'], ['GET', 'agent'], ['DELETE', '/session'],
    ['POST', '/session/ses_abc/permissions/per_1/extra'], ['GET', '/agent#x'],
  ]
  for (const [m, p] of no) assert.equal(allowedRequest(m, p), false, `${m} ${p}`)
  assert.equal(allowedEventPath('/event'), true)
  assert.equal(allowedEventPath('/event?directory=%2Fhome%2Fu'), true)
  assert.equal(allowedEventPath('/event?directory=x&other=1'), false)
  assert.equal(allowedEventPath('/session'), false)
})

// ── two peers through a fake relay with the real one's semantics (spaces/test/fakeRelay.mjs) ─────────────────────
const until = async (fn, ms = 3000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 15)) } return false }

test('RelayPeer: a client and a computer find each other, exchange sealed messages (chunked when big), and see the peer count', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  const secret = newRelaySecret()
  const atComputer = [], atClient = []
  const computer = new RelayPeer({ secret, role: 'computer', relay: relay.url(), onMessage: (m) => atComputer.push(m) })
  const client = new RelayPeer({ secret, role: 'client', relay: relay.url(), onMessage: (m) => atClient.push(m) })
  t.after(() => { computer.stop(); client.stop() })
  await computer.start(); await client.start()
  assert.ok(await until(() => computer.isOpen && client.isOpen && client.peers === 2 && computer.peers === 2), 'both open, both see 2')
  assert.equal(await client.send({ t: 'req', id: 'a', m: 'GET', p: '/agent' }), true)
  const big = 'y'.repeat(CHUNK * 2 + 5)
  assert.equal(await computer.send({ t: 'res', id: 'a', st: 200, b: big }), true)
  assert.ok(await until(() => atComputer.length === 1 && atClient.length === 1))
  assert.deepEqual(atComputer[0], { t: 'req', id: 'a', m: 'GET', p: '/agent' })
  assert.equal(atClient[0].b.length, big.length)
  assert.equal(relay.channels.size, 1, 'both dialled the same derived channel')
  assert.equal([...relay.channels.keys()][0], computer.channel)
})

test('RelayPeer: a peer with a different secret shares nothing, and reconnects after the relay drops it', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  const secret = newRelaySecret()
  const got = []
  const computer = new RelayPeer({ secret, role: 'computer', relay: relay.url(), minBackoff: 30, onMessage: (m) => got.push(m) })
  const stranger = new RelayPeer({ secret: newRelaySecret(), role: 'client', relay: relay.url() })
  t.after(() => { computer.stop(); stranger.stop() })
  await computer.start(); await stranger.start()
  assert.ok(await until(() => computer.isOpen && stranger.isOpen))
  assert.equal(relay.channels.size, 2, 'a different secret is a different channel')
  const states = []
  computer.onState = (s) => states.push(s)
  relay.dropAll()
  assert.ok(await until(() => computer.isOpen && states.includes('connecting')), `reconnected: ${states}`)
  const client = new RelayPeer({ secret, role: 'client', relay: relay.url() })
  t.after(() => client.stop())
  await client.start()
  assert.ok(await until(() => client.isOpen && client.peers === 2))
  await client.send({ t: 'req', id: 'after-reconnect' })
  assert.ok(await until(() => got.some((m) => m.id === 'after-reconnect')), 'a message after the reconnect is not taken for a replay')
})

test('RelayPeer: a burst of concurrent sends arrives complete and in order (sealing and opening never reorder frames)', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  const secret = newRelaySecret()
  const got = []
  const computer = new RelayPeer({ secret, role: 'computer', relay: relay.url(), onMessage: (m) => got.push(m.n) })
  const client = new RelayPeer({ secret, role: 'client', relay: relay.url() })
  t.after(() => { computer.stop(); client.stop() })
  await computer.start(); await client.start()
  assert.ok(await until(() => computer.isOpen && client.isOpen && client.peers === 2))
  // mixed sizes, so encryption of later frames can finish before earlier ones
  const sends = Array.from({ length: 20 }, (_, i) => client.send({ t: 'req', n: i, pad: 'x'.repeat(i % 3 === 0 ? 150_000 : 10) }))
  assert.ok((await Promise.all(sends)).every(Boolean))
  assert.ok(await until(() => got.length === 20), `all 20 arrived — got ${got.length}: ${got}`)
  assert.deepEqual(got, Array.from({ length: 20 }, (_, i) => i))
})

test('allowlist: a "." or ".." path segment never passes — fetch would collapse it onto a route that is not listed', () => {
  for (const [m, p] of [['POST', '/session/./message'], ['DELETE', '/session/.'], ['GET', '/session/../message'], ['PATCH', '/session/..'], ['POST', '/session/ses_1/permissions/.'], ['GET', '/session/.hidden/message']]) {
    assert.equal(allowedRequest(m, p), false, `${m} ${p}`)
  }
  assert.equal(allowedRequest('GET', '/session/ses.with.dots_1/message'), true, 'an id that merely contains dots is fine')
})

test('RelayPeer.kick() reconnects at once during a backoff wait (the page calls it when iOS brings it back)', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  const p = new RelayPeer({ secret: newRelaySecret(), role: 'client', relay: relay.url(), minBackoff: 60_000, maxBackoff: 60_000 })
  t.after(() => p.stop())
  await p.start()
  assert.ok(await until(() => p.isOpen))
  relay.dropAll()
  assert.ok(await until(() => !p.isOpen && p.state === 'connecting'), 'dropped, now waiting out a 60 s backoff')
  const t0 = Date.now()
  p.kick()
  assert.ok(await until(() => p.isOpen, 3000), 'kick() skipped the wait')
  assert.ok(Date.now() - t0 < 3000)
})

test('the opener reports a sender it forgets, so the owner can invalidate anything that sender could have sealed', async () => {
  const { c2s } = await deriveRelay(VECTORS.secret)
  const evicted = []
  const opener = makeOpener(c2s, { maxSenders: 2, onEvict: (s) => evicted.push(s) })
  const a = makeSealer(c2s), b = makeSealer(c2s), c = makeSealer(c2s)
  await opener.open(await a.seal({ n: 1 })); await opener.open(await b.seal({ n: 2 }))
  assert.deepEqual(evicted, [])
  await opener.open(await c.seal({ n: 3 }))
  assert.deepEqual(evicted, [a.sender], 'the oldest sender left the window — and said so')
})

test('RelayPeer: stop() during a backoff wait, start() again, kick() — still exactly one socket', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  let made = 0
  class Counting extends WebSocket { constructor(...a) { super(...a); made++ } }
  const p = new RelayPeer({ secret: newRelaySecret(), role: 'client', relay: relay.url(), WebSocketImpl: Counting, minBackoff: 60_000, maxBackoff: 60_000 })
  t.after(() => p.stop())
  await p.start()
  assert.ok(await until(() => p.isOpen))
  relay.dropAll()
  assert.ok(await until(() => p.state === 'connecting' && !p.isOpen))
  p.stop()
  await p.start() // dials once
  p.kick() // must not dial a second socket beside it
  assert.ok(await until(() => p.isOpen))
  await new Promise((r) => setTimeout(r, 200))
  assert.equal(made, 2, `one socket before the drop, one after — ${made} were created`)
  assert.equal([...relay.channels.values()][0].size, 1, 'no orphan left on the channel')
})

test('RelayPeer.start() twice opens one socket, not two', async (t) => {
  const relay = await fakeRelay()
  t.after(() => relay.close())
  let made = 0
  class Counting extends WebSocket { constructor(...a) { super(...a); made++ } }
  const p = new RelayPeer({ secret: newRelaySecret(), role: 'client', relay: relay.url(), WebSocketImpl: Counting })
  t.after(() => p.stop())
  await Promise.all([p.start(), p.start()])
  assert.ok(await until(() => p.isOpen))
  await new Promise((r) => setTimeout(r, 150))
  assert.equal(made, 1)
})

test('send() resolves false with no open socket', async () => {
  const p = new RelayPeer({ secret: newRelaySecret(), role: 'client', relay: 'ws://127.0.0.1:9' })
  assert.equal(await p.send({ t: 'req' }), false)
})
