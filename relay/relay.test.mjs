// The sealed relay, run in the real Workers runtime (Miniflare/workerd) — the Durable Object, hibernatable sockets and
// all. Hardening for the Code section (docs/opencode-relay.md §6): a strict channel id, an Origin allowlist for browsers,
// a socket cap per channel, a per-socket rate limit, a size cap, and a peer count that never counts a socket that left.
//
//   node --test relay/relay.test.mjs          (needs miniflare; looked up in MINIFLARE_PATH, this repo, then ~/kibitz)
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'

const HERE = dirname(fileURLToPath(import.meta.url))
let Miniflare = null
for (const base of [process.env.MINIFLARE_PATH, join(HERE, '..'), join(homedir(), 'kibitz')].filter(Boolean)) {
  const pkg = join(base, 'node_modules', 'miniflare', 'package.json')
  if (!existsSync(pkg)) continue
  try { ({ Miniflare } = createRequire(pkg)('miniflare')); break } catch { /* try the next */ }
}
const skip = !Miniflare && 'miniflare not installed'

const CH = 'A'.repeat(43) // a channel id is exactly 43 base64url chars — HKDF-SHA256 output, base64url, unpadded
const APP = 'https://app.witbitz.chat'
let mf

before(async () => {
  if (skip) return
  mf = new Miniflare({
    modules: true,
    scriptPath: join(HERE, 'relay.mjs'),
    compatibilityDate: '2024-11-01',
    durableObjects: { RELAY: { className: 'Relay', useSQLite: true } },
  })
  await mf.ready
})
after(async () => { if (mf) await mf.dispose() })

/** Open a socket; collect everything it receives (text) and how it closed. */
async function connect(channel = CH, { origin = APP } = {}) {
  const headers = { Upgrade: 'websocket' }
  if (origin) headers.Origin = origin
  const res = await mf.dispatchFetch(`https://code-relay.witbitz.chat/c/${channel}`, { headers })
  if (res.status !== 101) return { status: res.status, text: await res.text() }
  const ws = res.webSocket
  const got = []
  const closed = new Promise((resolve) => ws.addEventListener('close', (e) => resolve({ code: e.code })))
  ws.addEventListener('message', (e) => got.push(typeof e.data === 'string' ? e.data : '[binary]'))
  ws.accept()
  return { status: 101, ws, got, closed, data: () => got.filter((m) => !m.startsWith('{"t":"peers"')), peers: () => got.filter((m) => m.startsWith('{"t":"peers"')).map((m) => JSON.parse(m).n) }
}
const until = async (fn, ms = 3000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 20)) } return false }

test('health answers', { skip }, async () => {
  const r = await mf.dispatchFetch('https://code-relay.witbitz.chat/health')
  assert.equal(r.status, 200)
})

test('a channel id is exactly 43 base64url characters — anything else is not a channel', { skip }, async () => {
  for (const bad of ['A'.repeat(42), 'A'.repeat(44), 'A'.repeat(42) + '=', 'A'.repeat(42) + '/', '']) {
    const r = await connect(bad)
    assert.equal(r.status, 404, `"${bad}" must not open a channel`)
  }
  const ok = await connect('Zz09_-' + 'x'.repeat(37))
  assert.equal(ok.status, 101)
  ok.ws.close()
})

test('a plain GET on a channel is refused (it is only a websocket)', { skip }, async () => {
  const r = await mf.dispatchFetch(`https://code-relay.witbitz.chat/c/${CH}`)
  assert.equal(r.status, 426)
})

test('browsers must come from a witbitz origin; a socket with no Origin (the connector) is allowed', { skip }, async () => {
  const evil = await connect('B'.repeat(43), { origin: 'https://evil.example' })
  assert.equal(evil.status, 403)
  const app = await connect('B'.repeat(43), { origin: APP })
  assert.equal(app.status, 101)
  const node = await connect('B'.repeat(43), { origin: null })
  assert.equal(node.status, 101)
  app.ws.close(); node.ws.close()
})

test('a message goes to every OTHER socket on the channel, verbatim, and to nobody elsewhere', { skip }, async () => {
  const ch = 'C'.repeat(43)
  const a = await connect(ch), b = await connect(ch), c = await connect(ch), stranger = await connect('D'.repeat(43))
  a.ws.send('sealed-bytes-1')
  assert.ok(await until(() => b.data().length && c.data().length), 'both peers receive it')
  assert.deepEqual(b.data(), ['sealed-bytes-1'])
  assert.deepEqual(c.data(), ['sealed-bytes-1'])
  await new Promise((r) => setTimeout(r, 150))
  assert.deepEqual(a.data(), [], 'never echoed to the sender')
  assert.deepEqual(stranger.data(), [], 'never crosses channels')
  for (const s of [a, b, c, stranger]) s.ws.close()
})

test('the peer count is announced on join AND leave, and never counts the socket that left', { skip }, async () => {
  const ch = 'E'.repeat(43)
  const a = await connect(ch)
  const b = await connect(ch)
  assert.ok(await until(() => a.peers().includes(2)), `a hears 2 when b joins: ${a.peers()}`)
  b.ws.close(1000)
  assert.ok(await until(() => a.peers().at(-1) === 1), `after b leaves a hears 1 — got ${a.peers()}`)
  a.ws.close()
})

test('a channel holds at most 16 sockets; the 17th is refused', { skip }, async () => {
  const ch = 'F'.repeat(43)
  const socks = []
  for (let i = 0; i < 16; i++) { const s = await connect(ch); assert.equal(s.status, 101, `socket ${i + 1}`); socks.push(s) }
  const extra = await connect(ch)
  assert.equal(extra.status, 429)
  for (const s of socks) s.ws.close()
})

test('a socket that floods (more than 200 messages in 10 s) is closed with 1008, and the flood stops there', { skip }, async () => {
  const ch = 'G'.repeat(43)
  const spam = await connect(ch), victim = await connect(ch)
  for (let i = 0; i < 260; i++) { try { spam.ws.send('m' + i) } catch { break } }
  const how = await Promise.race([spam.closed, new Promise((r) => setTimeout(() => r({ code: 'timeout' }), 4000))])
  assert.equal(how.code, 1008)
  await new Promise((r) => setTimeout(r, 200))
  assert.ok(victim.data().length <= 200, `the peer got at most 200 — got ${victim.data().length}`)
  victim.ws.close()
})

test('a single message over 1 MiB closes the sender with 1009 and is not forwarded', { skip }, async () => {
  const ch = 'H'.repeat(43)
  const big = await connect(ch), peer = await connect(ch)
  big.ws.send('x'.repeat(1024 * 1024 + 1))
  const how = await Promise.race([big.closed, new Promise((r) => setTimeout(() => r({ code: 'timeout' }), 4000))])
  assert.equal(how.code, 1009)
  await new Promise((r) => setTimeout(r, 150))
  assert.deepEqual(peer.data(), [])
  peer.ws.close()
})

// The heartbeat (spaces/public/codeRelay.js RELAY_PING): measured 2026-09-14, a connector's socket went dead after a network
// blip yet stayed "open" for 10+ minutes, and phones found a computer that never answered. The relay answers the ping itself.
test('the relay answers {"t":"relay-ping"} to the sender alone — not broadcast, not counted as the sender\'s traffic', { skip }, async () => {
  const ch = 'I'.repeat(43)
  const a = await connect(ch), b = await connect(ch)
  for (let i = 0; i < 250; i++) a.ws.send('{"t":"relay-ping"}') // more than the rate limit: auto-answers are not counted
  assert.ok(await until(() => a.data().filter((m) => m === '{"t":"relay-pong"}').length === 250), `a got every pong — got ${a.data().length}`)
  await new Promise((r) => setTimeout(r, 150))
  assert.deepEqual(b.data(), [], 'the other socket hears nothing of it')
  a.ws.send('sealed-after')
  assert.ok(await until(() => b.data().includes('sealed-after')), 'and the pinging socket was not closed by the rate limit')
  a.ws.close(); b.ws.close()
})
