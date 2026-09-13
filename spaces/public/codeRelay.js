// codeRelay.js — the sealed wire between the Code section and the connector on your computer (docs/opencode-relay.md).
//
// ONE module for both ends: the page imports it in the browser, tools/opencode-connector.mjs imports it in Node ≥ 22.
// Pure WebCrypto + the global WebSocket, so the two ends cannot drift. The Python package (witbitz-code) is held to it
// by the vectors in spaces/test/codeRelay.test.mjs.
//
//   secret S (32 bytes, per computer × account pairing)
//     ├─ channel = b64url(HKDF(S, "channel"))        → wss://code-relay.witbitz.chat/c/<channel>   (the relay's routing key)
//     ├─ kC2S    = HKDF(S, "client-to-computer")     → AES-256-GCM, page → computer
//     └─ kS2C    = HKDF(S, "computer-to-client")     → AES-256-GCM, computer → page
//
// A frame on the socket:  {"v":1,"s":<sender id>,"q":<seq>,"n":<iv>,"c":<ciphertext>}  — AAD "wbcr1|v|s|q", so the clear
// header is authenticated; receivers drop any q ≤ the last one seen from that sender (replay).

export const RELAY_URL = 'wss://code-relay.witbitz.chat'
const SALT = 'witbitz-code-relay-v1'
const te = new TextEncoder()
const td = new TextDecoder()

// ── base64url ────────────────────────────────────────────────────────────────────────────────────────────────────
export function b64u(bytes) {
  let s = ''
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000))
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
export function unb64u(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** A new pairing secret: 32 random bytes, base64url. */
export const newRelaySecret = () => b64u(crypto.getRandomValues(new Uint8Array(32)))

// ── keys ─────────────────────────────────────────────────────────────────────────────────────────────────────────
/** Secret → { channel, c2s, s2c }. Throws on a secret that is not 32 bytes (a truncated copy must fail loudly). */
export async function deriveRelay(secret) {
  const raw = unb64u(secret)
  if (raw.length !== 32) throw new Error('relay secret must be 32 bytes')
  const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits', 'deriveKey'])
  const params = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(SALT), info: te.encode(info) })
  const channel = b64u(await crypto.subtle.deriveBits(params('channel'), base, 256))
  const key = (info) => crypto.subtle.deriveKey(params(info), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  return { channel, c2s: await key('client-to-computer'), s2c: await key('computer-to-client') }
}

// ── frames ───────────────────────────────────────────────────────────────────────────────────────────────────────
const aadOf = (v, s, q) => te.encode(`wbcr1|${v}|${s}|${q}`)

/** A sealer for ONE socket: its own random sender id and a counter. */
export function makeSealer(key) {
  const s = b64u(crypto.getRandomValues(new Uint8Array(12)))
  let q = 0
  return {
    sender: s,
    async seal(msg) {
      // ★ Take the sequence number BEFORE the await. Reading the shared counter after encrypt() stamped every frame of a
      //   concurrent burst with the LAST number — the page fires several requests at boot — so the header no longer
      //   matched the AAD it was sealed with, and the connector dropped them all.
      const seq = ++q
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadOf(1, s, seq) }, key, te.encode(JSON.stringify(msg)))
      return JSON.stringify({ v: 1, s, q: seq, n: b64u(iv), c: b64u(ct) })
    },
  }
}

/** An opener: the other direction's key + a replay window per sender. Returns the message object, or null for anything
 *  that is not a valid, fresh frame for this key (junk, the relay's own control frames, the wrong key, a replay). */
export function makeOpener(key, { maxSenders = 64, onEvict = () => {} } = {}) {
  const last = new Map() // sender → highest q accepted
  return {
    async open(text) {
      let f
      try { f = typeof text === 'string' ? JSON.parse(text) : null } catch { return null }
      if (!f || f.v !== 1 || typeof f.s !== 'string' || !Number.isSafeInteger(f.q) || f.q < 1 || typeof f.n !== 'string' || typeof f.c !== 'string') return null
      if (f.q <= (last.get(f.s) || 0)) return null
      let pt
      try { pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(f.n), additionalData: aadOf(f.v, f.s, f.q) }, key, unb64u(f.c)) } catch { return null }
      // Re-check after the await: two frames from one sender can race through decrypt.
      if (f.q <= (last.get(f.s) || 0)) return null
      last.delete(f.s); last.set(f.s, f.q)
      // A sender pushed out of the window could have its recorded frames replayed from now on — so say so: the connector
      // rotates its nonce, which voids every request that sender ever sealed (review finding, round 2).
      if (last.size > maxSenders) { const gone = last.keys().next().value; last.delete(gone); try { onEvict(gone) } catch { /* */ } }
      try { return JSON.parse(td.decode(pt)) } catch { return null }
    },
  }
}

/** Is this socket message the relay's own unsealed peer count? → n, else null. */
export function peersOf(text) {
  if (typeof text !== 'string' || !text.startsWith('{"t":"peers"')) return null
  try { const m = JSON.parse(text); return Number.isInteger(m.n) ? m.n : null } catch { return null }
}

// ── chunking ─────────────────────────────────────────────────────────────────────────────────────────────────────
// Cloudflare caps a WebSocket message at 1 MiB; a sealed frame is ~4/3 of its plaintext. Bodies are split well below.
export const CHUNK = 192 * 1024
export const MAX_TOTAL = 32 * 1024 * 1024

/** A message whose string field `b` is large → parts {…msg, b: slice, part: i, of: n}; small → [msg]. */
export function chunkMessage(msg, size = CHUNK) {
  if (typeof msg.b !== 'string' || msg.b.length <= size) return [msg]
  const of = Math.ceil(msg.b.length / size)
  const parts = []
  for (let i = 0; i < of; i++) parts.push({ ...msg, b: msg.b.slice(i * size, (i + 1) * size), part: i, of })
  return parts
}

/** Collects parts by (t, id). push(msg) → the whole message once complete, the message itself if unchunked, else null. */
export function makeReassembler({ timeoutMs = 60_000, maxTotal = MAX_TOTAL } = {}) {
  const open = new Map()
  return {
    push(msg) {
      if (!msg || msg.of === undefined) return msg
      const { of, part } = msg
      if (!Number.isInteger(of) || of < 1 || !Number.isInteger(part) || part < 0 || part >= of || typeof msg.b !== 'string') return null
      const k = `${msg.t}:${msg.id}`
      const now = Date.now()
      for (const [key, e] of open) if (now - e.at > timeoutMs) open.delete(key)
      let e = open.get(k)
      if (!e) { e = { parts: new Array(of), got: 0, size: 0, at: now }; open.set(k, e) }
      if (e.parts.length !== of) { open.delete(k); return null }
      if (e.parts[part] === undefined) { e.parts[part] = msg.b; e.got++; e.size += msg.b.length }
      if (e.size > maxTotal) { open.delete(k); return null }
      if (e.got < of) return null
      open.delete(k)
      const whole = { ...msg, b: e.parts.join('') }
      delete whole.part; delete whole.of
      return whole
    },
  }
}

// ── the socket ───────────────────────────────────────────────────────────────────────────────────────────────────
/**
 * One end of a channel, with reconnect. role 'client' (the page) seals with c2s and opens s2c; 'computer' the reverse.
 *   const peer = new RelayPeer({ secret, role: 'client', onMessage, onPeers, onState })
 *   peer.start(); await peer.send({ t: 'req', … }); peer.stop()
 * A fresh sealer (new sender id, q from 1) per socket, so a reconnect is never mistaken for a replay.
 */
export class RelayPeer {
  constructor({ secret, role, relay = RELAY_URL, WebSocketImpl = globalThis.WebSocket, onMessage = () => {}, onPeers = () => {}, onState = () => {}, onEvict = () => {}, maxSenders = 64, minBackoff = 500, maxBackoff = 15_000 }) {
    if (role !== 'client' && role !== 'computer') throw new Error('role must be client or computer')
    Object.assign(this, { secret, role, relay: String(relay).replace(/\/+$/, ''), WebSocketImpl, onMessage, onPeers, onState, onEvict, maxSenders, minBackoff, maxBackoff })
    this.peers = 0
    this.state = 'idle' // idle | connecting | open | closed
    this.ws = null
    this.backoff = minBackoff
    this.timer = 0
    this.stopped = true
    this.reasm = makeReassembler()
    this.keys = null
    // ★ ONE AT A TIME, BOTH WAYS. Receivers drop a frame whose sequence is not above the last one opened (replay), so a
    //   frame must reach the socket in the order it was numbered and be opened in the order it arrived. Concurrent
    //   seal/open awaits reorder them — measured: a burst of 20 lost the 4 large frames, which finished encrypting last.
    this.sendChain = Promise.resolve()
    this.recvChain = Promise.resolve()
  }

  async start() {
    if (!this.stopped) return // already started (or starting): a second call must not dial a second socket
    this.stopped = false
    if (!this.keys) this.keys = await deriveRelay(this.secret)
    this.connect()
  }

  stop() {
    this.stopped = true
    clearTimeout(this.timer)
    this.waiting = false // a stop during a backoff wait must not leave kick() believing a wait is pending (it dialled a 2nd socket)
    try { if (this.ws) this.ws.close(1000) } catch { /* */ }
    this.ws = null
    this.setState('closed')
  }

  /** Reconnect now (e.g. the page became visible again) instead of waiting out the backoff. */
  kick() {
    // ★ `connecting` covers two situations: a socket actually dialling (leave it) and a backoff WAIT (skip it). Treating
    //   both alike made kick() a no-op exactly when it matters — iOS bringing the page back after killing its socket.
    if (this.stopped || this.state === 'open' || (this.state === 'connecting' && !this.waiting)) return
    clearTimeout(this.timer); this.waiting = false; this.backoff = this.minBackoff; this.connect()
  }
  /** Drop the current socket and dial again now — for a socket that is "open" but has gone silent (a dead network path). */
  reconnect() {
    if (this.stopped) return
    const ws = this.ws
    this.ws = null
    try { if (ws) ws.close(4000, 'silent') } catch { /* */ }
    this.peers = 0
    clearTimeout(this.timer); this.waiting = false; this.backoff = this.minBackoff
    this.connect()
  }

  get channel() { return this.keys && this.keys.channel }
  get isOpen() { return this.state === 'open' }

  setState(s) { if (this.state !== s) { this.state = s; try { this.onState(s) } catch { /* */ } } }

  connect() {
    if (this.stopped) return
    const { c2s, s2c, channel } = this.keys
    const sealer = makeSealer(this.role === 'client' ? c2s : s2c)
    const opener = makeOpener(this.role === 'client' ? s2c : c2s, { maxSenders: this.maxSenders, onEvict: (s) => this.onEvict(s) })
    let ws
    try { ws = new this.WebSocketImpl(`${this.relay}/c/${channel}`) } catch { this.retry(); return }
    this.ws = ws
    this.sealer = sealer
    this.setState('connecting')
    ws.onopen = () => { if (this.ws !== ws) return; this.backoff = this.minBackoff; this.setState('open') }
    ws.onmessage = (e) => {
      this.recvChain = this.recvChain.then(async () => {
        if (this.ws !== ws) return
        const text = typeof e.data === 'string' ? e.data : null
        const n = peersOf(text)
        if (n !== null) { this.peers = n; try { this.onPeers(n) } catch { /* */ } return }
        const msg = this.reasm.push(await opener.open(text))
        if (msg) { try { this.onMessage(msg) } catch { /* a handler bug must not kill the socket */ } }
      }).catch(() => {})
    }
    ws.onclose = () => { if (this.ws !== ws) return; this.ws = null; this.peers = 0; try { this.onPeers(0) } catch { /* */ } this.retry() }
    ws.onerror = () => { try { ws.close() } catch { /* */ } }
  }

  retry() {
    if (this.stopped) return
    this.setState('connecting')
    clearTimeout(this.timer)
    const wait = this.backoff
    this.backoff = Math.min(this.maxBackoff, this.backoff * 2)
    this.waiting = true
    this.timer = setTimeout(() => { this.waiting = false; this.connect() }, wait)
  }

  /** Seal and send (chunked if large). Resolves false when there is no open socket — the caller decides what that means. */
  send(msg) {
    const run = async () => {
      const ws = this.ws
      if (!ws || this.state !== 'open') return false
      const sealer = this.sealer
      for (const part of chunkMessage(msg)) {
        const frame = await sealer.seal(part)
        if (this.ws !== ws) return false
        try { ws.send(frame) } catch { return false }
      }
      return true
    }
    const p = this.sendChain.then(run, run)
    this.sendChain = p.catch(() => false)
    return p
  }
}

// ── what the connector serves ────────────────────────────────────────────────────────────────────────────────────
// Only the calls the Code section makes (opencodeApp.js). OpenCode can run shell commands on the computer; a leaked
// secret must not unlock more than the page itself can do. Paths carry their query string (?directory=…).
// A segment may contain dots but never START with one: '.' and '..' would be collapsed by fetch onto a route that is not
// on this list (review finding: `DELETE /session/.` passed).
const SEG = '(?!\\.)[A-Za-z0-9_.-]{1,128}'
const ALLOW = [
  ['GET', '/experimental/session'],
  ['GET', '/agent'],
  ['GET', '/api/model'],
  ['GET', '/config'],           // answered through projectResponse — never as OpenCode sent it
  ['GET', '/config/providers'], // the model menu: what is CONNECTED on this computer (projectResponse, no keys)
  ['POST', '/session'],
  ['GET', `/session/${SEG}/message`],
  ['POST', `/session/${SEG}/message`],
  ['POST', `/session/${SEG}/abort`],
  ['POST', `/session/${SEG}/permissions/${SEG}`],
  ['PATCH', `/session/${SEG}`],
  ['DELETE', `/session/${SEG}`],
  // New session's folder picker: the computer's home, and folder listings under it (names, never contents). Neither
  // raises the ceiling — a session the page can already create reads files with `read`/`list` allowed.
  ['GET', '/path'],
  ['GET', '/file'],
  // The agent's question tool: what is pending, and the answer or the dismissal. Inside the agent loop — answering a
  // question grants nothing; the turn it resumes is still held to the session's permission prompts.
  // The "/" menu READS commands and skills. Running one is an ordinary message the page builds (codeCommands.js):
  // POST /session/:id/command runs !`…` from its arguments in a shell, unprompted — it must never be on this list.
  ['GET', '/command'],
  ['GET', `/session/${SEG}/todo`], // the agent's todo list, as it stands
  ['GET', '/question'],
  ['POST', `/question/${SEG}/reply`],
  ['POST', `/question/${SEG}/reject`],
  // /undo /redo /compact. Undo puts the session's files back to a snapshot OpenCode took before the turn; redo puts them
  // forward again; compact asks the model to summarize. None runs anything the session's permission prompts do not hold.
  ['POST', `/session/${SEG}/revert`],
  ['POST', `/session/${SEG}/unrevert`],
  ['POST', `/session/${SEG}/summarize`],
].map(([m, p]) => [m, new RegExp(`^${p}$`)])

/** Is `method path?query` something the connector will forward? The event stream is NOT here: it is `sub`, not a req. */
export function allowedRequest(method, pathWithQuery) {
  const m = String(method || '').toUpperCase()
  const p = String(pathWithQuery || '')
  if (!p.startsWith('/') || p.includes('..') || p.includes('//') || p.includes('#')) return false
  const path = p.split('?')[0]
  return ALLOW.some(([am, re]) => am === m && re.test(path))
}

/** The event-stream path a `sub` may name: /event, optionally ?directory=… (and nothing else). */
export function allowedEventPath(p) {
  const s = String(p || '')
  if (s === '/event') return true
  const m = s.match(/^\/event\?directory=([^&#]*)$/)
  return !!m
}

// ── what the connector gives back ────────────────────────────────────────────────────────────────────────────────
// Two routes the page needs answer with SECRETS in them, measured on opencode 1.18:
//   • GET /config resolves every `{env:…}` in the provider options — the owner's TrustedRouter key came back in plain text.
//   • GET /config/providers carries each connected provider's stored API key in `key` (from `opencode auth login`).
// The page needs names, not credentials, and the key must never leave the computer. So the connector does not pass these
// answers through: it rebuilds them from an ALLOWLIST of fields (a blocklist would miss the next field OpenCode adds).
// Anything that does not parse, or is not a success, goes back as a plain error — never the raw body.
const PROJECTED = new Set(['/config', '/config/providers'])
const MAX_PROVIDERS = 100, MAX_MODELS = 2000
const s200 = (v) => (typeof v === 'string' ? v.slice(0, 200) : undefined)
const dict = () => Object.create(null) // a model named "__proto__" is a key like any other
const MEDIA = ['text', 'image', 'pdf', 'audio', 'video']
function projectInput(caps) {
  const input = caps && typeof caps === 'object' ? caps.input : null
  if (Array.isArray(input)) return MEDIA.filter((k) => input.includes(k))
  if (input && typeof input === 'object') return MEDIA.filter((k) => input[k] === true)
  return undefined
}
function projectModels(models, keep) {
  const out = dict()
  if (!models || typeof models !== 'object' || Array.isArray(models)) return out
  for (const k of Object.keys(models).slice(0, MAX_MODELS)) {
    const id = s200(k)
    if (!id) continue
    const m = models[k] && typeof models[k] === 'object' ? models[k] : {}
    out[id] = keep(m)
  }
  return out
}
/** GET /config → the declared model names and the default model. Nothing else (no options, no MCP, no permissions). */
function projectConfig(c) {
  const out = {}
  if (s200(c.model)) out.model = s200(c.model)
  if (s200(c.small_model)) out.small_model = s200(c.small_model)
  const provider = dict()
  const src = c.provider && typeof c.provider === 'object' && !Array.isArray(c.provider) ? c.provider : {}
  for (const pid of Object.keys(src).slice(0, MAX_PROVIDERS)) {
    if (!s200(pid)) continue
    const p = src[pid] && typeof src[pid] === 'object' ? src[pid] : {}
    const entry = { models: projectModels(p.models, (m) => (s200(m.name) ? { name: s200(m.name) } : {})) }
    if (s200(p.name)) entry.name = s200(p.name)
    provider[s200(pid)] = entry
  }
  out.provider = provider
  return out
}
/** GET /config/providers → for each connected provider: id, name, source, and its models' names and input kinds. */
function projectProviders(d) {
  const providers = (Array.isArray(d.providers) ? d.providers : []).slice(0, MAX_PROVIDERS).filter((p) => p && s200(p.id)).map((p) => {
    const entry = { id: s200(p.id), models: projectModels(p.models, (m) => {
      const o = {}
      if (s200(m.name)) o.name = s200(m.name)
      if (s200(m.status)) o.status = s200(m.status)
      const input = projectInput(m.capabilities)
      if (input) o.input = input
      return o
    }) }
    if (s200(p.name)) entry.name = s200(p.name)
    if (s200(p.source)) entry.source = s200(p.source)
    return entry
  })
  const def = dict()
  if (d.default && typeof d.default === 'object' && !Array.isArray(d.default)) {
    for (const k of Object.keys(d.default).slice(0, MAX_PROVIDERS)) if (s200(k) && s200(d.default[k])) def[s200(k)] = s200(d.default[k])
  }
  return { providers, default: def }
}
/** The answer the connector sends for `method path` — projected for the routes above, untouched otherwise.
 *  Returns { st, b } (status, body text). */
export function projectResponse(method, pathWithQuery, status, text) {
  const path = String(pathWithQuery || '').split('?')[0]
  if (String(method || '').toUpperCase() !== 'GET' || !PROJECTED.has(path)) return { st: status, b: text }
  if (!(status >= 200 && status < 300)) return { st: status, b: JSON.stringify({ error: `OpenCode answered ${status} for ${path}` }) }
  let v
  try { v = JSON.parse(text) } catch { v = null }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { st: 502, b: JSON.stringify({ error: `OpenCode sent an unexpected answer for ${path}` }) }
  return { st: status, b: JSON.stringify(path === '/config' ? projectConfig(v) : projectProviders(v)) }
}
