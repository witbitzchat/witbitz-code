// witbitz/relay/relay.mjs — THE SEALED RELAY.
//
// A dumb, content-blind WebSocket forwarder keyed by an OPAQUE channel id. Two kinds of peer dial OUT to
// wss://<relay>/c/<channel> and every message is broadcast to the *other* sockets on that channel:
//   • the Code section (docs/opencode-relay.md) — the page in the app, and the connector beside OpenCode on your computer,
//     on  wss://code-relay.witbitz.chat
//   • the (parked) browse room — its local server and the app
// The channel id is derived by the peers from a key the relay never sees (Code: HKDF-SHA256 of the pairing secret), and
// every payload is sealed end to end, so the relay carries only ciphertext: it forwards bytes it cannot read. It sees a
// channel id, IP addresses, timing and sizes — nothing else.
//
// One Durable Object instance per channel = the hub. WebSocket hibernation keeps idle channels ~free.
//
// HARDENING (§6 of the design). None of it is the security boundary — the key is — but a public relay must not be a
// free megaphone: a strict channel id, browsers only from witbitz origins, at most 16 sockets per channel, 200 messages
// per 10 s per socket, 1 MiB per message.

const CHANNEL = /^\/c\/([A-Za-z0-9_-]{43})$/ // HKDF-SHA256 → 32 bytes → base64url, unpadded = exactly 43 chars
const MAX_SOCKETS = 16
const RATE_MAX = 200
const RATE_WINDOW_MS = 10_000
const MAX_MESSAGE = 1024 * 1024
// (Plain consts, NOT exports: a Worker module treats every named export as an entrypoint and refuses to start.)
// A socket with NO Origin header is a native client (the Node connector); a browser always sends one, and a page on any
// other site must not be able to join a channel even if it learned an id.
const ORIGINS = new Set([
  'https://app.witbitz.chat',
  'https://spaces.witbitz.chat',
  'https://witbitz-spaces.pages.dev',
  'https://preview.witbitz-spaces.pages.dev',
  'https://witbitz-browse.pages.dev', // the parked browse room's viewer
  'http://127.0.0.1:8099', // the local dev harness (npm run dev)
])

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    if (url.pathname === '/health') return new Response('ok\n', { headers: { 'content-type': 'text/plain' } })
    const m = url.pathname.match(CHANNEL)
    if (!m) return new Response('not found', { status: 404 })
    if ((request.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') return new Response('expected a websocket', { status: 426 })
    const origin = request.headers.get('Origin')
    if (origin && !ORIGINS.has(origin)) return new Response('origin not allowed', { status: 403 })
    return env.RELAY.get(env.RELAY.idFromName(m[1])).fetch(request)
  },
}

export class Relay {
  constructor(state) {
    this.state = state
    // The heartbeat (spaces/public/codeRelay.js RELAY_PING): answered by the runtime itself — the object is not woken, the
    // message is not broadcast and not counted against the rate limit. A socket whose ping goes unanswered redials.
    try { state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"t":"relay-ping"}', '{"t":"relay-pong"}')) } catch { /* a runtime without auto-responses: pings are broadcast, and peers ignore them */ }
  }

  async fetch() {
    // Refuse BEFORE upgrading: a 429 is an answer the client can read; a socket closed right after 101 is a mystery.
    if (this.live().length >= MAX_SOCKETS) return new Response('channel full', { status: 429 })
    const { 0: client, 1: server } = new WebSocketPair()
    this.state.acceptWebSocket(server) // hibernatable — the DO can evict from memory between messages
    server.serializeAttachment({ w: Date.now(), n: 0 }) // the rate window survives hibernation with the socket
    this.announce()
    return new Response(null, { status: 101, webSocket: client })
  }

  // Broadcast every message verbatim to the OTHER sockets on this channel. No inspection, no storage — ciphertext to us.
  webSocketMessage(ws, message) {
    const size = typeof message === 'string' ? message.length : message.byteLength
    if (size > MAX_MESSAGE) { this.drop(ws, 1009, 'message too big'); return }
    const now = Date.now()
    const a = ws.deserializeAttachment() || { w: now, n: 0 }
    if (now - a.w >= RATE_WINDOW_MS) { a.w = now; a.n = 0 }
    a.n++
    if (a.n > RATE_MAX) { this.drop(ws, 1008, 'rate limit'); return }
    ws.serializeAttachment(a)
    for (const p of this.live()) { if (p !== ws) { try { p.send(message) } catch { /* dropped peer */ } } }
  }

  webSocketClose(ws, code, reason) { this.drop(ws, code, reason) }
  webSocketError(ws) { this.drop(ws, 1011, 'error') }

  /** Close a socket and tell the others — the closing socket is marked first, so the count never includes it. */
  drop(ws, code, reason) {
    try { ws.serializeAttachment({ ...(ws.deserializeAttachment() || {}), gone: true }) } catch { /* already closed */ }
    try { ws.close(code === 1005 || code === 1006 ? 1000 : code, reason) } catch { /* already closed */ }
    this.announce()
  }

  /** Sockets that are still here. getWebSockets() keeps returning a socket while its close is being handled. */
  live() {
    return this.state.getWebSockets().filter((w) => { try { return !(w.deserializeAttachment() || {}).gone && w.readyState !== 2 && w.readyState !== 3 } catch { return false } })
  }

  // The current peer count — a small, unsealed control signal (a count, no content): the connector forwards events only
  // while a client is present, and the page tells "your computer is offline" from "nobody else is here".
  announce() {
    const peers = this.live()
    const msg = JSON.stringify({ t: 'peers', n: peers.length })
    for (const p of peers) { try { p.send(msg) } catch { /* */ } }
  }
}
