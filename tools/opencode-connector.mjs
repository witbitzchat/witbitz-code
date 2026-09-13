// tools/opencode-connector.mjs — the Code section's end on YOUR computer (docs/opencode-relay.md).
//
// OpenCode stays on 127.0.0.1. This process dials OUT to the sealed relay (wss://code-relay.witbitz.chat) once per
// pairing, and does for the Code page what a browser on the same machine would do: it calls OpenCode's HTTP API (with the
// local password, which never leaves this machine) and streams OpenCode's events back — every frame sealed with keys
// derived from the pairing secret, so the relay forwards bytes it cannot read.
//
//   node tools/opencode-connector.mjs            run every pairing in ~/.witbitz/code/pairings.json (until Ctrl-C)
//   node tools/opencode-connector.mjs --status   list the pairings (names only — never a secret)
//   … --parent <pid>                              stop when that process is gone (opencode-serve.sh passes its own)
//
// It serves ONLY the calls the Code page makes (codeRelay.js `allowedRequest`): OpenCode can run shell commands here, so a
// leaked secret must not unlock more than the page itself can do.
import { readFileSync, existsSync } from 'node:fs'
import { homedir, hostname } from 'node:os'
import { join } from 'node:path'
import { RelayPeer, allowedRequest, allowedEventPath, projectResponse, RELAY_URL } from '../spaces/public/codeRelay.js'

export const VERSION = '1'
export const PAIRINGS_PATH = process.env.WITBITZ_CODE_PAIRINGS || join(homedir(), '.witbitz', 'code', 'pairings.json')
const DEFAULT_ENV = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')
const REQUEST_TIMEOUT_MS = 30_000
const HELLO_EVERY_MS = 20_000 // the page counts the computer online while a hello arrived in the last 30 s
const SUB_TTL_MS = 75_000 // a page re-subscribes every 30 s; a subscription nobody renews is dropped
const MAX_RESPONSE = 30 * 1024 * 1024 // above the page's 32 MiB reassembly cap: say so at once instead of timing out
const START_HINT = process.env.WITBITZ_CODE_BUNDLED === '1' ? 'node witbitz-code.mjs serve' : 'bash tools/opencode-serve.sh'

/** OPENCODE_SERVER_PASSWORD from an env file — the LAST assignment wins, quotes stripped, `export` allowed. */
export function parseEnvPassword(text) {
  let v = ''
  for (const line of String(text || '').split(/\r?\n/)) { // CRLF too: `.` does not match \r, so a Windows-edited file hid the password
    const m = line.match(/^\s*(?:export\s+)?OPENCODE_SERVER_PASSWORD=(.*)$/)
    if (m) v = m[1].trim().replace(/^(['"])(.*)\1$/, '$2')
  }
  return v
}

/** The pairings file → a list (empty when absent). Entries without a secret are skipped, loudly. */
export function loadPairings(path = PAIRINGS_PATH, log = console.error) {
  if (!existsSync(path)) return []
  let doc
  try { doc = JSON.parse(readFileSync(path, 'utf8')) } catch (e) { log(`opencode-connector: ${path} is not valid JSON (${e.message})`); return [] }
  const list = Array.isArray(doc && doc.pairings) ? doc.pairings : []
  return list.filter((p) => { const ok = p && typeof p.secret === 'string' && p.secret.length >= 43; if (!ok) log('opencode-connector: skipping a pairing with no secret'); return ok })
}

/** The pairings served by the OpenCode on `port`. Two connectors (one OpenCode per account) must never both answer the
 *  same channel — every event would arrive twice — so each serves only the pairings that point at its own port. */
export function pairingsForPort(pairings, port) {
  return pairings.filter((p) => { try { const u = new URL(p.opencodeUrl || 'http://127.0.0.1:4096'); return Number(u.port || (u.protocol === 'https:' ? 443 : 80)) === Number(port) } catch { return false } })
}

/** Split an SSE byte stream into `data:` payloads (one per event, multi-line data joined). */
function sseReader(onData) {
  let buf = ''
  return (chunk) => {
    buf += chunk
    let i
    while ((i = buf.search(/\r?\n\r?\n/)) >= 0) {
      const block = buf.slice(0, i)
      buf = buf.slice(buf.slice(i).match(/^\r?\n\r?\n/)[0].length + i)
      const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n')
      if (data) onData(data)
    }
  }
}

/**
 * Serve the given pairings. Returns { stop, peers } — `peers` is one RelayPeer per pairing.
 * Options exist for tests: fetchImpl, WebSocketImpl, flushMs, log.
 */
export async function startConnector({ pairings, fetchImpl = fetch, WebSocketImpl = globalThis.WebSocket, flushMs = 120, log = console.error, requestTimeoutMs = REQUEST_TIMEOUT_MS, maxSenders = 64, maxResponseBytes = MAX_RESPONSE } = {}) {
  const running = []
  for (const p of pairings) running.push(await servePairing(p, { fetchImpl, WebSocketImpl, flushMs, log, requestTimeoutMs, maxSenders, maxResponseBytes }))
  return { peers: running.map((r) => r.peer), stop: () => { for (const r of running) r.stop() } }
}

async function servePairing(pairing, { fetchImpl, WebSocketImpl, flushMs, log, requestTimeoutMs, maxSenders, maxResponseBytes }) {
  const name = pairing.name || hostname()
  const base = String(pairing.opencodeUrl || 'http://127.0.0.1:4096').replace(/\/+$/, '')
  const password = () => pairing.password || parseEnvPassword(existsSync(pairing.envFile || DEFAULT_ENV) ? readFileSync(pairing.envFile || DEFAULT_ENV, 'utf8') : '')
  const auth = () => { const pw = password(); return pw ? { authorization: 'Basic ' + Buffer.from('opencode:' + pw).toString('base64') } : {} }
  const inflight = new Map() // request id → AbortController
  const subs = new Map() // event path → { ctrl, clients: Map(client id → last renewed), buffer, timer }
  let helloTimer = 0
  // ★ REPLAY ACROSS RESTARTS. The frame layer drops a replay only while this process remembers the sender, so a sealed
  //   request recorded earlier (by anyone on the path — the relay included) could be re-sent after a restart and run
  //   again. Each socket therefore announces a fresh random nonce inside its sealed hello, and a request must carry the
  //   CURRENT one: a recording from before a restart or reconnect carries a nonce nobody will accept again.
  let nonce = ''
  const freshNonce = () => { nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString('base64url') }

  const peer = new RelayPeer({
    secret: pairing.secret, role: 'computer', relay: pairing.relay || RELAY_URL, WebSocketImpl, maxSenders,
    onState: (s) => { log(`opencode-connector: ${name} · relay ${s}`); if (s === 'open') { freshNonce(); hello() } },
    onPeers: (n) => {
      if (n >= 2) hello()
      else for (const k of [...subs.keys()]) unsubscribe(k, ALL) // nobody is watching: close OpenCode's streams
    },
    onMessage: (m) => { handle(m).catch((e) => log(`opencode-connector: ${name} · ${e && e.message}`)) },
    // A page socket fell out of the replay window: its recorded frames would open again — rotate the nonce so every
    // request it ever sealed is refused, and tell the pages (they re-ask reads under the new one).
    onEvict: () => { freshNonce(); hello() },
  })

  function hello() { if (nonce) peer.send({ t: 'hello', ver: VERSION, name, computerId: pairing.computerId || '', k: nonce, ts: Date.now() }) }

  async function handle(m) {
    if (!m || typeof m.t !== 'string') return
    if (m.t === 'ping') return hello()
    const current = typeof m.k === 'string' && m.k === nonce
    if (m.t === 'cancel') { if (current) { const c = inflight.get(m.id); if (c) c.abort() } return }
    if (m.t === 'sub') { if (current) subscribe(m.p, m.c); return }
    if (m.t === 'unsub') { if (current) unsubscribe(m.p, m.c); return }
    if (m.t !== 'req') return
    const id = typeof m.id === 'string' ? m.id : ''
    if (!id) return
    const reply = (st, b) => peer.send({ t: 'res', id, st, b: typeof b === 'string' ? b : JSON.stringify(b) })
    // Refuse rather than truncate: a shortened id could collide, and `cancel` would look up the long one.
    if (id.length > 64) return reply(400, { error: 'request id longer than 64 characters' })
    if (!current) return reply(409, { error: 'stale: this computer\'s connector changed — reconnecting' })
    if (!allowedRequest(m.m, m.p)) return reply(403, { error: 'not allowed by the connector' })
    const ctrl = new AbortController()
    inflight.set(id, ctrl)
    let timedOut = false
    // A turn POST returns only when the model has finished; it has no timeout (its progress rides the event stream).
    const timer = /\/message$/.test(m.p.split('?')[0]) && m.m === 'POST' ? 0 : setTimeout(() => { timedOut = true; ctrl.abort() }, requestTimeoutMs)
    try {
      const r = await fetchImpl(base + m.p, {
        method: m.m,
        headers: { ...auth(), ...(typeof m.b === 'string' ? { 'content-type': 'application/json' } : {}) },
        body: typeof m.b === 'string' ? m.b : undefined,
        signal: ctrl.signal,
      })
      // Read with a cap: refuse while reading, never after holding an unbounded answer in memory.
      const chunks = []
      let size = 0
      const dec = new TextDecoder()
      if (r.body) {
        for await (const chunk of r.body) {
          size += chunk.byteLength
          if (size > maxResponseBytes) { ctrl.abort(); return reply(413, { error: `OpenCode's answer is over ${Math.round(maxResponseBytes / 1048576) || '<1'} MB — too large to send through the relay` }) }
          chunks.push(dec.decode(chunk, { stream: true }))
        }
      }
      chunks.push(dec.decode())
      // /config and /config/providers carry API keys: rebuilt from an allowlist of fields before they leave (codeRelay.js).
      const out = projectResponse(m.m, m.p, r.status, chunks.join(''))
      await reply(out.st, out.b)
    } catch (e) {
      if (timedOut) return reply(504, { error: `OpenCode did not answer within ${Math.round(requestTimeoutMs / 1000)} s` })
      if (ctrl.signal.aborted) return reply(499, { error: 'cancelled' })
      await reply(502, { error: `OpenCode is not answering at ${base} — start it on that computer: ${START_HINT}` })
    } finally {
      clearTimeout(timer)
      inflight.delete(id)
    }
  }

  // One OpenCode stream per path, shared by every device watching it; each device (its client id `c`) renews its own
  // interest, so one device leaving never closes the stream another is still reading.
  function subscribe(p, c) {
    if (!allowedEventPath(p)) return
    const cid = typeof c === 'string' && c ? c.slice(0, 64) : '_'
    const existing = subs.get(p)
    if (existing) { existing.clients.set(cid, Date.now()); return }
    const sub = { ctrl: new AbortController(), clients: new Map([[cid, Date.now()]]), buffer: [], timer: 0 }
    subs.set(p, sub)
    const flush = () => {
      sub.timer = 0
      if (!sub.buffer.length) return
      const batch = sub.buffer.splice(0)
      peer.send({ t: 'evts', p, b: JSON.stringify(batch) })
    }
    const pump = async () => {
      while (subs.get(p) === sub) {
        try {
          const r = await fetchImpl(base + p, { headers: { ...auth(), accept: 'text/event-stream' }, signal: sub.ctrl.signal })
          if (!r.ok || !r.body) throw new Error(`event stream ${r.status}`)
          const feed = sseReader((data) => { sub.buffer.push(data); if (!sub.timer) sub.timer = setTimeout(flush, flushMs) })
          const dec = new TextDecoder()
          for await (const chunk of r.body) feed(dec.decode(chunk, { stream: true }))
        } catch { /* aborted, or OpenCode restarted */ }
        if (subs.get(p) !== sub) break
        await new Promise((r) => setTimeout(r, 1000)) // OpenCode went away mid-stream: try again while someone watches
      }
    }
    pump()
  }

  const ALL = Symbol('every client') // internal only: nobody is watching any more
  function unsubscribe(p, c) {
    const sub = subs.get(p)
    if (!sub) return
    if (c !== ALL) { sub.clients.delete(typeof c === 'string' && c ? c.slice(0, 64) : '_'); if (sub.clients.size) return } // no id = the anonymous interest, as in subscribe()
    subs.delete(p)
    clearTimeout(sub.timer)
    try { sub.ctrl.abort() } catch { /* */ }
  }

  const sweep = setInterval(() => {
    const now = Date.now()
    for (const [p, s] of subs) {
      for (const [cid, at] of s.clients) if (now - at > SUB_TTL_MS) s.clients.delete(cid)
      if (!s.clients.size) unsubscribe(p, ALL)
    }
  }, 15_000)
  helloTimer = setInterval(() => { if (peer.peers >= 2) hello() }, HELLO_EVERY_MS)

  await peer.start()
  return {
    peer,
    stop: () => {
      clearInterval(sweep); clearInterval(helloTimer)
      for (const k of [...subs.keys()]) unsubscribe(k, ALL)
      for (const c of inflight.values()) { try { c.abort() } catch { /* */ } }
      peer.stop()
    },
  }
}

/** Stop when the process that started us is gone. opencode-serve.sh passes `--parent $$`: killed with -9 its trap never
 *  runs, and the connector would go on holding a sealed channel for an OpenCode nobody supervises. The signal is a
 *  CHANGED ppid (re-parented to init or a subreaper) — never a probe of the old pid, which a reused pid would fool.
 *  No parent given (a connector started by hand) → no watch. Returns a stop function. */
export function watchParent({ parent, getPpid = () => process.ppid, onGone, everyMs = 2000 }) {
  if (!Number.isInteger(parent) || parent <= 1) return () => {}
  const t = setInterval(() => { if (getPpid() !== parent) { clearInterval(t); onGone() } }, everyMs)
  if (t.unref) t.unref()
  return () => clearInterval(t)
}

export async function main(argv = process.argv.slice(2)) {
  const args = argv
  const pi = args.indexOf('--port')
  const pairings = pi >= 0 ? pairingsForPort(loadPairings(), Number(args[pi + 1])) : loadPairings()
  if (args.includes('--status')) {
    if (!pairings.length) console.log('opencode-connector: not paired — run `bash tools/opencode-serve.sh --pair`')
    for (const p of pairings) console.log(`· ${p.name || hostname()} → ${p.account || '(account)'} · OpenCode ${p.opencodeUrl || 'http://127.0.0.1:4096'}`)
    return
  }
  if (!pairings.length) { console.error('opencode-connector: not paired yet — run `bash tools/opencode-serve.sh --pair` and scan the QR with the Spaces app'); process.exit(1) }
  const c = await startConnector({ pairings })
  console.error(`opencode-connector: serving ${pairings.length} pairing${pairings.length === 1 ? '' : 's'} through the sealed relay (Ctrl-C to stop)`)
  const bye = () => { c.stop(); process.exit(0) }
  process.on('SIGINT', bye); process.on('SIGTERM', bye)
  const pp = args.indexOf('--parent')
  watchParent({ parent: pp >= 0 ? Number(args[pp + 1]) : 0, onGone: () => { console.error('opencode-connector: the script that started me is gone — stopping'); bye() } })
}

// (WITBITZ_CODE_BUNDLED is defined at bundle time: inside witbitz-code.mjs every module shares one import.meta.url.)
if (process.env.WITBITZ_CODE_BUNDLED !== "1" && process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((e) => { console.error('opencode-connector: FATAL —', (e && e.message) || e); process.exit(1) })
}
