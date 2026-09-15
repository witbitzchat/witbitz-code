// codeTransport.js — how the Code section reaches OpenCode. Two interchangeable transports behind one shape, so the rest
// of opencodeApp.js never knows which it is using (docs/opencode-relay.md §5):
//
//   relay  — the normal path: a sealed WebSocket to the connector on a paired computer (codeRelay.js). No server address,
//            no password in the page, no third-party origin in the CSP.
//   direct — development only: fetch + SSE straight to an OpenCode server the page can reach (http://127.0.0.1:4096).
//
//   t.request(method, pathWithQuery, bodyObject?) → { ok, status, json, text }
//   t.subscribe(pathWithQuery, onEvent)           → stop()      (onEvent gets each parsed OpenCode event)
//   t.status()                                    → 'online' | 'connecting' | 'offline'
//   t.onChange(fn)  t.kick()  t.close()
import { RelayPeer } from './codeRelay.js'
import { makeSseParser } from './opencodeWire.js'

const parse = (text) => { try { return text ? JSON.parse(text) : null } catch { return null } }
const rid = () => Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(36).padStart(2, '0')).join('')

// ── direct ───────────────────────────────────────────────────────────────────────────────────────────────────────
export function directTransport({ base, pass, fetchImpl = (...a) => fetch(...a) }) {
  const root = String(base || '').replace(/\/+$/, '')
  const auth = () => (pass ? { authorization: 'Basic ' + btoa('opencode:' + pass) } : {})
  return {
    kind: 'direct',
    label: root,
    status: () => 'online',
    onChange: () => () => {},
    can: () => false, // Auto mode lives in the connector — a direct server has none
    autoSessions: () => [],
    onAuto: () => () => {},
    onProgress: () => () => {}, // the confidential-model proxy lives in the connector too
    setAuto: () => false,
    askTools: async () => null, // a direct server has no connector to look
    kick: () => {},
    close: () => {},
    async request(method, p, body) {
      const init = { method, headers: { ...auth(), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) } }
      if (body !== undefined) init.body = JSON.stringify(body)
      const r = await fetchImpl(root + p, init) // a network failure throws — the caller explains it
      const text = await r.text().catch(() => '')
      return { ok: r.ok, status: r.status, json: parse(text), text }
    },
    subscribe(p, onEvent, onError = () => {}) {
      const ctrl = new AbortController()
      ;(async () => {
        let r
        try { r = await fetchImpl(root + p, { headers: { ...auth(), accept: 'text/event-stream' }, signal: ctrl.signal }) }
        catch (err) { if (!ctrl.signal.aborted) onError(err); return }
        if (!r.ok || !r.body) { onError(new Error(`event stream ${r.status}`)); return }
        const feed = makeSseParser(onEvent)
        const reader = r.body.getReader()
        const dec = new TextDecoder()
        try { for (;;) { const { done, value } = await reader.read(); if (done) break; feed(dec.decode(value, { stream: true })) } }
        catch { /* aborted, or the server went away */ }
      })()
      return () => ctrl.abort()
    },
  }
}

// ── relay ────────────────────────────────────────────────────────────────────────────────────────────────────────
const PEERS_WAIT_MS = 3_000 // a relay that never says who is on the channel: offline after this, not "connecting" for good
const HELLO_FRESH_MS = 30_000 // the connector says hello every 20 s while someone is here
const WAIT_ONLINE_MS = 8_000 // a request made while connecting waits this long for the computer
const REQUEST_TIMEOUT_MS = 35_000 // the connector's own timeout is 30 s
const RESUB_MS = 30_000 // the connector drops a subscription nobody renewed for 75 s
const GIVE_UP_MS = 60_000
const SILENT_MS = 50_000 // an "open" socket with a computer on it but no hello for this long is a dead path: redial
const WAKE_GAP_MS = 15_000 // the 5-second tick went this long without running: the page was frozen in the background
const WAKE_WAIT_MS = 4_000 // back from the background: how long the computer has to answer before "offline" may show

export function relayTransport({ computer, WebSocketImpl, now = () => Date.now() }) {
  const listeners = new Set()
  const pending = new Map() // id → { resolve, timer, resend: (() => void) | null }
  const subs = new Map() // path → Set(onEvent)
  let lastHello = 0
  // The connector's nonce for its CURRENT socket (sealed in its hello). Every request carries it; a request recorded before
  // the connector restarted carries a stale one and is refused there (replay protection across restarts).
  let nonce = ''
  let lastHelloTs = 0 // a replayed OLD hello (earlier ts) must not move this page back onto a dead nonce
  // This device's id for its event-stream interest, so one device leaving never closes a stream another is reading.
  const cid = rid()
  let last = 'connecting'
  // Auto mode (docs/code-auto-mode.md §5): what the connector says it can do, which sessions it decides for, and its verdicts.
  let caps = []
  let autoList = []
  const autoListeners = new Set()
  const toolWaiters = [] // askTools() calls waiting for the computer's {t:'tools'} answer
  const tellAuto = (e) => { for (const fn of autoListeners) { try { fn(e) } catch { /* */ } } }
  const progressListeners = new Set() // what a confidential model is doing (codeProgress.js)
  let resubTimer = 0
  let freshTimer = 0

  let openedAt = 0
  // The relay says who is on the channel only just AFTER the socket opens. Counting the page alone before then said
  // "offline" for a moment on every open (the owner: "I get this brief red warning. It is transient and shouldnt show up").
  let peersKnown = false
  // ★ BACK FROM THE BACKGROUND. iOS freezes the page with its socket still "open"; on return the computer's last hello is
  //   old because nothing ran, not because the computer left — and the first tick said offline before anyone had asked it
  //   again (the owner: "When I switch apps and return to spaces I get this transient red notice"). A frozen tick, or the
  //   page saying it is visible again (kick), asks the computer and holds "offline" back until it has had time to answer.
  let lastTick = now()
  let wokeAt = -Infinity
  const status = () => {
    if (!peer.isOpen) return 'connecting' // still dialling the relay (or retrying)
    if (peer.peers >= 2 && now() - lastHello < HELLO_FRESH_MS) return 'online'
    if (now() - lastTick > WAKE_GAP_MS || now() - wokeAt < WAKE_WAIT_MS) return 'connecting' // just back: asking again
    if (peer.peers < 2) return !peersKnown && now() - openedAt < PEERS_WAIT_MS ? 'connecting' : 'offline' // alone on the channel: the computer is not running
    // Someone else is here but has not said hello — maybe the computer is just answering, maybe it is only another of
    // your devices. Give it a moment, then call it offline.
    return now() - openedAt < 5_000 ? 'connecting' : 'offline'
  }
  let giveUpTimer = 0
  const changed = () => {
    const s = status()
    if (s === last) return
    last = s
    clearTimeout(giveUpTimer)
    if (s === 'online') { resubscribe(); for (const e of pending.values()) if (e.resend) e.resend() }
    // A turn waiting on a computer that went away would leave the page "busy" forever. After a minute offline, every
    // request that cannot be safely re-asked resolves as failed; reads stay pending and re-ask when it returns.
    if (s === 'offline') giveUpTimer = setTimeout(() => {
      for (const [id, e] of pending) if (!e.resend) { pending.delete(id); clearTimeout(e.timer); e.resolve({ ok: false, status: 0, json: null, text: 'offline' }) }
    }, GIVE_UP_MS)
    for (const fn of listeners) { try { fn(s) } catch { /* */ } }
  }

  function onHello(m) {
    // A hello OLDER than the last one is a replay (the relay can record and resend frames): ignore it, or the page would
    // move back onto a nonce the connector no longer accepts.
    if (typeof m.ts === 'number' && m.ts <= lastHelloTs) return
    if (typeof m.ts === 'number') lastHelloTs = m.ts
    const renewed = typeof m.k === 'string' && m.k && m.k !== nonce
    if (typeof m.k === 'string' && m.k) nonce = m.k
    lastHello = now()
    const nextCaps = Array.isArray(m.caps) ? m.caps.filter((c) => typeof c === 'string').slice(0, 16) : []
    const nextAuto = nextCaps.includes('auto') && Array.isArray(m.auto) ? m.auto.filter((s) => typeof s === 'string' && /^ses[A-Za-z0-9_-]{1,80}$/.test(s)) : []
    if (nextCaps.join() !== caps.join() || nextAuto.join() !== autoList.join()) { caps = nextCaps; autoList = nextAuto; tellAuto({ kind: 'sessions', sessions: [...autoList] }) }
    // A NEW nonce = the connector restarted, redialled or rotated: anything it has not answered was refused or lost —
    // re-ask the reads with the new nonce and renew the streams. (Mutations are never re-sent.)
    if (renewed && last === 'online') { resubscribe(); for (const e of pending.values()) if (e.resend) e.resend() }
    changed()
  }

  const peer = new RelayPeer({
    secret: computer.secret,
    role: 'client',
    relay: computer.relay,
    WebSocketImpl,
    onState: (s) => { peersKnown = false; if (s === 'open') { openedAt = now(); peer.send({ t: 'ping' }); setTimeout(changed, PEERS_WAIT_MS + 50) } else { lastHello = 0; nonce = '' } changed() },
    onPeers: (n) => { peersKnown = peer.isOpen; if (n < 2) lastHello = 0; else peer.send({ t: 'ping' }); changed() },
    onMessage: (m) => {
      if (m.t === 'hello') { onHello(m); return }
      if (m.t === 'progress') { for (const fn of progressListeners) { try { fn(m) } catch { /* */ } } return }
      if (m.t === 'tools') { const waiting = toolWaiters.splice(0); for (const w of waiting) w(m); return }
      if (m.t === 'autoverdict') { if (typeof m.sessionID === 'string' && typeof m.action === 'string') tellAuto({ kind: 'verdict', verdict: m }); return }
      if (m.t === 'res') {
        const e = pending.get(m.id)
        if (!e) return // another device's request, or one we gave up on
        if (m.st === 409 && e.resend) return // stale nonce on a read: the connector's new hello re-sends it
        pending.delete(m.id)
        clearTimeout(e.timer)
        e.resolve({ ok: m.st >= 200 && m.st < 300, status: m.st, json: parse(m.b), text: m.b || '' })
        return
      }
      if (m.t === 'evts') {
        const handlers = subs.get(m.p)
        if (!handlers) return
        const batch = parse(m.b)
        if (!Array.isArray(batch)) return
        for (const d of batch) { const ev = parse(d); if (ev) for (const h of handlers) { try { h(ev) } catch { /* */ } } }
      }
    },
  })
  const resubscribe = () => { if (nonce) for (const p of subs.keys()) peer.send({ t: 'sub', c: cid, k: nonce, p }) }
  const wake = () => {
    lastTick = now()
    wokeAt = now()
    if (peer.isOpen) peer.send({ t: 'ping' }) // the connector answers a ping with its hello
    setTimeout(changed, WAKE_WAIT_MS + 50)
    changed()
  }
  peer.start()
  freshTimer = setInterval(() => {
    if (now() - lastTick > WAKE_GAP_MS) wake() // the page was frozen: this tick is the first thing to run
    lastTick = now()
    // ★ A dead network path can leave a socket "open" forever (send() never fails). The connector says hello every 20 s
    //   while anyone is here, so silence for 50 s with a peer present means the path is gone: redial.
    if (peer.isOpen && peer.peers >= 2 && lastHello && now() - lastHello > SILENT_MS) peer.reconnect()
    changed() // a hello that stops arriving must turn into "offline"
  }, 5_000)
  resubTimer = setInterval(() => { if (status() === 'online') resubscribe() }, RESUB_MS)

  const waitOnline = () => new Promise((resolve) => {
    if (status() === 'online') return resolve(true)
    const off = () => { listeners.delete(fn); clearTimeout(timer) }
    const fn = (s) => { if (s === 'online') { off(); resolve(true) } }
    const timer = setTimeout(() => { off(); resolve(false) }, WAIT_ONLINE_MS)
    listeners.add(fn)
  })

  return {
    kind: 'relay',
    label: computer.name || 'your computer',
    _nonce: () => nonce, // test hooks
    _hello: (m) => onHello(m),
    computer,
    status,
    onChange(fn) { listeners.add(fn); return () => listeners.delete(fn) },
    can: (cap) => caps.includes(cap),
    autoSessions: () => [...autoList],
    onAuto(fn) { autoListeners.add(fn); return () => autoListeners.delete(fn) },
    onProgress(fn) { progressListeners.add(fn); return () => progressListeners.delete(fn) },
    /** Switch Auto for one session on the computer (nonce-checked there). The next hello confirms it. */
    setAuto(sid, dir, on) { if (!nonce || !caps.includes('auto')) return false; peer.send({ t: 'auto', k: nonce, sid, dir, on: !!on }); return true },
    /** Which suggested tools the computer has ("Set up this computer"): its `{t:'tools'}` answer, or null when it does not
     *  answer in `ms` — a connector from before this never does. */
    askTools(ms = 6000) {
      if (!nonce) return Promise.resolve(null)
      return new Promise((resolve) => {
        const done = (m) => { clearTimeout(timer); const i = toolWaiters.indexOf(done); if (i >= 0) toolWaiters.splice(i, 1); resolve(m) }
        const timer = setTimeout(() => done(null), ms)
        toolWaiters.push(done)
        peer.send({ t: 'tools', k: nonce })
      })
    },
    kick: () => { wake(); peer.kick() }, // the page is visible again: ask the computer, and redial a dead socket
    close() {
      clearInterval(resubTimer); clearInterval(freshTimer); clearTimeout(giveUpTimer)
      for (const e of pending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, status: 0, json: null, text: 'closed' }) }
      pending.clear(); subs.clear(); listeners.clear(); autoListeners.clear(); progressListeners.clear()
      peer.stop()
    },
    async request(method, p, body) {
      if (!(await waitOnline())) return { ok: false, status: 0, json: null, text: 'offline' }
      return new Promise((resolve) => {
        const id = rid()
        const b = body !== undefined ? { b: JSON.stringify(body) } : {}
        const msg = () => ({ t: 'req', id, k: nonce, m: method, p, ...b }) // built at send time: always the CURRENT nonce
        // A turn POST returns only when the model has finished; its progress rides the event stream, so no timeout.
        const turn = method === 'POST' && /\/message$/.test(p.split('?')[0])
        const entry = { resolve, timer: 0, resend: null }
        // Reads are safe to re-ask after a reconnect; anything that changes state is never sent twice.
        if (method === 'GET') entry.resend = () => peer.send(msg())
        if (!turn) entry.timer = setTimeout(() => { pending.delete(id); resolve({ ok: false, status: 0, json: null, text: 'timeout' }) }, REQUEST_TIMEOUT_MS)
        pending.set(id, entry)
        peer.send(msg()).then((sent) => { if (!sent && method !== 'GET') { pending.delete(id); clearTimeout(entry.timer); resolve({ ok: false, status: 0, json: null, text: 'offline' }) } })
      })
    },
    subscribe(p, onEvent) {
      if (!subs.has(p)) subs.set(p, new Set())
      subs.get(p).add(onEvent)
      if (status() === 'online' && nonce) peer.send({ t: 'sub', c: cid, k: nonce, p })
      return () => {
        const set = subs.get(p)
        if (!set) return
        set.delete(onEvent)
        if (!set.size) { subs.delete(p); if (nonce) peer.send({ t: 'unsub', c: cid, k: nonce, p }) }
      }
    },
  }
}
