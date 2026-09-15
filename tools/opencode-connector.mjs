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
import { readFileSync, existsSync, mkdirSync, appendFileSync, writeFileSync, renameSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { homedir, hostname } from 'node:os'
import { join, resolve, relative } from 'node:path'
import { RelayPeer, allowedRequest, allowedEventPath, projectResponse, RELAY_URL } from '../spaces/public/codeRelay.js'
import { startConfidentialProxy, proxyPortFor, makeTinfoilReader, tinfoilKey } from './code-confidential.mjs'
import { stageMessageBody, serveAttachment, removeSessionAttachments, pruneAttachments, attachmentRule, ATTACH_ROOT, MAX_FILE_BYTES } from './code-attachments.mjs' // attachments, the Claude Code way (docs/code-attachments.md)
import { ATTACHMENT_ROUTE } from '../spaces/public/codeAttachments.js'
import { serveOutput } from './code-outputs.mjs' // a file a reply produced, for the page's automatic preview
import { OUTPUT_ROUTE } from '../spaces/public/codeOutputs.js'
import { SEEN_ROUTE, normSeen, mergeSeen } from '../spaces/public/codeUnread.js' // what the person has seen, shared by their devices
import { mkdirIn, MKDIR_ROUTE } from './code-mkdir.mjs' // "new folder" in the New-session picker, answered here — re-exports the page constant
import { WitbitzNotes } from './opencode-plugins/witbitz-notes.js' // project notes: the connector allows reads of a session's notes folder
import { probeTools } from './code-tools-probe.mjs' // "Set up this computer": which suggested tools are installed (a PATH lookup)
import { startAutoRunner } from './code-auto-runner.mjs' // Auto mode: permission asks decided here (docs/code-auto-mode.md)
import { createAskBook, ASK_FRAME } from './code-asks.mjs' // what is waiting, from the event stream — OpenCode's own list can break
import { folderRoute, FOLDER_ROUTE } from './code-folders.mjs' // "allow this folder": one card for a whole folder outside the project

export const VERSION = '1'
export const PAIRINGS_PATH = process.env.WITBITZ_CODE_PAIRINGS || join(homedir(), '.witbitz', 'code', 'pairings.json')
// What this connector can do beyond the requests, announced in hello. The page shows Auto only when `auto` is here, and
// tells a computer it runs an older witbitz-code when one of spaces/public/codeUpdate.js CONNECTOR_CAPS is missing.
const CAPS = ['auto', 'attachments', 'outputs', 'tools', 'seen', 'asks', 'folders']
const AUTO_DIR = process.env.WITBITZ_CODE_AUTO_DIR || join(homedir(), '.witbitz', 'code') // Auto state (per pairing) + the verdict log
const DEFAULT_ENV = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')
const REQUEST_TIMEOUT_MS = 30_000
const HELLO_EVERY_MS = 20_000 // the page counts the computer online while a hello arrived in the last 30 s
const SUB_TTL_MS = 75_000 // a page re-subscribes every 30 s; a subscription nobody renews is dropped
const ASKS_RECONCILE_MS = 30_000 // how often recorded asks are checked against which sessions still run
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
export async function startConnector({ pairings, fetchImpl = fetch, WebSocketImpl = globalThis.WebSocket, flushMs = 120, log = console.error, requestTimeoutMs = REQUEST_TIMEOUT_MS, maxSenders = 64, maxResponseBytes = MAX_RESPONSE, autoDir = AUTO_DIR, autoPollMs = 1000, attachRoot = ATTACH_ROOT, readTextFor = tinfoilReaderForKey, attachMaxFileBytes = MAX_FILE_BYTES, notesRoot = WitbitzNotes.helpers.NOTES_ROOT, notesPluginPath = NOTES_PLUGIN, toolsProbe = probeTools, caps = CAPS, asksReconcileMs = ASKS_RECONCILE_MS } = {}) {
  const running = []
  try { const n = pruneAttachments(attachRoot); if (n) log(`opencode-connector: removed ${n} attachment folder(s) untouched for 30 days`) } catch { /* no folder yet */ }
  for (const p of pairings) running.push(await servePairing(p, { fetchImpl, WebSocketImpl, flushMs, log, requestTimeoutMs, maxSenders, maxResponseBytes, autoDir, autoPollMs, attachRoot, readTextFor, attachMaxFileBytes, notesRoot, notesPluginPath, toolsProbe, caps, asksReconcileMs }))
  return {
    peers: running.map((r) => r.peer),
    /** What the confidential-model proxy is doing for a session (code-confidential.mjs onProgress), to the phones. */
    progress: (ev) => { for (const r of running) if (r.peer.peers >= 2) r.peer.send({ t: 'progress', ...ev, ts: Date.now() }).catch(() => {}) },
    stop: () => { for (const r of running) r.stop() },
  }
}

const NOTES_PLUGIN = join(homedir(), '.config', 'opencode', 'plugins', 'witbitz-notes.js') // installed by tools/opencode-config.mjs

// The Tinfoil reader for this computer's key, read at request time (adding a key needs no restart); null without one.
let readerKey = '', reader = null
function tinfoilReaderForKey() {
  const key = tinfoilKey()
  if (!key) return null
  if (key !== readerKey) { readerKey = key; reader = makeTinfoilReader({ apiKey: key }) }
  return reader
}

async function servePairing(pairing, { fetchImpl, WebSocketImpl, flushMs, log, requestTimeoutMs, maxSenders, maxResponseBytes, autoDir, autoPollMs, attachRoot, readTextFor, attachMaxFileBytes, notesRoot, notesPluginPath, toolsProbe, caps, asksReconcileMs }) {
  const name = pairing.name || hostname()
  const base = String(pairing.opencodeUrl || 'http://127.0.0.1:4096').replace(/\/+$/, '')
  const password = () => pairing.password || parseEnvPassword(existsSync(pairing.envFile || DEFAULT_ENV) ? readFileSync(pairing.envFile || DEFAULT_ENV, 'utf8') : '')
  const auth = () => { const pw = password(); return pw ? { authorization: 'Basic ' + Buffer.from('opencode:' + pw).toString('base64') } : {} }
  const inflight = new Map() // request id → AbortController
  const subs = new Map() // event path → { ctrl, clients: Map(client id → last renewed), buffer, timer }
  let helloTimer = 0
  let auto = null // Auto mode's loop for this pairing — created before the relay opens, so the first hello can list it
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

  // caps: what this connector can do beyond the requests — a page shows the Auto switch only when `auto` is here.
  function hello() { if (nonce) peer.send({ t: 'hello', ver: VERSION, name, computerId: pairing.computerId || '', k: nonce, ts: Date.now(), caps, auto: auto ? auto.sessions() : [] }) }

  async function handle(m) {
    if (!m || typeof m.t !== 'string') return
    if (m.t === 'ping') return hello()
    const current = typeof m.k === 'string' && m.k === nonce
    if (m.t === 'cancel') { if (current) { const c = inflight.get(m.id); if (c) c.abort() } return }
    if (m.t === 'sub') { if (current) subscribe(m.p, m.c); return }
    if (m.t === 'unsub') { if (current) unsubscribe(m.p, m.c); return }
    // Auto mode on/off for one session — nonce-checked like a request (a recording cannot switch it). No new power: a page
    // that can switch Auto could already answer the same asks itself.
    if (m.t === 'auto') { if (current && auto && auto.setAuto(m.sid, m.dir, !!m.on)) hello(); return }
    // Which suggested tools this computer has (spaces/public/codeTools.js) — a PATH lookup, nonce-checked like a request.
    // An older connector never answers, and the page offers nothing.
    if (m.t === 'tools') { if (current) peer.send({ t: 'tools', ...toolsProbe() }); return }
    if (m.t !== 'req') return
    const id = typeof m.id === 'string' ? m.id : ''
    if (!id) return
    const reply = (st, b) => peer.send({ t: 'res', id, st, b: typeof b === 'string' ? b : JSON.stringify(b) })
    // Refuse rather than truncate: a shortened id could collide, and `cancel` would look up the long one.
    if (id.length > 64) return reply(400, { error: 'request id longer than 64 characters' })
    if (!current) return reply(409, { error: 'stale: this computer\'s connector changed — reconnecting' })
    const [path, query = ''] = m.p.split('?')
    // A saved attachment, for the page's chip (preview, download): answered HERE from the attachments folder, never forwarded.
    if (m.m === 'GET' && path === ATTACHMENT_ROUTE) {
      const u = new URLSearchParams(query)
      const out = serveAttachment({ root: attachRoot, session: u.get('session'), file: u.get('file') })
      return reply(out.st, out.b)
    }
    // A file a reply produced, for the page's preview under it (spaces/public/codeOutputs.js): answered HERE, from the
    // folder OpenCode reports for the session — never one the page names — and logged on this computer (a digest of the
    // path, never the path).
    if (m.m === 'GET' && path === OUTPUT_ROUTE) {
      const u = new URLSearchParams(query)
      const sid = u.get('session') || ''
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(sid)) return reply(400, { error: 'not a session id' })
      const dirQuery = u.get('directory') ? `directory=${encodeURIComponent(u.get('directory'))}` : ''
      const session = await sessionFor(sid, dirQuery)
      if (!session || typeof session.directory !== 'string') return reply(404, { error: 'no such session on this computer' })
      const statOnly = u.get('stat') === '1'
      const out = serveOutput({ directory: session.directory, path: u.get('path'), stat: statOnly })
      logOutput({ at: Date.now(), session: sid, digest: createHash('sha256').update(String(u.get('path') || '')).digest('hex'), stat: statOnly, st: out.st })
      return reply(out.st, out.b)
    }
    // What the person has seen, shared by their devices (spaces/public/codeUnread.js — the owner: "When I switch devices I get
    // green dots"): answered HERE and kept on this computer. GET: the record. POST a device's record: merged, and the merge back.
    if (path === SEEN_ROUTE && (m.m === 'GET' || m.m === 'POST')) {
      if (m.m === 'GET') return reply(200, seenRecord())
      if (typeof m.b !== 'string' || m.b.length > 1_000_000) return reply(413, { error: 'a seen record is at most 1 MB' })
      let incoming = null
      try { incoming = JSON.parse(m.b) } catch { /* below */ }
      if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) return reply(400, { error: 'not a seen record' })
      const merged = mergeSeen(seenRecord(), normSeen(incoming))
      if (merged !== seen) { seen = merged; saveSeen() }
      return reply(200, merged)
    }
    // "NEW FOLDER" in the New-session picker (tools/code-mkdir.mjs): the page names the home (directory) and the
    // relative path under it (path) it is already listing, and a single clean leaf name (name). Answered HERE, never
    // forwarded to OpenCode. It adds no new power: the page could already list a folder there and a session could already
    // create it; only the realpath containment check below stops a link from smuggling the write out of the root.
    if (m.m === 'POST' && path === MKDIR_ROUTE) {
      const u = new URLSearchParams(query)
      const home = u.get('directory'), rel = u.get('path')
      if (typeof home !== 'string' || !home) return reply(400, { error: 'no home to create under' })
      let parsed = null
      try { parsed = m.b ? JSON.parse(m.b) : null } catch { /* below */ }
      if (!parsed || typeof parsed !== 'object' || typeof parsed.name !== 'string') return reply(400, { error: 'no folder name' })
      const out = mkdirIn({ root: home, rel, name: parsed.name })
      return reply(out.st, out.b)
    }
    // "ALLOW THIS FOLDER" (tools/code-folders.mjs): the folder a waiting outside-the-project ask belongs to, and allowing it for
    // the conversation. Answered HERE; the folder comes from the ask and the disk, never from the page.
    if (path === FOLDER_ROUTE && (m.m === 'GET' || m.m === 'POST')) {
      const out = await folderRoute({ method: m.m, query, body: m.b, pending: pendingAsks, call: opencodeJson, log: (l) => log(`opencode-connector: ${name} · ${l}`) })
      return reply(out.st, out.b)
    }
    if (!allowedRequest(m.m, m.p)) return reply(403, { error: 'not allowed by the connector' })
    // What is still waiting (the page's card recovery): OpenCode's list when it can give one, else the asks its event stream
    // carried (tools/code-asks.mjs — one malformed ask breaks OpenCode's list for the whole folder). null: forwarded as before.
    if (m.m === 'GET' && path === '/permission') {
      const dir = new URLSearchParams(query).get('directory')
      const list = dir ? await pendingAsks(dir) : null
      if (list) return reply(200, list)
    }
    // ATTACHMENTS (docs/code-attachments.md): the files a turn carries are saved on this computer and the message names them.
    let body = typeof m.b === 'string' ? m.b : undefined
    const turnOf = m.m === 'POST' && /^\/session\/([^/]+)\/message$/.exec(path)
    // PROJECT NOTES (tools/opencode-plugins/witbitz-notes.js), every turn, only where the plugin is installed: reads of ITS
    // project's notes folder and writes into notes/ ask nothing, whatever the model — one note used to cost FOUR approvals
    // (external_directory + edit, for the note and its INDEX.md; measured 2026-09-14) and a model that writes notes
    // reluctantly gave up. AGENTS.md — injected as INSTRUCTIONS — still asks for every edit.
    if (turnOf && existsSync(notesPluginPath)) await ruleNotes(turnOf[1], query)
    if (turnOf && body && body.includes('"file"')) {
      let parsed = null
      try { parsed = JSON.parse(body) } catch { /* OpenCode answers a malformed body itself */ }
      if (parsed && Array.isArray(parsed.parts) && parsed.parts.some((p) => p && p.type === 'file' && /^data:/.test(String(p.url || '')))) {
        // Only for a session OpenCode has — an invented id must not get a folder (security review: disk filling).
        const known = await sessionFor(turnOf[1], query)
        if (!known) return reply(404, { error: 'no such session on this computer' })
        pruneDaily()
        const staged = await stageMessageBody(parsed, { sessionID: turnOf[1], root: attachRoot, readText: readTextFor(), maxFileBytes: attachMaxFileBytes })
        if (staged && staged.error) return reply(staged.error.status, { error: staged.error.message })
        if (staged) { await allowAttachmentReads(turnOf[1], query, known); body = JSON.stringify(staged.body) }
      }
    }
    const ctrl = new AbortController()
    inflight.set(id, ctrl)
    let timedOut = false
    // A turn POST returns only when the model has finished; it has no timeout (its progress rides the event stream).
    const timer = /\/message$/.test(m.p.split('?')[0]) && m.m === 'POST' ? 0 : setTimeout(() => { timedOut = true; ctrl.abort() }, requestTimeoutMs)
    try {
      const r = await fetchImpl(base + m.p, {
        method: m.m,
        headers: { ...auth(), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
        body,
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
      const gone = m.m === 'DELETE' && r.ok && /^\/session\/([^/]+)$/.exec(path)
      if (gone) removeSessionAttachments(attachRoot, gone[1]) // a deleted session takes its saved files along
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

  // The agent reads saved attachments outside the project; our sessions ask for that (external_directory). One rule per
  // session allows reads in THAT session's folder and nowhere else — measured: PATCH /session/:id APPENDS it to a session
  // that already exists; a same-prefix sibling folder, another session's folder and the root still ask.
  const ruled = new Set()
  /** The session as OpenCode has it, or null when it has no such session (or cannot say). */
  // What the person has seen (SEEN_ROUTE above), per pairing, beside Auto's state — read once, written as it changes.
  const seenFile = join(autoDir, `seen-${String(pairing.computerId || 'default').replace(/[^A-Za-z0-9_-]/g, '_')}.json`)
  let seen = null
  function seenRecord() {
    if (!seen) { try { seen = normSeen(JSON.parse(readFileSync(seenFile, 'utf8'))) } catch { seen = normSeen(null) } }
    return seen
  }
  function saveSeen() {
    try { mkdirSync(autoDir, { recursive: true }); writeFileSync(seenFile + '.tmp', JSON.stringify(seen), { mode: 0o600 }); renameSync(seenFile + '.tmp', seenFile) } catch (e) { log(`opencode-connector: ${name} · could not keep what was seen (${e && e.message})`) }
  }
  // Each preview fetch, on this computer: when, which session, a digest of the path (never the path), stat or bytes, the answer.
  function logOutput(rec) {
    try { mkdirSync(autoDir, { recursive: true }); appendFileSync(join(autoDir, 'output-log.jsonl'), JSON.stringify(rec) + '\n', { mode: 0o600 }) } catch { /* a log never breaks a preview */ }
  }
  async function sessionFor(sid, query) {
    try {
      const r = await fetchImpl(`${base}/session/${sid}${query ? '?' + query : ''}`, { headers: auth() })
      if (!r.ok) return null
      const s = await r.json().catch(() => null)
      return s && typeof s === 'object' ? s : null
    } catch { return null }
  }
  let prunedAt = Date.now()
  function pruneDaily() {
    if (Date.now() - prunedAt < 86_400_000) return
    prunedAt = Date.now()
    try { pruneAttachments(attachRoot) } catch { /* next time */ }
  }
  async function allowAttachmentReads(sid, query, s) {
    if (ruled.has(sid)) return
    if (await addRules(sid, query, s, [attachmentRule(attachRoot, sid)], 'attachment')) ruled.add(sid) // this session's folder only
  }
  /** The notes rules for one turn (see handle). Appends only what does not already take effect — last match wins. */
  async function ruleNotes(sid, query) {
    const s = await sessionFor(sid, query)
    const root = s && WitbitzNotes.helpers.rootFromSession(s)
    if (!root) return
    const dir = `${notesRoot}/${WitbitzNotes.helpers.notesKey(resolve(root))}`
    // The edit tool's pattern is relative to the WORKTREE (measured): the git root, or "/" for a plain folder — whose
    // session path is its directory without the leading "/".
    const plain = !!s.path && s.directory === '/' + s.path
    const rel = relative(plain ? '/' : resolve(root), dir)
    const want = [
      { permission: 'external_directory', pattern: `${dir}/*`, action: 'allow' },
      // One notes folder for every model (the owner removed the confidential split, 2026-09-14). A session from before may
      // still hold that version's `deny` on notes/ from a confidential turn — the allow is appended after it, and wins.
      { permission: 'edit', pattern: `${rel}/notes/*`, action: 'allow' },
    ]
    const have = Array.isArray(s.permission) ? s.permission : []
    const effective = (rule) => { let a = null; for (const r of have) if (r && r.permission === rule.permission && r.pattern === rule.pattern) a = r.action; return a }
    const missing = want.filter((rule) => effective(rule) !== rule.action)
    if (missing.length) await addRules(sid, query, s, missing, 'project notes', { always: true })
  }
  /** Append the rules the session does not have yet (PATCH appends — measured). True when they are in place. */
  async function addRules(sid, query, s, rules, what, { always = false } = {}) {
    const have = Array.isArray(s && s.permission) ? s.permission : []
    const missing = always ? rules : rules.filter((rule) => !have.some((r) => r && r.permission === rule.permission && r.pattern === rule.pattern && r.action === rule.action))
    if (!missing.length) return true
    try {
      const p = await fetchImpl(`${base}/session/${sid}${query ? '?' + query : ''}`, { method: 'PATCH', headers: { ...auth(), 'content-type': 'application/json' }, body: JSON.stringify({ permission: missing }) })
      if (!p.ok) throw new Error(`PATCH answered ${p.status}`)
      if (Array.isArray(s && s.permission)) s.permission.push(...missing)
      return true
    } catch (e) { log(`opencode-connector: ${name} · could not allow ${what} reads for ${sid} (${e && e.message}) — reading them will ask`); return false }
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

  // ── WHAT IS WAITING (tools/code-asks.mjs) ── OpenCode's GET /permission breaks for a whole folder on one ask with an
  // undefined in its metadata, and keeps a stopped turn's asks forever. So every folder's asks are followed on
  // /global/event — whether or not a page is open — and a dead ask (its session stopped) is replied to, which heals the list.
  const asks = createAskBook()
  const watch = { ctrl: new AbortController(), live: false, epoch: 0 } // epoch: one per connection of the stream
  const complete = new Map() // directory → the epoch in which its whole list was read — the book knows every ask since
  const triedAt = new Map() // directory → when a whole read was last tried for a folder the book does not know in full
  const suspects = new Map() // directory → ask ids whose session was not running at the last check
  const opencodeCall = (method, path, directory, body) => fetchImpl(`${base}${path}${path.includes('?') ? '&' : '?'}directory=${encodeURIComponent(directory)}`, {
    method, headers: { ...auth(), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined, signal: AbortSignal.any([watch.ctrl.signal, AbortSignal.timeout(requestTimeoutMs)]),
  })
  const opencodeJson = async (method, path, directory, body) => { const r = await opencodeCall(method, path, directory, body); return { ok: r.ok, status: r.status, json: await r.json().catch(() => null) } }
  async function settleDead(dead) {
    for (const { directory, ask } of dead) {
      try {
        const r = await opencodeCall('POST', `/permission/${encodeURIComponent(ask.id)}/reply`, directory, { reply: 'reject' })
        if (r.ok) log(`opencode-connector: ${name} · cleared a ${ask.permission || 'permission'} approval a stopped turn left waiting`)
      } catch { /* OpenCode restarting: the ask went with it */ }
    }
  }
  /** OpenCode's list of waiting asks in a folder; the recorded ones when that list fails; null when neither can say.
   *  The book answers only for a folder it has followed since a whole read, on the same connection: an ask from before
   *  that is unknown to it, and a list missing it would read as "answered" — the page drops the card, Auto a held refusal. */
  async function pendingAsks(directory) {
    const epoch = watch.live ? watch.epoch : -1
    try {
      const r = await opencodeCall('GET', '/permission', directory)
      const list = await r.json().catch(() => null)
      if (r.ok && Array.isArray(list)) {
        asks.merge(directory, list)
        if (epoch >= 0 && watch.live && watch.epoch === epoch) complete.set(directory, epoch)
        return list
      }
    } catch { return null } // OpenCode is not answering
    return watch.live && complete.get(directory) === watch.epoch ? asks.list(directory) : null
  }
  /** A folder with activity whose list the book does not know in full: read it now, while no broken ask is in it yet. */
  function learnFolder(directory) {
    if (!directory || complete.get(directory) === watch.epoch || Date.now() - (triedAt.get(directory) || 0) < 5000) return
    triedAt.set(directory, Date.now())
    pendingAsks(directory)
  }
  /** Asks whose session is not running at TWO checks in a row are dead (a stop the stream missed) — one reading never
   *  rejects a live ask. A stop the stream saw is settled at once by its idle event. */
  async function reconcileAsks() {
    for (const directory of asks.directories()) {
      const known = asks.list(directory)
      try {
        const r = await opencodeCall('GET', '/session/status', directory)
        const status = r.ok ? await r.json().catch(() => null) : null
        if (!status || typeof status !== 'object' || Array.isArray(status)) continue
        const busy = Object.keys(status).filter((sid) => status[sid] && status[sid].type !== 'idle')
        const before = suspects.get(directory) || new Set()
        const notRunning = known.filter((a) => !busy.includes(a.sessionID)).map((a) => a.id)
        suspects.set(directory, new Set(notRunning))
        await settleDead(asks.settleIdle(directory, busy, notRunning.filter((id) => before.has(id))))
      } catch { /* next time */ }
    }
    for (const directory of [...suspects.keys()]) if (!asks.directories().includes(directory)) suspects.delete(directory)
  }
  ;(async () => {
    let wait = 1000
    while (!watch.ctrl.signal.aborted) {
      try {
        const r = await fetchImpl(`${base}/global/event`, { headers: { ...auth(), accept: 'text/event-stream' }, signal: watch.ctrl.signal })
        if (!r.ok || !r.body || !/event-stream/.test(r.headers.get('content-type') || '')) throw new Error(`global event stream ${r.status}`)
        watch.epoch++
        watch.live = true
        wait = 1000
        reconcileAsks() // a turn stopped while the stream was down
        const feed = sseReader((data) => {
          if (!ASK_FRAME.test(data)) return
          let frame = null
          try { frame = JSON.parse(data) } catch { return }
          const dead = asks.apply(frame)
          if (dead.length) settleDead(dead)
          learnFolder(frame && typeof frame.directory === 'string' ? frame.directory : '')
        })
        const dec = new TextDecoder()
        for await (const chunk of r.body) feed(dec.decode(chunk, { stream: true }))
      } catch { /* stopped, OpenCode restarted, or an OpenCode without /global/event */ }
      watch.live = false
      if (watch.ctrl.signal.aborted) break
      await new Promise((res) => { const t = setTimeout(res, wait); watch.ctrl.signal.addEventListener('abort', () => { clearTimeout(t); res() }, { once: true }) })
      wait = Math.min(wait * 2, 30_000)
    }
  })()
  const reconcileTimer = setInterval(() => { if (watch.live) reconcileAsks() }, asksReconcileMs)

  const safeId = String(pairing.computerId || 'default').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64)
  auto = startAutoRunner({
    base, auth, fetchImpl, log, pollMs: autoPollMs, listAsks: pendingAsks,
    statePath: join(autoDir, `auto-${safeId}.json`), logPath: join(autoDir, 'auto-log.jsonl'),
    onVerdict: (v) => peer.send({ t: 'autoverdict', ...v, ts: Date.now() }),
  })

  await peer.start()
  return {
    peer,
    stop: () => {
      clearInterval(sweep); clearInterval(helloTimer); clearInterval(reconcileTimer)
      watch.ctrl.abort()
      if (auto) auto.stop()
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
  // Confidential models (tools/code-confidential.mjs): OpenCode's TrustedRouter calls come through here, so a model the
  // catalog calls confidential really runs in the confidential pool, receipt-verified, and gets pictures through Tinfoil.
  const proxyPort = proxyPortFor(pi >= 0 ? Number(args[pi + 1]) : 4096)
  let proxy = null
  try { proxy = await startConfidentialProxy({ port: proxyPort, onProgress: (ev) => c.progress(ev) }); console.error(`opencode-connector: confidential models via 127.0.0.1:${proxy.port}`) } catch (e) { console.error(`opencode-connector: could not start the confidential-model proxy on 127.0.0.1:${proxyPort} (${(e && e.code) || (e && e.message)}) — TrustedRouter calls from OpenCode will fail until it can`) }
  const bye = () => { c.stop(); if (proxy) proxy.close(); process.exit(0) }
  process.on('SIGINT', bye); process.on('SIGTERM', bye)
  const pp = args.indexOf('--parent')
  watchParent({ parent: pp >= 0 ? Number(args[pp + 1]) : 0, onGone: () => { console.error('opencode-connector: the script that started me is gone — stopping'); bye() } })
}

// (WITBITZ_CODE_BUNDLED is defined at bundle time: inside witbitz-code.mjs every module shares one import.meta.url.)
if (process.env.WITBITZ_CODE_BUNDLED !== "1" && process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((e) => { console.error('opencode-connector: FATAL —', (e && e.message) || e); process.exit(1) })
}
