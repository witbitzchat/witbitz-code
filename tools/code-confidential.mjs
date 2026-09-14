// tools/code-confidential.mjs — CONFIDENTIAL models in the Code section, made true on the user's own computer.
//
// The owner found that "· confidential" in Code was only a label: OpenCode calls TrustedRouter directly, so nothing asked
// for the confidential pool and nothing checked where a request ran — while a confidential ROOM refuses any answer whose
// signed receipt does not prove a TEE-verified upstream (agent/inferenceReceipt.mjs). And a confidential model that cannot
// see pictures simply lost them. This is the room's discipline, run by the connector on 127.0.0.1:
//
//   OpenCode ──http──▶ this proxy ──https──▶ api.trustedrouter.com
//
//   • a model NOT in the catalog's confidential tier → passed through byte for byte (no rewrite, no check).
//   • a CONFIDENTIAL model →
//       1. images / documents it cannot read become TEXT first, through Tinfoil's attested enclaves — the connector
//          verifies Tinfoil's AMD SEV-SNP evidence and pins TLS to the attested key before any byte leaves
//          (agent/tinfoilAttest.mjs + attestedTool.mjs), with the USER's own TINFOIL_API_KEY. No key, or no attestation ⇒
//          the turn is refused with a plain reason; the file is never sent anywhere less.
//       2. the request carries TrustedRouter's hard floor `provider.min_privacy = confidential`, goes out only after the
//          gateway's Google Confidential Space attestation verifies (gatewayAttest.mjs), with a fresh receipt nonce;
//       3. the answer streams through as it arrives, but everything that COMMITS the step — tool calls, the finish reason,
//          usage, [DONE] — is held until TrustedRouter's signed inference receipt verifies for these exact request and
//          response bytes (inferenceReceipt.mjs). A receipt that does not verify ends the step with an error instead, so
//          OpenCode runs no tool and records the failure: "not confidential: <reason>".
//       4. ONE refusal is asked again (agent/attestedRetry.mjs): `receipt_verification_window`. TrustedRouter renews its
//          proof of the model's enclave every 900 s and signs the receipt when the answer ENDS, so an answer still
//          streaming as a proof lapses is refused (the owner: "I sometimes get this"). A fresh call re-runs the whole
//          check. It can only be asked again while nothing of the refused answer has reached OpenCode — so an answer
//          that STARTS near the end of the last proof seen is held back whole (like a tool call) instead of streamed.
//          When words WERE already shown and the receipt's only fault is the window (every other check held), it is still
//          asked again — held back, and only the new answer's ACTIONS are passed on (its words would repeat what is on
//          screen). The shown words stay; no tool from the refused answer ever reaches OpenCode.
//       5. What it is doing is reported (onProgress → the connector → the page): waiting for the first word, writing a
//          tool call (name, file, size — never its contents), checking the receipt, asking again. OpenCode never sees
//          these: its AI SDK runs every tool call left unfinished when a stream closes, so a tool call's start cannot be
//          shown through OpenCode before the receipt verifies.
//
// Who pays: the user — TrustedRouter with their key (OpenCode's own), Tinfoil with theirs. Witbitz is not on this path.
import http from 'node:http'
import { createHash } from 'node:crypto'
import { readFileSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { CATALOG } from '../agent/modelCatalog.mjs'
import { verifyGatewayAttestation } from '../agent/gatewayAttest.mjs'
import { newReceiptNonce, newSseCapture, feedSsePayload, verifyInferenceReceipt } from '../agent/inferenceReceipt.mjs'
import { RETRYABLE, isRetryableReceiptFailure } from '../agent/attestedRetry.mjs'
import { callAttestedTool } from '../agent/attestedTool.mjs'
import { makeTinfoilVision } from '../agent/tinfoilVision.mjs'
import { makeTinfoilExtractor } from '../agent/tinfoilDocRead.mjs'

export const TR_UPSTREAM = 'https://api.trustedrouter.com'
export const PROXY_PORT_OFFSET = 100 // OpenCode on 4096 → this proxy on 4196
export const proxyPortFor = (opencodePort) => Number(process.env.WITBITZ_TR_PROXY_PORT) || (Number(opencodePort) || 4096) + PROXY_PORT_OFFSET
// The declarations a confidential Space's measured policy uses (infra/enclave/policy.json) — the same enclaves, verified the same way.
const TINFOIL_VISION = { root: 'tinfoil', repo: 'tinfoilsh/confidential-model-router', host: 'inference.tinfoil.sh', path: '/v1/chat/completions' }
const TINFOIL_DOCS = { root: 'tinfoil', repo: 'tinfoilsh/confidential-model-router', host: 'inference.tinfoil.sh', path: '/v1/convert/file' }
const GATE_TTL_MS = 600_000
const MAX_BODY = 40 * 1024 * 1024
const CACHE_MAX = 200

// ── which models ─────────────────────────────────────────────────────────────────────────────────────────────────────
/** TrustedRouter model id → { vision } for every model the catalog offers on the CONFIDENTIAL tier. The catalog's
 *  confidential eligibility is live-probed (agent/modelCatalog.mjs); this is that list, not a second one. */
export function confidentialModels(catalog = CATALOG) {
  const out = new Map()
  for (const m of catalog) if (m.route === 'trustedrouter' && (m.tiers || []).includes('confidential')) out.set(m.model, { vision: m.vision !== false, label: m.label })
  return out
}

// ── files a model cannot read ────────────────────────────────────────────────────────────────────────────────────────
const parseDataUrl = (url) => { const m = /^data:([^;,]+)?(?:;[^,]*)?;base64,(.*)$/s.exec(String(url || '')); return m ? { mime: m[1] || 'application/octet-stream', b64: m[2] } : null }
/** The parts of a chat request that are not text: [{ at: [message, part], kind: 'image'|'file', mime, b64, name }]. */
export function unreadableParts(body) {
  const found = []
  for (const [mi, msg] of (Array.isArray(body && body.messages) ? body.messages : []).entries()) {
    if (!Array.isArray(msg && msg.content)) continue
    for (const [pi, part] of msg.content.entries()) {
      if (part && part.type === 'image_url') {
        const d = parseDataUrl(part.image_url && part.image_url.url)
        found.push({ at: [mi, pi], kind: 'image', mime: d ? d.mime : '', b64: d ? d.b64 : '', remote: !d })
      } else if (part && part.type === 'file') {
        const f = part.file || {}
        const d = parseDataUrl(f.file_data)
        found.push({ at: [mi, pi], kind: 'file', mime: d ? d.mime : '', b64: d ? d.b64 : '', name: f.filename || 'file', remote: !d })
      }
    }
  }
  return found
}
const textOf = (msg) => (Array.isArray(msg.content) ? msg.content.filter((p) => p && p.type === 'text').map((p) => p.text).join('\n') : String(msg.content || ''))

/** A reader that turns images and documents into text through Tinfoil, cached by content (OpenCode re-sends the whole
 *  conversation every step, so without a cache one screenshot would be described again on every turn). */
export function makeTinfoilReader({ apiKey, call = callAttestedTool, vision, docs } = {}) {
  const look = vision || makeTinfoilVision({ apiKey, call, decl: TINFOIL_VISION })
  const read = docs || makeTinfoilExtractor({ apiKey, call, decl: TINFOIL_DOCS })
  const cache = new Map()
  const remember = (k, v) => { cache.set(k, v); if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value) }
  return async function toText(item, question) {
    const k = createHash('sha256').update(item.kind + '\0' + item.b64 + '\0' + (item.kind === 'image' ? question : '')).digest('hex')
    if (cache.has(k)) return cache.get(k)
    const text = item.kind === 'image'
      ? await look({ b64: item.b64, mime: item.mime }, { question })
      : (await read({ b64: item.b64, mime: item.mime, name: item.name })).text
    remember(k, text)
    return text
  }
}

const refuse = (status, message, type = 'confidential_refused') => { const e = new Error(message); e.status = status; e.type = type; return e }

/** Replace every image/file part with Tinfoil's text, in place of the bytes. Throws a refusal the proxy answers with. */
export async function convertUnreadable(body, { label, toText }) {
  const parts = unreadableParts(body)
  if (!parts.length) return { body, converted: 0 }
  if (!toText) throw refuse(400, `${label} cannot read images or files, and this computer has no Tinfoil key to read them confidentially. Add one (witbitz-code tinfoil-key), or pick a model that can read them.`, 'tinfoil_key_missing')
  const messages = body.messages.map((m) => (Array.isArray(m.content) ? { ...m, content: [...m.content] } : m))
  for (const p of parts) {
    const [mi, pi] = p.at
    const where = p.kind === 'image' ? 'an image' : `the file "${p.name}"`
    if (p.remote || !p.b64) throw refuse(400, `${label} cannot read ${where} that is not attached inline.`)
    const question = `Describe this image for a coding assistant that cannot see it: its layout and every visible piece of text, code, numbers and UI elements, quoted verbatim. The person's message with it: "${textOf(body.messages[mi]).slice(0, 600)}"`
    let text
    try { text = await toText(p, question) } catch (e) {
      const code = e && e.code
      if (code === 'tool_unavailable') throw refuse(502, `${label}: Tinfoil's enclave did not prove what it runs, so ${where} was not sent (${String(e.message).slice(0, 140)}).`, 'tinfoil_unattested')
      if (/answered 40[13]\b/.test(String(e && e.message))) throw refuse(400, `${label}: Tinfoil did not accept this computer's key, so ${where} could not be read. Check TINFOIL_API_KEY (witbitz-code tinfoil-key).`, 'tinfoil_key_rejected')
      throw refuse(502, `${label}: Tinfoil could not read ${where} (${String((e && e.message) || e).slice(0, 140)}).`, 'tinfoil_failed')
    }
    const head = p.kind === 'image'
      ? '[An image was attached. This model cannot see images, so it was read inside Tinfoil\'s attested enclave; this is what it shows:]'
      : `[The file "${p.name}" was attached. It was read inside Tinfoil's attested enclave; its text:]`
    messages[mi].content[pi] = { type: 'text', text: `${head}\n${text}` }
  }
  return { body: { ...body, messages }, converted: parts.length }
}

/** The confidential floor, as a confidential room stamps it: min_privacy, and always streaming (the receipt is only
 *  embedded with its attestation in the streaming form). Key ORDER matters — the receipt signs these exact bytes. */
export function stampFloor(req) {
  return { ...req, stream: true, stream_options: { include_usage: true }, provider: { ...(req.provider || {}), min_privacy: 'confidential' } }
}

// ── the answer ───────────────────────────────────────────────────────────────────────────────────────────────────────
/** Splits an SSE byte stream into frames; for each `data:` payload, decides whether it may go to OpenCode NOW. Answer text
 *  and reasoning flow live; from the first event that commits anything (tool calls, a finish reason, usage, [DONE], an
 *  error) everything is held, in order, until the receipt verdict. The receipt event itself never reaches OpenCode.
 *  `hold`: nothing flows live — the whole answer waits for the verdict (so a refusal can still be asked again). */
export function makeAnswerGate({ hold = false } = {}) {
  const capture = newSseCapture()
  const held = []
  let holding = hold, buf = ''
  const calls = [] // index → { name, args } as the held tool calls arrive — for progress only, never forwarded from here
  const track = (ev) => {
    const d = ev && ev.choices && ev.choices[0] && ev.choices[0].delta
    for (const t of (d && d.tool_calls) || []) {
      const ix = typeof t.index === 'number' ? t.index : calls.length
      const c = calls[ix] || (calls[ix] = { name: '', args: '' })
      if (t.function && typeof t.function.name === 'string') c.name += t.function.name
      if (t.function && typeof t.function.arguments === 'string') c.args += t.function.arguments
    }
  }
  const live = (ev) => {
    if (!ev || ev.error || ev.usage) return false
    const ch = ev.choices && ev.choices[0]
    if (!ch) return false
    if (ch.finish_reason) return false
    const d = ch.delta || {}
    return !d.tool_calls && !d.function_call
  }
  return {
    capture,
    /** Feed bytes; returns the frames that may be written to OpenCode now. */
    push(chunk) {
      buf += chunk
      const out = []
      let i
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, i + 2); buf = buf.slice(i + 2)
        const line = frame.split('\n').find((l) => l.startsWith('data:'))
        if (!line) continue
        const payload = line.slice(5).trim()
        if (!payload) continue
        feedSsePayload(capture, payload) // exactly as the room's reader frames it: the receipt hashes these bytes
        let ev = null
        if (payload !== '[DONE]') { try { ev = JSON.parse(payload) } catch { /* hashed above; never forwarded as-is */ } }
        if (ev && ev.inference_receipt) continue
        track(ev)
        if (!holding && ev && live(ev)) { out.push(`data: ${payload}\n\n`); continue }
        holding = true
        held.push(`data: ${payload}\n\n`)
      }
      return out
    },
    held: () => held,
    /** The tool call being written now: { tool, subject, chars } — the subject is the file, path or command when its JSON
     *  string has arrived whole. null before any. */
    writing: () => {
      const c = calls.filter(Boolean).pop()
      if (!c || !c.name) return null
      return { tool: c.name, subject: subjectOf(c.args.slice(0, SUBJECT_SCAN)), chars: c.args.length } // a path comes first; a 100 KB file's body is not re-scanned per chunk
    },
    events: () => capture.datas.map((b) => { try { return JSON.parse(b.toString('utf8')) } catch { return null } }).filter(Boolean),
  }
}

const SUBJECT_SCAN = 4000
const SUBJECT = /"(filePath|path|command|pattern|url)"\s*:\s*"((?:[^"\\]|\\.)*)"/
function subjectOf(args) {
  const m = SUBJECT.exec(args)
  if (!m) return ''
  try { return String(JSON.parse(`"${m[2]}"`)).slice(0, 200) } catch { return '' }
}

/** A held frame without the answer's words (content, reasoning) — for an answer asked again after words were shown.
 *  '' when nothing but words (or a bare role) is left. */
export function withoutWords(frame) {
  const line = String(frame).split('\n').find((l) => l.startsWith('data:'))
  const payload = line ? line.slice(5).trim() : ''
  if (!payload || payload === '[DONE]') return frame
  let ev
  try { ev = JSON.parse(payload) } catch { return '' }
  const ch = ev && Array.isArray(ev.choices) && ev.choices[0]
  if (!ch || !ch.delta) return frame
  const { content, reasoning_content: rc, reasoning, ...rest } = ch.delta
  if (content == null && rc == null && reasoning == null) return frame
  const left = Object.keys(rest).filter((k) => k !== 'role')
  if (!left.length && !ch.finish_reason && !ev.usage) return ''
  return `data: ${JSON.stringify({ ...ev, choices: [{ ...ch, delta: rest }, ...ev.choices.slice(1)] })}\n\n`
}

/** The streamed events as one chat.completion — for a caller that asked without `stream`. */
export function completionOf(events, model) {
  let content = '', reasoning = '', finish = null, usage = null, id = null, created = null
  const calls = []
  for (const ev of events) {
    if (!ev || ev.inference_receipt) continue
    id = id || ev.id; created = created || ev.created
    if (ev.usage) usage = ev.usage
    const ch = ev.choices && ev.choices[0]
    if (!ch) continue
    if (ch.finish_reason) finish = ch.finish_reason
    const d = ch.delta || {}
    if (typeof d.content === 'string') content += d.content
    if (typeof d.reasoning_content === 'string') reasoning += d.reasoning_content
    for (const t of d.tool_calls || []) {
      const ix = typeof t.index === 'number' ? t.index : calls.length
      const cur = calls[ix] || (calls[ix] = { id: '', type: 'function', function: { name: '', arguments: '' } })
      if (t.id) cur.id = t.id
      if (t.function && t.function.name) cur.function.name += t.function.name
      if (t.function && typeof t.function.arguments === 'string') cur.function.arguments += t.function.arguments
    }
  }
  const message = { role: 'assistant', content: content || null, ...(reasoning ? { reasoning_content: reasoning } : {}), ...(calls.filter(Boolean).length ? { tool_calls: calls.filter(Boolean) } : {}) }
  return { id, object: 'chat.completion', created, model, choices: [{ index: 0, message, finish_reason: finish }], ...(usage ? { usage } : {}) }
}

// ── the key ──────────────────────────────────────────────────────────────────────────────────────────────────────────
/** TINFOIL_API_KEY: the environment first, then the env file (read at REQUEST time — adding a key needs no restart). */
export function tinfoilKey(envFile = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')) {
  if (process.env.TINFOIL_API_KEY) return process.env.TINFOIL_API_KEY.trim()
  if (!existsSync(envFile)) return ''
  let v = ''
  for (const line of readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?TINFOIL_API_KEY=(.*)$/)
    if (m) v = m[1].trim().replace(/^(['"])(.*)\1$/, '$2')
  }
  return v
}

// ── the one refusal asked again ──────────────────────────────────────────────────────────────────────────────────────
// An answer that starts this close to the end of the last proof seen for its model is held back whole. Longer answers
// that start earlier can still straddle a renewal; those end with the refusal below, which says to send again.
export const HOLD_BEFORE_LAPSE_SEC = 90
export const PROGRESS_EVERY_MS = 1500 // a tool call being written is reported at most this often (and when it changes)
export const RETRY_DELAY_MS = 600 // the beat the gateway needs to finish the renewal the lapsed call set off

/** The receipt's own timing, for the log only (never trusted: the verdict comes from verifyInferenceReceipt). */
function receiptTiming(capture) {
  try {
    const c = JSON.parse(Buffer.from(capture.receipt.payload, 'base64url').toString('utf8'))
    const up = c.upstream || {}
    return ` (receipt signed ${c.iat}, proof ${up.verified_at}–${up.verification_expires_at})`
  } catch { return '' }
}

/** What the person sees when a receipt did not verify. */
export function refusalMessage(label, reason) {
  if (reason === RETRYABLE) return `${label}: TrustedRouter renewed its proof of the model's enclave while this answer was on its way, so the answer could not be verified and was not used — nothing it asked to run was run. Send your message again to continue. (${reason})`
  return `not confidential: TrustedRouter's receipt for ${label} did not verify (${reason}). The answer was not used — try again.`
}

// ── the proxy ────────────────────────────────────────────────────────────────────────────────────────────────────────
const HOP = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'accept-encoding', 'expect'])
const forwardHeaders = (h) => Object.fromEntries(Object.entries(h).filter(([k]) => !HOP.has(k.toLowerCase())))
const readBody = (req) => new Promise((resolve, reject) => {
  const chunks = []; let n = 0
  req.on('data', (c) => { n += c.length; if (n > MAX_BODY) { reject(refuse(413, 'request too large for the confidential proxy')); req.destroy() } else chunks.push(c) })
  req.on('end', () => resolve(Buffer.concat(chunks)))
  req.on('error', reject)
})

/**
 * Start the proxy on 127.0.0.1:`port`. Returns { port, close }.
 * Injectable for tests: fetchImpl (upstream + attestation fetches), upstream, gate (gateway attestation → {ok,error}),
 * nonce, now, reader (Tinfoil toText, or null = no key), key (→ TINFOIL_API_KEY), models, log.
 */
export function startConfidentialProxy({
  port = 0, host = '127.0.0.1', upstream = TR_UPSTREAM, fetchImpl = fetch, models = confidentialModels(),
  gate, nonce = newReceiptNonce, now = () => Date.now(), key = tinfoilKey, reader, log = console.error, policies,
  verify = verifyInferenceReceipt, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), onProgress = () => {},
} = {}) {
  const proofEnds = new Map() // model → verification_expires_at (s) of its last VERIFIED receipt
  let gateCache = null
  const checkGateway = gate || (async () => {
    if (gateCache && now() - gateCache.at < GATE_TTL_MS && gateCache.ok) return gateCache
    const v = await verifyGatewayAttestation({ fetchImpl, now: now() })
    gateCache = { at: now(), ok: v.ok, error: v.error }
    return gateCache
  })
  let readerFor = { key: null, fn: null }
  const toTextFor = () => {
    if (reader !== undefined) return reader
    const k = key()
    if (!k) return null
    if (readerFor.key !== k) readerFor = { key: k, fn: makeTinfoilReader({ apiKey: k }) }
    return readerFor.fn
  }

  const server = http.createServer(async (req, res) => {
    const ctrl = new AbortController()
    res.on('close', () => { if (!res.writableFinished) ctrl.abort() })
    const fail = (e, streaming) => {
      const status = e.status || 502
      const payload = { error: { message: String(e.message || e), type: e.type || 'confidential_proxy' } }
      if (res.headersSent) { if (streaming) res.write(`data: ${JSON.stringify(payload)}\n\n`); res.end(); return }
      res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(payload))
    }
    let raw
    try { raw = await readBody(req) } catch (e) { return fail(e) }
    const target = upstream + req.url
    let body = null
    if (req.method === 'POST' && /\/chat\/completions(\?|$)/.test(req.url)) { try { body = JSON.parse(raw.toString('utf8')) } catch { body = null } }
    const conf = body && typeof body.model === 'string' ? models.get(body.model) : null

    if (!conf) { // ── pass through, untouched ──
      try {
        const up = await fetchImpl(target, { method: req.method, headers: forwardHeaders(req.headers), body: ['GET', 'HEAD'].includes(req.method) ? undefined : raw, signal: ctrl.signal })
        const headers = Object.fromEntries([...up.headers].filter(([k]) => !['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k)))
        res.writeHead(up.status, headers)
        if (up.body) for await (const c of up.body) res.write(c)
        res.end()
      } catch (e) { if (!ctrl.signal.aborted) fail(refuse(502, `could not reach TrustedRouter (${String((e && e.message) || e).slice(0, 120)})`)) }
      return
    }

    // ── a confidential model ──
    const label = `${conf.label} (confidential)`
    const wantsStream = body.stream === true
    // Who is asking: OpenCode names the session on every provider call (X-Session-Id; measured in 1.18.30's bundle).
    const sessionID = String(req.headers['x-session-id'] || req.headers['x-session-affinity'] || '').slice(0, 100)
    const parentID = String(req.headers['x-parent-session-id'] || '').slice(0, 100)
    let attempt = 1
    const tell = (phase, extra = {}) => {
      if (!sessionID) return
      try { onProgress({ sessionID, ...(parentID ? { parentID } : {}), model: body.model, label: conf.label, phase, attempt, ...extra }) } catch { /* progress must never fail a call */ }
    }
    try {
      if (!conf.vision) ({ body } = await convertUnreadable(body, { label, toText: toTextFor() }))
      const g = await checkGateway()
      if (!g || !g.ok) throw refuse(502, `${label}: TrustedRouter's gateway did not prove it runs attested code (${(g && g.error) || 'no attestation'}), so nothing was sent.`, 'gateway_unattested')
      const once = async ({ wordsShown = false } = {}) => {
        const ends = proofEnds.get(body.model)
        const hold = attempt > 1 || (ends !== undefined && now() / 1000 >= ends - HOLD_BEFORE_LAPSE_SEC)
        const n = nonce()
        const bytes = JSON.stringify(stampFloor(body))
        const headers = { ...forwardHeaders(req.headers), 'content-type': 'application/json', 'x-inference-receipt': n }
        tell('waiting', { bytes: bytes.length })
        const up = await fetchImpl(target, { method: 'POST', headers, body: bytes, signal: ctrl.signal })
        if (!up.ok) {
          const text = await up.text()
          if (res.headersSent) throw refuse(502, `${label}: TrustedRouter answered ${up.status} when asked again (${text.slice(0, 160)})`, 'upstream_error')
          res.writeHead(up.status, { 'content-type': up.headers.get('content-type') || 'application/json' }); res.end(text)
          return
        }
        const answer = makeAnswerGate({ hold })
        if (wantsStream && !res.headersSent) res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
        const dec = new TextDecoder()
        let streamed = false, told = '', toldAt = 0
        for await (const c of up.body) {
          const frames = answer.push(dec.decode(c, { stream: true }))
          if (wantsStream && frames.length) { for (const f of frames) res.write(f); if (!streamed) tell('answering'); streamed = true }
          const w = answer.writing()
          if (w) {
            const key = `${w.tool}\0${w.subject}`, at = Date.now()
            if (key !== told || at - toldAt >= PROGRESS_EVERY_MS) { told = key; toldAt = at; tell('writing', w) }
          }
        }
        answer.push(dec.decode() + '\n\n')
        tell('checking')
        const v = await verify({ capture: answer.capture, requestBody: bytes, nonce: n, now: now(), fetchImpl, explainLapse: true, ...(policies ? { policies } : {}) })
        if (!v.ok) {
          log(`code-confidential: REFUSED ${body.model} — ${v.error}${v.error === RETRYABLE ? receiptTiming(answer.capture) : ''}${hold ? ' (held back)' : streamed ? ' (after streaming)' : ''}${v.lapsedOnly ? ' (every other check held)' : ''}`)
          const e = refuse(502, refusalMessage(label, v.error), 'receipt_unverified')
          e.streamed = streamed || wordsShown
          e.lapsedOnly = v.lapsedOnly === true
          throw e
        }
        const exp = v.claims && v.claims.upstream && v.claims.upstream.verification_expires_at
        if (Number.isFinite(exp)) proofEnds.set(body.model, exp)
        if (wantsStream) {
          for (const f of answer.held()) { const out = wordsShown ? withoutWords(f) : f; if (out) res.write(out) }
          res.end(); return
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify(completionOf(answer.events(), body.model)))
      }
      try {
        await once()
      } catch (e) {
        // Asked again only for the window, and — when words already reached OpenCode — only if nothing else was wrong.
        if (ctrl.signal.aborted || !isRetryableReceiptFailure(e) || (e.streamed && !e.lapsedOnly)) throw e
        log(`code-confidential: ↻ ${body.model} — ${RETRYABLE}; ${e.streamed ? 'the words already shown stay, and only the new answer\'s actions are used' : 'nothing had reached OpenCode'}; asking once more`)
        attempt = 2
        tell('retrying')
        await sleep(RETRY_DELAY_MS)
        if (ctrl.signal.aborted) return
        await once({ wordsShown: e.streamed }) // verified again from scratch, or it refuses for real
      }
    } catch (e) {
      if (ctrl.signal.aborted) return
      fail(e, wantsStream)
    } finally {
      tell('end')
    }
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => {
      server.off('error', reject)
      resolve({ port: server.address().port, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()) }) })
    })
  })
}

/** OpenCode config that sends TrustedRouter through the proxy, and declares the confidential models so a text-only one
 *  still receives images (the proxy turns them into text). Merged by OpenCode over the user's own config. */
export function proxyConfig(proxyPort, catalog = CATALOG) {
  const models = {}
  for (const m of catalog) {
    if (m.route !== 'trustedrouter' || !(m.tiers || []).includes('confidential')) continue
    models[m.model] = { name: `${m.label} · confidential`, attachment: true, tool_call: true, modalities: { input: ['text', 'image'], output: ['text'] }, limit: { context: 200_000, output: (m.params && m.params.max_tokens) || 16_000 } }
  }
  return { provider: { trustedrouter: { options: { baseURL: `http://127.0.0.1:${proxyPort}/v1` }, models } } }
}
