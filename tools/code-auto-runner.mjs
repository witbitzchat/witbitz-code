// tools/code-auto-runner.mjs — Code Auto mode's loop inside the connector (docs/code-auto-mode.md §2).
//
// For each session switched to Auto it polls OpenCode's pending permission asks (GET /permission?directory=…), and for each
// new one: the deterministic layer (tools/code-auto.mjs) answers what needs no model; otherwise the SESSION'S OWN model
// reviews it in a throw-away session whose rules deny every tool. Only a clear allow is answered `once`, a deny is
// answered `reject` with the reason for the agent, and everything else — ask, nonsense, a severe allow, a timeout, any
// error — is LEFT for the person's approval card. Each decision: one line in the local log (a digest, never the command)
// and an onVerdict callback (the connector sends it to open pages as `autoverdict`).
//
//   const auto = startAutoRunner({ base, auth, statePath, logPath, onVerdict })
//   auto.setAuto(sessionID, directory, on) · auto.sessions() · auto.stop()
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync, renameSync } from 'node:fs'
import { dirname } from 'node:path'
import { homedir } from 'node:os'
import { classifyDeterministic, reviewerPrompt, parseVerdict, actionFor, logRecord } from './code-auto.mjs'

const REVIEW_TITLE = 'witbitz-auto-review' // the page never lists a session with this title
const HANDLED_TTL_MS = 30 * 60_000
const MAX_USER_MESSAGES = 6
const MAX_DETAIL = 300
/** What the ask is about, for the person's own page (the verdict is sealed to it, like the ask) — never for the log. */
const detailOf = (req) => String((req.metadata && typeof req.metadata.command === 'string' && req.metadata.command) || (Array.isArray(req.patterns) && typeof req.patterns[0] === 'string' ? req.patterns[0] : '')).slice(0, MAX_DETAIL)

export function startAutoRunner({ base, auth = () => ({}), fetchImpl = fetch, statePath, logPath, pollMs = 1000, reviewTimeoutMs = 30_000, home = homedir(), onVerdict = () => {}, log = console.error, now = Date.now }) {
  const root = String(base || '').replace(/\/+$/, '')
  const auto = new Map() // sessionID → { dir, at }
  const handled = new Map() // permission id → when it was taken up (so a poll never reviews it twice)
  let timer = 0
  let stopped = false
  let polling = false

  // ── state on the computer ──
  try {
    const doc = statePath && existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : null
    for (const [sid, v] of Object.entries((doc && doc.sessions) || {})) if (/^ses/.test(sid) && v && typeof v.dir === 'string' && v.dir.startsWith('/')) auto.set(sid, { dir: v.dir, at: Number(v.at) || 0 })
  } catch (e) { log(`code-auto: ignoring an unreadable ${statePath} (${e.message})`) }
  const save = () => {
    if (!statePath) return
    try {
      mkdirSync(dirname(statePath), { recursive: true })
      const tmp = statePath + '.tmp'
      writeFileSync(tmp, JSON.stringify({ sessions: Object.fromEntries(auto) }, null, 2), { mode: 0o600 })
      renameSync(tmp, statePath) // atomic: a crash mid-write never leaves half a file
    } catch (e) { log(`code-auto: could not save ${statePath} (${e.message})`) }
  }
  const appendLog = (rec) => {
    if (!logPath) return
    try { mkdirSync(dirname(logPath), { recursive: true }); appendFileSync(logPath, JSON.stringify(rec) + '\n', { mode: 0o600 }) } catch (e) { log(`code-auto: could not write ${logPath} (${e.message})`) }
  }

  // ── OpenCode ──
  const q = (path, dir) => `${root}${path}${path.includes('?') ? '&' : '?'}directory=${encodeURIComponent(dir)}`
  async function call(method, path, dir, body, signal) {
    const r = await fetchImpl(q(path, dir), { method, headers: { ...auth(), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined, signal })
    let json = null
    try { json = await r.json() } catch { /* an empty or non-JSON answer */ }
    return { ok: r.ok, status: r.status, json }
  }

  async function reply(req, dir, answer, message) {
    try {
      const r = await call('POST', `/permission/${encodeURIComponent(req.id)}/reply`, dir, message ? { reply: answer, message } : { reply: answer })
      return r.ok
    } catch { return false }
  }

  /** The session's model and what the person asked for — from its own transcript. */
  async function sessionContext(sid, dir) {
    const r = await call('GET', `/session/${encodeURIComponent(sid)}/message`, dir)
    const msgs = Array.isArray(r.json) ? r.json : []
    let model = null
    const userMessages = []
    for (const m of msgs) {
      const info = (m && m.info) || {}
      if (info.role === 'assistant' && info.providerID && info.modelID) model = { providerID: info.providerID, modelID: info.modelID }
      if (info.role === 'user') {
        const text = (m.parts || []).filter((p) => p && p.type === 'text' && typeof p.text === 'string' && !p.synthetic).map((p) => p.text).join('\n').trim()
        if (text) userMessages.push(text)
      }
    }
    return { model, userMessages: userMessages.slice(-MAX_USER_MESSAGES) }
  }

  async function review(req, dir) {
    const { model, userMessages } = await sessionContext(req.sessionID, dir)
    if (!model) return { verdict: null, model: '', note: 'the session has no model to review with yet' }
    const prompt = reviewerPrompt({ req, directory: dir, userMessages })
    const created = await call('POST', '/session', dir, { title: REVIEW_TITLE, permission: [{ permission: '*', pattern: '*', action: 'deny' }] })
    const rid = created.json && created.json.id
    if (!rid) return { verdict: null, model: `${model.providerID}/${model.modelID}`, note: 'could not open a review session' }
    const ctrl = new AbortController()
    let timedOut = false
    const t = setTimeout(() => { timedOut = true; ctrl.abort() }, reviewTimeoutMs)
    try {
      const r = await call('POST', `/session/${encodeURIComponent(rid)}/message`, dir, { model, system: prompt.system, tools: { '*': false }, parts: [{ type: 'text', text: prompt.text }] }, ctrl.signal)
      const parts = (r.json && Array.isArray(r.json.parts)) ? r.json.parts : []
      const text = parts.filter((p) => p && p.type === 'text' && p.text).map((p) => p.text).pop() || ''
      return { verdict: parseVerdict(text), model: `${model.providerID}/${model.modelID}`, note: text ? '' : 'the reviewer gave no answer' }
    } catch {
      return { verdict: null, model: `${model.providerID}/${model.modelID}`, note: timedOut ? `the reviewer did not answer within ${Math.round(reviewTimeoutMs / 1000) || 1} s` : 'the review failed' }
    } finally {
      clearTimeout(t)
      if (timedOut) { try { await call('POST', `/session/${encodeURIComponent(rid)}/abort`, dir) } catch { /* */ } }
      try { await call('DELETE', `/session/${encodeURIComponent(rid)}`, dir) } catch { /* */ }
    }
  }

  async function decide(req, dir) {
    const t0 = now()
    const det = classifyDeterministic(req, { directory: dir, home })
    let stage, verdict, model = '', note = ''
    if (det) { stage = det.stage; verdict = { decision: det.decision, severity: det.stage === 'hard-deny' ? 100 : 0, rule: det.rule, reason: det.reason } }
    else { stage = 'reviewer'; ({ verdict, model, note } = await review(req, dir)) }
    const action = det ? det.decision : actionFor(verdict)
    let answered = null
    if (action === 'allow') answered = await reply(req, dir, 'once')
    else if (action === 'deny') answered = await reply(req, dir, 'reject', `${(verdict && verdict.reason) || 'Refused by Auto mode.'} (Witbitz Auto mode refused this — try a narrower or safer step.)`)
    const rec = logRecord({ req, stage, verdict, action, model, ms: now() - t0, at: t0 })
    appendLog(answered === false ? { ...rec, answered: false } : rec)
    const reason = (verdict && verdict.reason) || note || ''
    try { onVerdict({ id: req.id, sessionID: req.sessionID, permission: req.permission, detail: detailOf(req), stage, action, severity: rec.severity, rule: rec.rule, reason, answered: answered === null ? null : answered }) } catch { /* a listener never breaks the loop */ }
  }

  // ── the loop ──
  async function poll() {
    if (polling || stopped || !auto.size) return
    polling = true
    try {
      const cutoff = now() - HANDLED_TTL_MS
      for (const [id, at] of handled) if (at < cutoff) handled.delete(id)
      const dirs = new Set([...auto.values()].map((v) => v.dir))
      for (const dir of dirs) {
        let list = []
        try { const r = await call('GET', '/permission', dir); list = Array.isArray(r.json) ? r.json : [] } catch { continue } // OpenCode restarting
        for (const req of list) {
          if (!req || typeof req.id !== 'string' || handled.has(req.id)) continue
          const on = auto.get(req.sessionID)
          if (!on || on.dir !== dir) continue
          handled.set(req.id, now())
          decide(req, dir).catch((e) => log(`code-auto: ${e && e.message}`))
        }
      }
    } finally { polling = false }
  }
  const tick = () => { if (!stopped) { poll().finally(() => { if (!stopped) timer = setTimeout(tick, pollMs) }) } }
  tick()

  return {
    setAuto(sessionID, directory, on) {
      if (typeof sessionID !== 'string' || !/^ses[A-Za-z0-9_-]{1,80}$/.test(sessionID)) return false
      if (on) {
        if (typeof directory !== 'string' || !directory.startsWith('/') || directory.length > 1024) return false
        auto.set(sessionID, { dir: directory, at: now() })
      } else auto.delete(sessionID)
      save()
      return true
    },
    sessions: () => [...auto.keys()],
    stop() { stopped = true; clearTimeout(timer) },
  }
}
