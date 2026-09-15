// tools/code-auto-runner.mjs — Code Auto mode's loop inside the connector (docs/code-auto-mode.md §2).
//
// For each session switched to Auto it polls OpenCode's pending permission asks (GET /permission?directory=…, or the
// connector's `listAsks` — which falls back to the asks the event stream carried when that list breaks), and for each
// new one: the deterministic layer (tools/code-auto.mjs) answers what needs no model; otherwise the SESSION'S OWN model
// reviews it in a throw-away session whose rules deny every tool. Only a clear allow is answered `once`, a deny is
// answered `reject` with the reason for the agent, and everything else — ask, nonsense, a severe allow, a timeout, any
// error — is LEFT for the person's approval card. Each decision: one line in the local log (a digest, never the command)
// and an onVerdict callback (the connector sends it to open pages as `autoverdict`).
//
// Three rules that come from OpenCode's own code (tools/code-opencode-policy.mjs has the findings):
//  · A SUBAGENT'S asks carry its own session id, and it is not the one switched to Auto — they are decided under the
//    nearest ancestor in Auto, reviewed against what the person asked THERE (not the prompt a model wrote for the agent).
//  · A `reject` makes OpenCode reject EVERY other pending ask in that session. So a refusal is HELD until nothing else is
//    pending there: it can never cancel a sibling Auto is about to allow, or one waiting on the person's card.
//  · Starting a subagent is allowed without a review only when that agent's OWN rules ask for bash/edit/webfetch/websearch
//    (a subagent does not inherit the session's asks); one whose rules would let it run commands unasked is the person's.
//
//   const auto = startAutoRunner({ base, auth, statePath, logPath, onVerdict })
//   auto.setAuto(sessionID, directory, on) · auto.sessions() · auto.stop()
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync, renameSync, lstatSync, realpathSync } from 'node:fs'
import { dirname } from 'node:path'
import { homedir } from 'node:os'
import { classifyDeterministic, reviewerPrompt, parseVerdict, actionFor, logRecord, scratchPaths, SCRATCH_DIR } from './code-auto.mjs'
import { SUBAGENT_GATED } from './code-opencode-policy.mjs'
import { allowedFolders } from '../spaces/public/codeFolders.js'

const REVIEW_TITLE = 'witbitz-auto-review' // the page never lists a session with this title
const HANDLED_TTL_MS = 30 * 60_000
const MAX_USER_MESSAGES = 6
const MAX_DETAIL = 300
const PARENT_TTL_MS = 10 * 60_000
const AGENTS_TTL_MS = 60_000
const MAX_DEPTH = 4 // parent links followed looking for the session in Auto
const REFUSAL_SUFFIX = '(Witbitz Auto mode refused this — try a narrower or safer step.)'
/** OpenCode's own evaluation for the catch-all pattern: the LAST rule that matches wins. */
const actionOf = (rules, perm) => { let a = null; for (const r of rules || []) if (r && (r.permission === perm || r.permission === '*') && r.pattern === '*') a = r.action; return a }
/** What the ask is about, for the person's own page (the verdict is sealed to it, like the ask) — never for the log. */
const detailOf = (req) => String((req.metadata && typeof req.metadata.command === 'string' && req.metadata.command) || (Array.isArray(req.patterns) && typeof req.patterns[0] === 'string' ? req.patterns[0] : '')).slice(0, MAX_DETAIL)

/**
 * The scratch rule (code-auto.mjs) trusts a path's words; the disk must agree before Auto allows on it: the directory is a
 * real one (not a link) this user owns, and every target — as far as it exists — resolves inside it. A target that is a
 * link to nowhere is refused too (a write would create its target, wherever that is). Anything unreadable ⇒ false, and
 * the reviewer decides as before.
 */
export function scratchOnDisk(paths, { dir = SCRATCH_DIR } = {}) {
  try {
    const st = lstatSync(dir)
    if (!st.isDirectory() || (typeof process.getuid === 'function' && st.uid !== process.getuid())) return false
    const root = realpathSync(dir)
    for (const p of paths) {
      for (let cur = p; ;) {
        let real = null
        try { real = realpathSync(cur) } catch {
          let exists = false
          try { lstatSync(cur); exists = true } catch { /* not there yet: its parent decides */ }
          if (exists) return false
        }
        if (real !== null) { if (real !== root && !real.startsWith(root + '/')) return false; break }
        const up = dirname(cur)
        if (up === cur) return false
        cur = up
      }
    }
    return true
  } catch { return false }
}

export function startAutoRunner({ base, auth = () => ({}), fetchImpl = fetch, statePath, logPath, pollMs = 1000, reviewTimeoutMs = 30_000, home = homedir(), onVerdict = () => {}, log = console.error, now = Date.now, scratchCheck = scratchOnDisk, listAsks = null }) {
  const root = String(base || '').replace(/\/+$/, '')
  const auto = new Map() // sessionID → { dir, at }
  const handled = new Map() // permission id → when it was taken up (so a poll never reviews it twice)
  const parents = new Map() // sessionID → { parent: string|null, at } — so a subagent's ask finds its Auto session
  const agentsByDir = new Map() // directory → { list, at } — GET /agent, for what a subagent's own rules allow
  const held = new Map() // sessionID → Map(permission id → a refusal waiting for its session's other asks to settle)
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
    const tools = new Map() // callID → tool name: which tool raised an ask (its `tool.callID`)
    for (const m of msgs) {
      for (const p of (m && Array.isArray(m.parts) ? m.parts : [])) if (p && p.type === 'tool' && typeof p.callID === 'string' && typeof p.tool === 'string') tools.set(p.callID, p.tool)
      const info = (m && m.info) || {}
      if (info.role === 'assistant' && info.providerID && info.modelID) model = { providerID: info.providerID, modelID: info.modelID }
      if (info.role === 'user') {
        const text = (m.parts || []).filter((p) => p && p.type === 'text' && typeof p.text === 'string' && !p.synthetic).map((p) => p.text).join('\n').trim()
        if (text) userMessages.push(text)
      }
    }
    return { model, userMessages: userMessages.slice(-MAX_USER_MESSAGES), tools }
  }

  /** The session's parent (null for a top-level session); undefined when OpenCode could not say — not cached. */
  async function parentOf(sid, dir) {
    const c = parents.get(sid)
    if (c && now() - c.at < PARENT_TTL_MS) return c.parent
    try {
      const r = await call('GET', `/session/${encodeURIComponent(sid)}`, dir)
      if (!r.ok || !r.json) return undefined
      const parent = typeof r.json.parentID === 'string' && r.json.parentID ? r.json.parentID : null
      parents.set(sid, { parent, at: now() })
      return parent
    } catch { return undefined }
  }
  /** The session in Auto this ask belongs to: its own, or its nearest ancestor's in the same project. */
  async function ownerOf(sid, dir) {
    let cur = sid
    for (let i = 0; i < MAX_DEPTH && cur; i++) {
      const on = auto.get(cur)
      if (on && on.dir === dir) return cur
      cur = await parentOf(cur, dir)
    }
    return null
  }
  /** Does the named agent ASK (or refuse) before every gated kind of action? null when its rules cannot be read. */
  async function subagentAsks(name, dir) {
    let c = agentsByDir.get(dir)
    if (!c || now() - c.at > AGENTS_TTL_MS) {
      try {
        const r = await call('GET', '/agent', dir)
        if (!r.ok || !Array.isArray(r.json)) return null
        c = { list: r.json, at: now() }
        agentsByDir.set(dir, c)
      } catch { return null }
    }
    const agent = c.list.find((a) => a && a.name === name)
    if (!agent || !Array.isArray(agent.permission)) return false
    return SUBAGENT_GATED.every((p) => { const a = actionOf(agent.permission, p); return a === 'ask' || a === 'deny' })
  }
  /** Starting a subagent: allowed at once when its own rules ask, the person's when they would not. null = review it. */
  async function classifySubagent(req, dir) {
    if (req.permission !== 'task') return null
    const name = String((req.metadata && req.metadata.subagent_type) || (Array.isArray(req.patterns) && req.patterns[0]) || '')
    if (!name) return null
    const asks = await subagentAsks(name, dir)
    if (asks === true) return { stage: 'fast-allow', decision: 'allow', rule: 'fast:subagent-asks', reason: `starts the ${name} agent, whose own commands each ask for approval` }
    if (asks === false) return { stage: 'fast-ask', decision: 'ask', rule: 'ask:subagent-unguarded', reason: `the ${name} agent's own commands would run without asking — start it yourself if you trust it` }
    return null
  }

  /** The folders the person allowed for the session that asked ("allow this folder") — they count as the project. A subagent's
   *  session holds its parent's (OpenCode copies external_directory rules into it), so its own rules say. */
  async function foldersOf(sid, dir) {
    try {
      const r = await call('GET', `/session/${encodeURIComponent(sid)}`, dir)
      return r.ok && r.json ? allowedFolders(r.json.permission) : []
    } catch { return [] }
  }

  async function review(req, dir, owner = req.sessionID, folders = []) {
    const { model, userMessages, tools } = await sessionContext(owner, dir)
    if (!model) return { verdict: null, model: '', note: 'the session has no model to review with yet' }
    // A subagent's ask names a call in ITS transcript, not the owner's: then there is no tool line, as before.
    const tool = (req.tool && typeof req.tool.callID === 'string' && tools.get(req.tool.callID)) || ''
    const prompt = reviewerPrompt({ req, directory: dir, userMessages, tool, folders })
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

  const emit = (req, stage, action, rec, reason, answered) => {
    try { onVerdict({ id: req.id, sessionID: req.sessionID, permission: req.permission, detail: detailOf(req), stage, action, severity: rec.severity, rule: rec.rule, reason, answered }) } catch { /* a listener never breaks the loop */ }
  }

  async function decide(req, dir, owner = req.sessionID) {
    const t0 = now()
    const folders = await foldersOf(req.sessionID, dir)
    let det = classifyDeterministic(req, { directory: dir, home, folders })
    if (det && det.rule === 'fast:agent-scratch' && !scratchCheck(scratchPaths(req))) det = null // the disk disagrees: the reviewer's
    det = det || await classifySubagent(req, dir)
    let stage, verdict, model = '', note = ''
    if (det) { stage = det.stage; verdict = { decision: det.decision, severity: det.stage === 'hard-deny' ? 100 : det.stage === 'fast-ask' ? 50 : 0, rule: det.rule, reason: det.reason } }
    else { stage = 'reviewer'; ({ verdict, model, note } = await review(req, dir, owner, folders)) }
    const action = det ? det.decision : actionFor(verdict)
    const rec = logRecord({ req, stage, verdict, action, model, ms: now() - t0, at: t0 })
    const reason = (verdict && verdict.reason) || note || ''
    if (action === 'deny') {
      // HELD, not sent: see the header. The page hears it now (answered: null) and again when it lands.
      if (!held.has(req.sessionID)) held.set(req.sessionID, new Map())
      held.get(req.sessionID).set(req.id, { req, dir, stage, rec, reason, message: `${(verdict && verdict.reason) || 'Refused by Auto mode.'} ${REFUSAL_SUFFIX}` })
      emit(req, stage, action, rec, reason, null)
      return
    }
    let answered = null
    if (action === 'allow') answered = await reply(req, dir, 'once')
    appendLog(answered === false ? { ...rec, answered: false } : rec)
    emit(req, stage, action, rec, reason, answered)
  }

  /** Send the held refusals of every session whose OTHER asks have all settled. `pending`: this directory's asks, fresh. */
  async function releaseHeld(dir, pending) {
    for (const [sid, refusals] of held) {
      const mine = [...refusals.values()].filter((h) => h.dir === dir)
      if (!mine.length) continue
      const pendingIds = new Set(pending.filter((p) => p && p.sessionID === sid).map((p) => p.id))
      for (const h of mine) {
        if (pendingIds.has(h.req.id)) continue
        refusals.delete(h.req.id) // answered elsewhere (the person, or the turn was stopped) before it could be sent
        appendLog({ ...h.rec, answered: false })
        emit(h.req, h.stage, 'deny', h.rec, h.reason, false)
      }
      if ([...pendingIds].some((id) => !refusals.has(id))) continue // something else in the session is still open
      for (const h of [...refusals.values()].filter((x) => x.dir === dir)) {
        refusals.delete(h.req.id)
        const answered = await reply(h.req, dir, 'reject', h.message)
        appendLog(answered === false ? { ...h.rec, answered: false } : h.rec)
        emit(h.req, h.stage, 'deny', h.rec, h.reason, answered)
      }
      if (!refusals.size) held.delete(sid)
    }
  }

  // ── the loop ──
  async function pending(dir) {
    if (listAsks) { try { return await listAsks(dir) } catch { return null } }
    try { const r = await call('GET', '/permission', dir); return r.ok && Array.isArray(r.json) ? r.json : null } catch { return null }
  }
  async function poll() {
    if (polling || stopped || !auto.size) return
    polling = true
    try {
      const cutoff = now() - HANDLED_TTL_MS
      for (const [id, at] of handled) if (at < cutoff) handled.delete(id)
      const dirs = new Set([...auto.values()].map((v) => v.dir))
      for (const dir of dirs) {
        // null = nobody can say what is waiting (OpenCode restarting, or its list broken with no events to go on): skip the
        // folder. Taken as "nothing is waiting", it would drop every held refusal as answered elsewhere.
        const list = await pending(dir)
        if (!list) continue
        for (const req of list) {
          if (!req || typeof req.id !== 'string' || typeof req.sessionID !== 'string' || handled.has(req.id)) continue
          const owner = await ownerOf(req.sessionID, dir)
          if (!owner) continue
          handled.set(req.id, now())
          decide(req, dir, owner).catch((e) => log(`code-auto: ${e && e.message}`))
        }
        await releaseHeld(dir, list)
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
