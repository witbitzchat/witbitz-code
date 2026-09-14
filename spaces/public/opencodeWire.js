// opencodeWire: the PURE OpenCode wire logic — no fetch, no DOM, no node builtins — shared by the Spaces "code"
// section (browser) and the /rc daemon (node). ONE definition, so the room lane and the attested client can never
// drift apart on what an event means.
//
// ★ EVERY SHAPE HERE WAS MEASURED against a live `opencode serve` v1.18.30 (OpenAPI 3.1 at GET /doc, 162 paths), not
//   read off the docs. See tools/rc-opencode.mjs for the probe log; the load-bearing surprises:
//     · GET /event is a GLOBAL stream (every session on the box) ⇒ a mapper MUST scope by sessionID.
//     · the live stream speaks `message.part.updated`, NOT the prettier `session.next.*` names in the schema's Event
//       union (those belong to the /api v2 stream) — pinning them would ship a mapper that never fires.
//     · the user's OWN prompt comes back as a text part ⇒ roles are learned from message.updated (info.role).
//     · a `file` part with url 'file://<abs>' IS read by the model.
//     · permission.asked carries metadata.command — the human-readable label an approval needs.

/** A prompt + staged files → OpenCode message parts. Files ride as `file` parts with a file:// URL (MEASURED to be
 *  read), so bytes never enter the prompt text. An absent prompt omits the text part rather than sending "". */
export function partsFor(prompt, files = []) {
  const text = typeof prompt === 'string' ? prompt.trim() : ''
  const parts = text ? [{ type: 'text', text }] : []
  for (const f of Array.isArray(files) ? files : []) {
    if (!f || !(f.url || f.path)) continue
    // Two origins for the same part: the DAEMON stages to disk and passes a path (file://), the BROWSER has bytes and
    // passes a data: URL. Both MEASURED against a live server — file:// answered "ZUCCHINI", data: reached the model
    // as a synthetic Read result.
    parts.push({ type: 'file', mime: f.mime || 'application/octet-stream', filename: f.name || basename(f.path || 'attachment'), url: f.url || 'file://' + f.path })
  }
  return parts
}
const basename = (p) => String(p).split('/').pop() || 'attachment'

// Events we deliberately DROP. Named rather than defaulted: a new event type we have never seen should fall through
// to the unknown branch (also dropped) — but the list documents what the live stream actually carries, which is the
// part a reader cannot get from the schema.
const IGNORED = new Set([
  'server.connected', 'server.heartbeat', 'plugin.added', 'catalog.updated', 'reference.updated', 'integration.updated',
  'integration.connection.updated', 'models-dev.refreshed', 'session.diff',
  'message.updated', 'message.removed', 'message.part.removed', 'file.edited', 'file.watcher.updated',
  'lsp.updated', 'project.updated', 'project.directories.updated', 'vcs.branch.updated', 'installation.updated',
  'installation.update-available', 'permission.v2.asked', 'permission.v2.replied', 'question.v2.asked', 'question.v2.replied',
])

// ── the agent's todo list (the measured wire is in codeTodos.js's header) ──
const STATUSES = ['pending', 'in_progress', 'completed', 'cancelled']
const PRIORITIES = ['high', 'medium', 'low']

/** The list as it can be drawn: the agent's order, known statuses and priorities, no empty items. */
export function normTodos(list) {
  return (Array.isArray(list) ? list : [])
    .filter((t) => t && typeof t === 'object' && String(t.content || '').trim())
    .map((t) => ({
      content: String(t.content),
      status: STATUSES.includes(t.status) ? t.status : 'pending',
      priority: PRIORITIES.includes(t.priority) ? t.priority : 'medium',
    }))
}

// ── the agent's question tool (the measured wire is in codeQuestions.js's header) ──
const qstr = (v) => (v == null ? '' : String(v))

/** A request from `question.asked` or GET /question → {id, sessionID, callID, questions} — or null when it is not one. */
/** A session's undo point (opencode 1.18.30: revert {messageID, partID?, snapshot, diff}) — only what the page reads.
 *  `files`: OpenCode had a snapshot to put the files back from. Measured: in a folder that is not a git repository the
 *  undo still hides the turn, but snapshot is false and the files stay as they are. */
export function normRevert(r) {
  if (!r || typeof r !== 'object' || typeof r.messageID !== 'string' || !r.messageID) return null
  return { messageID: r.messageID, ...(typeof r.partID === 'string' && r.partID ? { partID: r.partID } : {}), files: !!r.snapshot }
}

export function normQuestionRequest(p) {
  if (!p || typeof p !== 'object' || !p.id || !Array.isArray(p.questions)) return null
  const questions = p.questions
    .filter((q) => q && typeof q === 'object' && qstr(q.question).trim())
    .map((q) => ({
      question: qstr(q.question),
      header: qstr(q.header),
      options: (Array.isArray(q.options) ? q.options : [])
        .filter((o) => o && typeof o === 'object' && o.label != null && qstr(o.label) !== '')
        .map((o) => ({ label: qstr(o.label), description: qstr(o.description) })),
      multiple: q.multiple === true,
      custom: q.custom !== false,
    }))
  if (!questions.length) return null
  // A question with no options and no typing cannot be answered. It is never DROPPED — the reply needs one answer per
  // question, in order — the request is marked, and the card offers only Skip.
  const answerable = questions.every((q) => q.options.length > 0 || q.custom)
  return { id: qstr(p.id), sessionID: qstr(p.sessionID), callID: qstr(p.tool && p.tool.callID), questions, answerable }
}

/** ONE SSE event → the rc events it means (0, 1 or more). `sessionID` scopes it: GET /event is a GLOBAL stream
 *  carrying every session on the server, so an unscoped mapper would mix another room's run into this one's pane.
 *
 *  `roles` is an optional Map the CALLER owns, filled from `message.updated` (which carries info.role + info.id) and
 *  read when a text part arrives. ★ MEASURED: the user's OWN prompt comes back as a `message.part.updated` text part,
 *  indistinguishable from the answer without this — the live probe echoed the prompt into the step list before the
 *  map existed. Unknown messageID ⇒ KEEP: losing the assistant's answer is far worse than echoing a prompt, so the
 *  drop happens only on an explicit 'user'. */
export function mapEvent(ev, sessionID = '', roles = null, partTypes = null) {
  if (!ev || typeof ev !== 'object') return []
  const type = String(ev.type || '')
  const p = ev.properties || {}
  const sid = p.sessionID || (p.info && p.info.id) || ''
  if (sessionID && sid && sid !== sessionID) return [] // another session's event — not ours to render
  // Learn roles BEFORE the ignore list drops the event: message.updated is noise for the pane and the only place the
  // role is published. (Measured ordering: the user's message.updated precedes its part update.)
  if (type === 'message.updated' && roles) {
    const info = p.info || {}
    if (info.id && info.role) roles.set(info.id, info.role)
  }
  // Part types, for the same reason: a delta names only its part, and reasoning streams on field 'text' exactly like the
  // answer does (measured, opencode 1.18.30: message.part.updated {type:'reasoning'} first, then ~80 text deltas).
  if (type === 'message.part.updated' && partTypes && p.part && p.part.id && p.part.type) partTypes.set(p.part.id, p.part.type)
  if (IGNORED.has(type)) return []

  if (type === 'session.created') return sid ? [{ kind: 'session', id: sid }] : []
  if (type === 'session.idle') return [{ kind: 'idle' }]
  // Whether the session is running a turn — whoever started it (another device, the TUI). Measured: {status:{type:'busy'}}
  // when a turn starts, {type:'idle'} as it ends; 'retry' carries the provider's message while it waits to try again.
  if (type === 'session.status') {
    const st = p.status || {}
    return st.type ? [{ kind: 'status', busy: st.type !== 'idle', retry: st.type === 'retry' ? String(st.message || '') : '' }] : []
  }
  // An undo or redo made anywhere (the TUI, another device) — the session record carries its undo point, or none.
  if (type === 'session.updated') return sid ? [{ kind: 'revert', revert: normRevert(p.info && p.info.revert) }] : []
  if (type === 'session.compacted') return [{ kind: 'note', text: 'context compacted' }]
  if (type === 'session.error') return [{ kind: 'stderr', text: errText(p) }]

  // ★ PROGRESSIVE TEXT. Measured payload: {sessionID, messageID, partID, field:'text', delta:'The'} — one token-ish
  //   chunk. The full text also arrives later as a part update, so a delta is an OPTIMISATION, never the only copy:
  //   a client that drops them still renders everything, just in one go at the end.
  if (type === 'message.part.delta') {
    if (p.field !== 'text' || typeof p.delta !== 'string' || !p.delta) return []
    if (roles && p.messageID && roles.get(p.messageID) === 'user') return [] // our own prompt echoing back
    if (partTypes && partTypes.get(p.partID) === 'reasoning') return [{ kind: 'thinking', id: p.partID, text: p.delta }] // not the answer
    return [{ kind: 'delta', id: p.partID, messageID: p.messageID, text: p.delta }]
  }

  if (type === 'message.part.updated') {
    const part = p.part || {}
    if (part.type === 'text' && part.text) {
      if (roles && part.messageID && roles.get(part.messageID) === 'user') return [] // our own prompt coming back
      return [{ kind: 'text', id: part.id, text: String(part.text), done: !!(part.time && part.time.end) }]
    }
    if (part.type === 'reasoning') return [{ kind: 'reasoning', id: part.id, text: String(part.text || ''), done: !!(part.time && part.time.end) }]
    if (part.type === 'tool') {
      const st = part.state || {}
      return [{ kind: 'tool', id: part.id, name: part.tool || 'tool', status: st.status || 'pending', input: st.input || {} }]
    }
    return [] // step-start / step-finish carry no content
  }

  if (type === 'permission.asked') {
    return [{
      kind: 'ask',
      id: p.id,
      permission: p.permission || 'tool',
      // metadata.command is the human-readable form for bash; patterns is what the rule would match. Prefer the
      // command, fall back to the first pattern — the room shows this to a person, so it must never be '[object]'.
      detail: (p.metadata && typeof p.metadata.command === 'string' && p.metadata.command) || (Array.isArray(p.patterns) ? p.patterns[0] : '') || '',
      patterns: Array.isArray(p.patterns) ? p.patterns : [],
      always: Array.isArray(p.always) ? p.always : [],
      callID: (p.tool && p.tool.callID) || '',
    }]
  }
  if (type === 'permission.replied') return [{ kind: 'settled', id: p.id }]
  // The agent's question tool (codeQuestions.js has the measured wire). Only the v1 events fire on this stream.
  if (type === 'question.asked') {
    const q = normQuestionRequest(p)
    return q ? [{ kind: 'question', ...q }] : []
  }
  // The agent's todo list: the WHOLE list, every time (an empty one clears it).
  if (type === 'todo.updated') return [{ kind: 'todos', todos: normTodos(p.todos) }]
  if (type === 'question.replied' || type === 'question.rejected') return p.requestID ? [{ kind: 'question-settled', id: String(p.requestID) }] : []
  return []
}
export const errText = (p) => {
  const e = p && p.error
  if (!e) return 'session error'
  if (typeof e === 'string') return e
  return String((e.data && e.data.message) || e.message || e.name || JSON.stringify(e)).slice(0, 2000)
}

/** Split an SSE byte stream into events. Kept separate from the transport so it can be tested on a string, and so a
 *  chunk boundary mid-event can never drop a tool call (the bug class that ate a streamed reply once already). */
export function makeSseParser(onData) {
  let buf = ''
  return (chunk) => {
    buf += chunk
    let i
    while ((i = buf.indexOf('\n\n')) !== -1) {
      const frame = buf.slice(0, i); buf = buf.slice(i + 2)
      for (const line of frame.split('\n')) {
        if (!line.startsWith('data:')) continue
        const body = line.slice(5).trim()
        if (!body) continue
        try { onData(JSON.parse(body)) } catch { /* a non-JSON keepalive is not an error */ }
      }
    }
  }
}

/** Model as ONE string, provider first: 'trustedrouter/deepseek/deepseek-v4-flash' → the two fields the API wants.
 *  The modelID keeps every remaining segment — TR's ids contain a slash, so splitting on the last one is wrong. */
export function parseModel(s) {
  const str = String(s || '').trim()
  if (!str) return null
  const i = str.indexOf('/')
  if (i <= 0 || i === str.length - 1) return null
  return { providerID: str.slice(0, i), modelID: str.slice(i + 1) }
}

/** The room's default ruleset. Read-shaped tools auto-pass (a gate that turns a 20-step run into 20 taps gets switched
 *  off and protects nothing); everything that writes, executes or LEAVES THE BOX asks a human. Set at session
 *  creation, so the box's own opencode config — whose defaults are mostly `allow` — cannot widen it.
 *  ⚠ The enclave profile flips webfetch/websearch to 'deny' and offers the attested fetch_url instead: inside a
 *  measured boundary an arbitrary outbound URL is an exfiltration channel, not a convenience. */
export const OC_ASK_PERMISSIONS = ['bash', 'edit', 'webfetch', 'websearch', 'task', 'skill', 'external_directory']
export const OC_ALLOW_PERMISSIONS = ['read', 'glob', 'grep', 'list', 'lsp']
export const ocPermissionRuleset = ({ ask = OC_ASK_PERMISSIONS, allow = OC_ALLOW_PERMISSIONS } = {}) => [
  ...allow.map((permission) => ({ permission, pattern: '*', action: 'allow' })),
  ...ask.map((permission) => ({ permission, pattern: '*', action: 'ask' })),
]

/** The answer is the LAST text part of the assistant message the prompt call returns — there is no `result` event on
 *  this wire, and the streamed parts are the same strings. Mirrors the spawn path's finalFromEvent. */
export const finalTextOf = (reply) => {
  const parts = (reply && reply.json && Array.isArray(reply.json.parts) ? reply.json.parts : []).filter((p) => p && p.type === 'text' && p.text)
  return parts.length ? String(parts[parts.length - 1].text) : ''
}

/** Why a fetch to the server failed, in terms a person can act on. A cross-origin fetch fails with the SAME opaque
 *  TypeError whether the server is stopped, CORS refused the origin, or the page is HTTPS and the target is HTTP — and
 *  the fix differs for each, so all three are named. Pure (protocol/base/origin are passed in) so it is testable. */
export function explainFetchFailure({ err, pageProtocol = 'http:', base = '', origin = '' } = {}) {
  if (pageProtocol === 'https:' && /^http:/i.test(base)) {
    return `blocked: this page is HTTPS and ${base} is HTTP, which the browser refuses silently (mixed content). Put an HTTPS front in front of the server — \`tailscale serve\` gives it a real certificate — or open this page over http on the same machine.`
  }
  return `cannot reach ${base} — is \`opencode serve\` running, and does it allow this origin? Start it with: opencode serve --port 4096 --cors ${origin}${err && err.message ? '  (' + err.message + ')' : ''}`
}

/** The server URL to start from. localhost is a fine guess when the page itself is local — and ALWAYS WRONG on a
 *  deployed HTTPS page, where it cannot even be fetched (mixed content). ★ Seen on a phone, first load of the
 *  deployed section: a wall of red explaining a default the user never chose. Unconfigured ⇒ '' ⇒ the UI asks. */
export function defaultBase({ stored = '', pageProtocol = 'http:' } = {}) {
  if (stored) return stored
  return pageProtocol === 'https:' ? '' : 'http://127.0.0.1:4096'
}

/** Which model capability a given attachment needs. TEXT NEEDS NONE: measured — the server expands a text file part
 *  into a synthetic "Called the Read tool" result, so the bytes arrive as a tool result any model can read. Images,
 *  PDFs, audio and video are passed to the MODEL, so the model must declare that input. */
export function neededCapability(mime) {
  const m = String(mime || '').toLowerCase()
  if (m.startsWith('image/')) return 'image'
  if (m === 'application/pdf') return 'pdf'
  if (m.startsWith('audio/')) return 'audio'
  if (m.startsWith('video/')) return 'video'
  return '' // text and everything else: read as a file, no model capability required
}

/** '' when the model can take it, otherwise a sentence saying what is wrong and what to do. `input` is the model's own
 *  declared capabilities.input from GET /api/model — measured: deepseek-v4-flash declares [], i.e. it cannot receive
 *  an image at all, which is exactly the "the agent cannot read my file" failure. */
export function attachmentWarning({ mime, modelLabel = 'this model', input = null }) {
  const need = neededCapability(mime)
  if (!need) return ''
  if (!Array.isArray(input)) return '' // unknown catalog ⇒ say nothing rather than cry wolf
  if (input.includes(need)) return ''
  return `${modelLabel} cannot read ${need === 'pdf' ? 'PDFs' : need + 's'} — pick a model that accepts ${need} input, or attach a text file instead.`
}
