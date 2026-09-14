// spaces/public/codeUnread.js — which sessions in the Code list have activity you have not seen. The room list's unread
// (unread.js) for OpenCode sessions: the owner, after the running mark, "it also needs to show if the user missed an
// activity" — a turn that finished while you were in another session, or one started on another device.
//
// The activity clock is the session's own `time.updated`. Measured on opencode 1.18.30: it moves with a turn's steps and
// NOT with a rename or an archive (PATCH leaves it where it was), so what you tidy here never reads as news.
//
// Device-local, like the room's: `at[sessionID]` is the newest activity you have seen of that session; `since` is the
// newest activity on the list the first time this device looked, so nothing already there is new (never retroactive).
// Both are the SERVER's stamps — a phone's clock minutes off the computer's cannot make old activity look new.
// The pure rules are tested in spaces/test/codeUnread.test.mjs; opencodeApp.js stores the record and draws the dots.

export const SEEN_KEY = 'oc.seen'

// SHARED BETWEEN DEVICES (the owner: "When I switch devices I get green dots"). The computer the sessions live on keeps a
// record too — its connector answers SEEN_ROUTE (GET: its record; POST a record: merged, and the merge comes back) — and
// every device merges with it, so a session read on the phone is not news on the laptop. A connector without the `seen`
// capability leaves the record on each device, as before.
export const SEEN_ROUTE = '/witbitz/seen'
const SEEN_ID = /^[A-Za-z0-9_-]{1,128}$/
const SEEN_MAX = 5000

/** A record from the wire or the disk, checked: session ids, positive numbers, at most SEEN_MAX (the latest looks kept). */
export function normSeen(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return { since: 0, at: {} }
  const entries = Object.entries(o.at && typeof o.at === 'object' && !Array.isArray(o.at) ? o.at : {})
    .filter(([id, v]) => SEEN_ID.test(id) && typeof v === 'number' && Number.isFinite(v) && v > 0)
  if (entries.length > SEEN_MAX) entries.sort((x, y) => y[1] - x[1]).length = SEEN_MAX
  return { since: typeof o.since === 'number' && Number.isFinite(o.since) && o.since > 0 ? o.since : 0, at: Object.fromEntries(entries) }
}

/** Two records → one: each session's LATER look, the EARLIER first look. The same `a` back when `b` adds nothing. */
export function mergeSeen(a, b) {
  const since = a.since && b.since ? Math.min(a.since, b.since) : a.since || b.since
  let at = a.at
  for (const [id, v] of Object.entries(b.at)) if (!(a.at[id] >= v)) { if (at === a.at) at = { ...a.at }; at[id] = v }
  return since === a.since && at === a.at ? a : { since, at }
}

const updatedOf = (s) => (s && s.time && Number(s.time.updated)) || 0

/** The stored record, parsed. Anything unreadable is an empty record — which baseline() then fills. */
export function readSeen(raw) {
  let o = null
  try { o = JSON.parse(raw || 'null') } catch { /* junk */ }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return { since: 0, at: {} }
  const at = {}
  for (const [id, v] of Object.entries(o.at && typeof o.at === 'object' ? o.at : {})) if (typeof v === 'number' && v > 0) at[id] = v
  return { since: typeof o.since === 'number' && o.since > 0 ? o.since : 0, at }
}

/** First sight on this device: `since` = the newest activity on the list. A record that has one is returned unchanged. */
export function baseline(seen, sessions) {
  if (seen.since) return seen
  const newest = Math.max(0, ...(Array.isArray(sessions) ? sessions : []).map(updatedOf))
  return newest ? { ...seen, since: newest } : seen
}

/** Sessions with activity past what you saw of them (never opened here: past `since`). Not the one you have open, not
 *  one running a turn (its spark says more, and the dot comes when it ends), not an archived one — and not a SUBAGENT's
 *  session whose conversation is on the list: it has no row to wear the dot or to open and clear it, so it lit ☰ for good
 *  (the owner: "Why do I have the green dot?"). Its work is its conversation's, whose own activity moves as it finishes. */
export function unreadIds(sessions, seen, { openSid = '', running = new Map() } = {}) {
  const out = new Set()
  if (!seen.since) return out
  const list = Array.isArray(sessions) ? sessions : []
  const ids = new Set(list.map((s) => s && s.id))
  for (const s of list) {
    if (!s || !s.id || s.id === openSid || running.has(s.id) || (s.time && s.time.archived)) continue
    if (typeof s.parentID === 'string' && s.parentID && ids.has(s.parentID)) continue
    if (updatedOf(s) > (seen.at[s.id] || seen.since)) out.add(s.id)
  }
  return out
}

/** You looked at a session: record its activity. Returns the SAME record when that changes nothing. */
export function markSeen(seen, sid, updated) {
  if (!sid || !(updated > 0) || (seen.at[sid] || 0) >= updated) return seen
  return { ...seen, at: { ...seen.at, [sid]: updated } }
}

/** Only sessions the list still has (active or archived) — the record never grows past the list. */
export function prune(seen, sessions) {
  const ids = new Set((Array.isArray(sessions) ? sessions : []).map((s) => s && s.id))
  const at = {}
  for (const [id, v] of Object.entries(seen.at)) if (ids.has(id)) at[id] = v
  return { ...seen, at }
}
