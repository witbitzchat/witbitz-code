// codeComputers.js — the account's PAIRED COMPUTERS registry (docs/opencode-relay.md §3.1).
//
// A sealed `op:'state'` doc named 'computers' in the account's index room, beside 'index' and 'index2'. Every signed-in
// device reads it (roomSync.js) and hands the live entries to the Code section (codeView.js); the pairing tool
// (tools/opencode-pair.mjs) writes it from the computer. ONE merge rule for all of them, defined here:
//
//   { v: 1, computers: { <id>: { name, relay, secret, pairedAt, mod } | { removed: true, mod } } }
//
// Last-writer-wins PER ENTRY on `mod`; on a tie a removal wins. A removal is a tombstone that keeps no secret, so an
// unpair propagates instead of being re-added by a device that has not heard of it yet.
//
// ⚠ A separate doc on purpose: older builds strip unknown fields from index2.code and write it back; they never touch a
//   doc called 'computers', so they cannot unpair anyone.

export const COMPUTERS_KEY = 'space:computers'
export const COMPUTERS_DOC = 'computers'

const ID = /^[A-Za-z0-9_-]{8,64}$/
const SECRET = /^[A-Za-z0-9_-]{43}$/
const okRelay = (u) => { try { const x = new URL(String(u)); return x.protocol === 'wss:' || (x.protocol === 'ws:' && ['127.0.0.1', 'localhost'].includes(x.hostname)) } catch { return false } }
const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0) // a real number — not true, not "0x10"
// Entry maps have NO prototype: an id is only ever data, even one spelled like a built-in ("constructor", "__proto__").
const dict = (src) => Object.assign(Object.create(null), src || {})

/** One entry → its canonical shape, or null when it is not usable. */
export function normEntry(e) {
  if (!e || typeof e !== 'object') return null
  const mod = num(e.mod)
  if (!mod) return null
  if (e.removed) return { removed: true, mod }
  if (typeof e.secret !== 'string' || !SECRET.test(e.secret) || !okRelay(e.relay)) return null
  return { name: Array.from(String(e.name || 'computer')).slice(0, 80).join(''), relay: String(e.relay), secret: e.secret, pairedAt: num(e.pairedAt) || mod, mod } // cut by character, never mid-emoji
}

/** Any doc (or nothing) → { v: 1, computers: {…} } with only well-formed entries. */
export function normRegistry(doc) {
  const out = { v: 1, computers: dict() }
  const src = doc && typeof doc === 'object' && doc.computers && typeof doc.computers === 'object' ? doc.computers : {}
  for (const [id, e] of Object.entries(src)) { if (!ID.test(id)) continue; const n = normEntry(e); if (n) out.computers[id] = n }
  return out
}

/** Merge two registries: per id the higher `mod` wins; a tie goes to the removal. Pure. */
export function mergeRegistry(a, b) {
  const x = normRegistry(a), y = normRegistry(b)
  const out = { v: 1, computers: dict(x.computers) }
  for (const [id, e] of Object.entries(y.computers)) {
    const cur = out.computers[id]
    if (!cur || e.mod > cur.mod || (e.mod === cur.mod && e.removed && !cur.removed)) out.computers[id] = e
  }
  return out
}

export const sameRegistry = (a, b) => JSON.stringify(sortKeys(normRegistry(a))) === JSON.stringify(sortKeys(normRegistry(b)))
function sortKeys(r) { const c = dict(); for (const id of Object.keys(r.computers).sort()) c[id] = r.computers[id]; return { v: 1, computers: c } }

/** The computers you can connect to, oldest pairing first: [{ id, name, relay, secret }]. */
export function liveComputers(reg) {
  return Object.entries(normRegistry(reg).computers)
    .filter(([, e]) => !e.removed)
    .sort((p, q) => p[1].pairedAt - q[1].pairedAt || (p[0] < q[0] ? -1 : 1))
    .map(([id, e]) => ({ id, name: e.name, relay: e.relay, secret: e.secret }))
}

/** Add or update one computer (the pairing tool's write). */
export function withComputer(reg, id, { name, relay, secret }, now = Date.now()) {
  const prev = normRegistry(reg).computers[id]
  const mod = Math.max(now, prev ? prev.mod + 1 : 0)
  return mergeRegistry(reg, { computers: dict({ [id]: { name, relay, secret, pairedAt: prev && !prev.removed ? prev.pairedAt : now, mod } }) })
}

/** Tombstone one computer (unpair / "Remove" in Settings). */
export function withoutComputer(reg, id, now = Date.now()) {
  const prev = normRegistry(reg).computers[id]
  return mergeRegistry(reg, { computers: dict({ [id]: { removed: true, mod: Math.max(now, prev ? prev.mod + 1 : 0) } }) })
}

// ── this device's cached copy (browser only) ─────────────────────────────────────────────────────────────────────
export function loadRegistry() { try { return normRegistry(JSON.parse(localStorage.getItem(COMPUTERS_KEY) || 'null')) } catch { return normRegistry(null) } }
export function saveRegistry(reg) { try { localStorage.setItem(COMPUTERS_KEY, JSON.stringify(normRegistry(reg))) } catch { /* private mode */ } }
/** Fold a remote copy into ours. Returns true when what this device holds changed. */
export function adoptRegistry(remote) {
  const cur = loadRegistry()
  const next = mergeRegistry(cur, remote)
  if (sameRegistry(cur, next)) return false
  saveRegistry(next)
  return true
}
export function removeComputerLocally(id, now = Date.now()) { saveRegistry(withoutComputer(loadRegistry(), id, now)) }
