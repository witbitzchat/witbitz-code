// tools/opencode-pair.mjs — PAIR this computer with your Spaces account, so the Code section on every device you are
// signed in on reaches the OpenCode running here — through the sealed relay, with nothing typed (docs/opencode-relay.md).
//
//   node tools/opencode-pair.mjs                show the QR → scan it with Add a device → this computer joins that account
//   node tools/opencode-pair.mjs --name "desk"  the name devices show (default: this machine's hostname)
//   node tools/opencode-pair.mjs --rotate       new secret(s) for existing pairings (no scan); restart the connector after
//   node tools/opencode-pair.mjs --unpair [--account you@x]   remove this computer from an account (no scan)
//   node tools/opencode-pair.mjs --status       list the pairings (never a secret)
//   bash tools/opencode-serve.sh --pair         pair, then start OpenCode + the connector
//
// What a pairing is (§3): a random 32-byte SECRET per (computer, account). It is stored here in
// ~/.witbitz/code/pairings.json (0600) and published into the account's sealed `computers` registry, which every
// signed-in device reads. The relay channel and both encryption keys derive from it; the relay never sees it.
//
// Several accounts can pair the same computer — each is a separate entry, secret and channel (§10). OpenCode has no users,
// so every paired account reaches the same sessions, files and shell; this tool says so when a second account pairs.
//
// ⚠ The registry and index2 are LIVE ACCOUNT DATA. op:'state' REPLACES a doc, so every write here READS first, refuses
//   unless that read was a definitive 200, merges, writes the whole doc back, and verifies by reading it again.
import { readFileSync, writeFileSync, chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, renameSync } from 'node:fs'
import { homedir, tmpdir, hostname } from 'node:os'
import { join, dirname } from 'node:path'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { _hasGzip, _jsonBytes, gunzipB64, gzipB64 } from '../spaces/public/compress.js'
import { linkNode } from './rc-link.mjs'
import { COMPUTERS_DOC, normRegistry, withComputer, withoutComputer, liveComputers } from '../spaces/public/codeComputers.js'
import { newRelaySecret, RELAY_URL } from '../spaces/public/codeRelay.js'

// Account docs above ~24 KB are gzip-wrapped as { z } (roomSync.js pushIndexDoc / rc-mkroom.mjs) — same rule, kept here so
// this tool (and the single-file bundle) does not pull in the room-minting code.
const GZIP_OVER = 24000
async function unwrapIndexState(state) { return state && typeof state === 'object' && typeof state.z === 'string' ? gunzipB64(state.z) : state }
async function wrapIndexState(state) { return _hasGzip && _jsonBytes(state) > GZIP_OVER ? { z: await gzipB64(state) } : state }
const API = process.env.RC_BASE || 'https://api.witbitz.chat/v1/space'
const ORIGIN = process.env.RC_ORIGIN || 'https://witbitz-spaces.pages.dev'
export const PAIRINGS_PATH = process.env.WITBITZ_CODE_PAIRINGS || join(homedir(), '.witbitz', 'code', 'pairings.json')
const ENV_PATH = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')
const START_HINT = process.env.WITBITZ_CODE_BUNDLED === '1' ? 'node witbitz-code.mjs serve' : 'bash tools/opencode-serve.sh'
/** Secret files are created 0600 — never written world-readable first and chmod-ed after. */
/** Secret files: written to a fresh 0600 temp file beside the target, then renamed over it — never readable by others,
 *  never half-written if the process dies mid-write. */
export function writeSecret(path, data) {
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  try { writeFileSync(tmp, data, { mode: 0o600 }); chmodSync(tmp, 0o600); renameSync(tmp, path) }
  catch (e) { try { rmSync(tmp, { force: true }) } catch { /* */ } throw e }
}

// ── pure helpers (tested in opencode-pair.test.mjs) ─────────────────────────────────────────────────────────────────

/** The value of KEY in an env file — the LAST assignment wins, as when the file is sourced. Quotes are stripped. */
export function envGet(text, key) {
  let v = null
  for (const line of String(text || '').split(/\r?\n/)) { // CRLF too — `.` does not match \r
    const m = line.match(new RegExp(`^\\s*(?:export\\s+)?${key}=(.*)$`))
    if (m) v = m[1].trim().replace(/^(['"])(.*)\1$/, '$2')
  }
  return v
}

/** Set KEY=value: every existing assignment of KEY is removed, one is appended, every other line is kept verbatim. */
export function envSet(text, key, value) {
  const keep = String(text || '').split(/\r?\n/).filter((l) => !new RegExp(`^\\s*(?:export\\s+)?${key}=`).test(l))
  while (keep.length && keep[keep.length - 1] === '') keep.pop()
  keep.push(`${key}=${value}`)
  return keep.join('\n') + '\n'
}

/** 32 URL-safe characters (192 bits) — the LOCAL OpenCode password; it never leaves this computer. */
export const newPassword = () => randomBytes(24).toString('base64url')
/** A computer id: 16 random bytes, base64url. One per (computer, account) pairing. */
export const newComputerId = () => randomBytes(16).toString('base64url')

/** The pairings file as a list-holder; tolerant of a missing or broken file. */
export function normPairings(doc) {
  const list = doc && Array.isArray(doc.pairings) ? doc.pairings : []
  return { v: 1, pairings: list.filter((p) => p && p.idx && p.idx.room && p.idx.mk && typeof p.secret === 'string' && typeof p.computerId === 'string') }
}

/** Add this computer for an account, or refresh the existing entry (same id + secret unless `rotate`). Pure. */
export function upsertPairing(doc, { account, idx, name, relay = RELAY_URL, opencodeUrl = '' }, { rotate = false, mintId = newComputerId, mintSecret = newRelaySecret } = {}) {
  const cur = normPairings(doc)
  const i = cur.pairings.findIndex((p) => p.idx.room === idx.room)
  const prev = i >= 0 ? cur.pairings[i] : null
  const entry = {
    account: account || (prev && prev.account) || '',
    idx: { room: idx.room, mk: idx.mk },
    computerId: prev ? prev.computerId : mintId(),
    secret: prev && !rotate ? prev.secret : mintSecret(),
    name: name || (prev && prev.name) || hostname(),
    relay,
    // An OpenCode asked for (`pair --port 4097`) wins; not asked → the entry keeps the one it had. Keeping the old one even when
    // asked made `setup --port 4097` fail on an account already paired for 4096: the scan "refreshed" and stayed on 4096.
    opencodeUrl: opencodeUrl || (prev && prev.opencodeUrl) || 'http://127.0.0.1:4096',
  }
  const pairings = cur.pairings.slice()
  if (i >= 0) pairings[i] = entry; else pairings.push(entry)
  const others = pairings.filter((p) => p.idx.room !== idx.room && p.opencodeUrl === entry.opencodeUrl)
  return { doc: { v: 1, pairings }, entry, isNew: !prev, sharedWith: others.map((p) => p.account || '(another account)') }
}

/** Drop the entries matching `account` (email) — or every entry when `account` is empty. Pure. */
export function removePairings(doc, account = '') {
  const cur = normPairings(doc)
  const gone = cur.pairings.filter((p) => !account || p.account === account)
  return { doc: { v: 1, pairings: cur.pairings.filter((p) => !gone.includes(p)) }, removed: gone }
}

// ── account writes (read-merge-write, verified) ─────────────────────────────────────────────────────────────────────

async function readDoc(call, idx, name) {
  const rd = await call({ op: 'state', room: idx.room, mk: idx.mk, name })
  if (rd.status !== 200 || !rd.j || rd.j.error) return { ok: false, why: `${name} read refused (${rd.status}${rd.j && rd.j.error ? ': ' + rd.j.error : ''}) — NOT writing` }
  try { return { ok: true, state: await unwrapIndexState(rd.j.state || null) } } catch (e) { return { ok: false, why: `${name} unreadable (${(e && e.message) || e}) — NOT writing` } }
}

/** Put (or refresh) this computer in the account's registry. */
export async function publishComputer({ call, idx, computerId, name, relay, secret, now = Date.now() }) {
  const rd = await readDoc(call, idx, COMPUTERS_DOC)
  if (!rd.ok) return rd
  const next = withComputer(rd.state, computerId, { name, relay, secret }, now)
  const wr = await call({ op: 'state', room: idx.room, mk: idx.mk, name: COMPUTERS_DOC, patch: await wrapIndexState({ ...next, at: now }), summary: 'computer paired', by: 'node' })
  if (wr.status !== 200) return { ok: false, why: `computers write refused (${wr.status})` }
  const back = await readDoc(call, idx, COMPUTERS_DOC)
  const got = back.ok && normRegistry(back.state).computers[computerId]
  if (!got || got.removed || got.secret !== secret) return { ok: false, why: 'wrote the registry but the read-back does not match — check the account before relying on it' }
  return { ok: true, computers: liveComputers(back.state) }
}

/** Tombstone this computer in the account's registry (its secret leaves the account). Nothing there → nothing written. */
export async function unpublishComputer({ call, idx, computerId, now = Date.now() }) {
  const rd = await readDoc(call, idx, COMPUTERS_DOC)
  if (!rd.ok) return rd
  const cur = normRegistry(rd.state).computers[computerId]
  if (!cur || cur.removed) return { ok: true, noop: true }
  const next = withoutComputer(rd.state, computerId, now)
  const wr = await call({ op: 'state', room: idx.room, mk: idx.mk, name: COMPUTERS_DOC, patch: await wrapIndexState({ ...next, at: now }), summary: 'computer unpaired', by: 'node' })
  if (wr.status !== 200) return { ok: false, why: `computers write refused (${wr.status})` }
  const back = await readDoc(call, idx, COMPUTERS_DOC)
  if (!back.ok || !normRegistry(back.state).computers[computerId] || !normRegistry(back.state).computers[computerId].removed) return { ok: false, why: 'wrote the tombstone but the read-back does not show it' }
  return { ok: true }
}

/** The OLD direct path (pre-relay): empty index2.code.base/pass so no device keeps dialling a server address. Keeps
 *  contacts, calendar and the chosen model/agent; nothing set → nothing written. */
export async function clearLegacyDirect({ call, idx, now = Date.now() }) {
  const rd = await readDoc(call, idx, 'index2')
  if (!rd.ok) return rd
  const s = rd.state && typeof rd.state === 'object' ? rd.state : {}
  const prev = s.code && typeof s.code === 'object' ? s.code : null
  if (!prev || (!prev.base && !prev.pass)) return { ok: true, noop: true }
  const code = { base: '', pass: '', model: typeof prev.model === 'string' ? prev.model : '', agent: typeof prev.agent === 'string' ? prev.agent : '', mod: Math.max(now, (Number(prev.mod) || 0) + 1) }
  const next = { ...s, v: s.v || 2, code, at: now }
  const wr = await call({ op: 'state', room: idx.room, mk: idx.mk, name: 'index2', patch: await wrapIndexState(next), summary: 'code direct server cleared', by: 'node' })
  if (wr.status !== 200) return { ok: false, why: `index2 write refused (${wr.status})` }
  const back = await readDoc(call, idx, 'index2')
  if (!back.ok || !back.state || !back.state.code || back.state.code.base !== '' || back.state.code.pass !== '') return { ok: false, why: 'cleared index2 but the read-back does not match' }
  return { ok: true }
}

// ── the command ──────────────────────────────────────────────────────────────────────────────────────────────────────

const call = async (body) => {
  const r = await fetch(API, { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify(body) })
  let j = null; try { j = await r.json() } catch { /* non-JSON */ }
  return { status: r.status, j }
}
const readPairings = () => { try { return normPairings(JSON.parse(readFileSync(PAIRINGS_PATH, 'utf8'))) } catch { return normPairings(null) } }
function writePairings(doc) {
  mkdirSync(dirname(PAIRINGS_PATH), { recursive: true, mode: 0o700 })
  writeSecret(PAIRINGS_PATH, JSON.stringify(doc, null, 1) + '\n')
}
function parseArgs(argv) {
  const a = { rotate: false, dry: false, unpair: false, status: false, name: '', account: '', opencodeUrl: '' }
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i]
    if (x === '--rotate') a.rotate = true
    else if (x === '--dry-run') a.dry = true
    else if (x === '--unpair') a.unpair = true
    else if (x === '--status') a.status = true
    else if (x === '--name') a.name = argv[++i] || ''
    else if (x === '--account') a.account = argv[++i] || ''
    else if (x === '--opencode-url') a.opencodeUrl = argv[++i] || ''
    else if (x === '--port') { const p = Number(argv[++i]); if (p) a.opencodeUrl = `http://127.0.0.1:${p}` }
    else { console.error(`opencode-pair: unknown argument ${x}`); process.exit(2) }
  }
  return a
}

/** The QR ritual: tools/rc-link.mjs shows the Add-a-device QR and waits for a signed-in device to seal the account to
 *  this computer. It writes to a PRIVATE temp file; an expired or failed scan changes nothing. The /rc tools keep their
 *  own single account file (~/.witbitz-rc.account.json) — pairing Code never replaces it. */
async function linkByQr() {
  console.log('opencode-pair: on your phone open Spaces → Settings → Back up & recovery → Add a device, and scan the QR below with the account to pair.\n')
  const dir = mkdtempSync(join(tmpdir(), 'oc-pair-'))
  const tmp = join(dir, 'account.json')
  try {
    const acct = await linkNode({ accountPath: tmp, nextHint: false })
    if (!acct) return null
    if (!acct.idx || !acct.idx.room || !acct.idx.mk) { console.error('opencode-pair: the scan carried no index-room pointer, so there is nowhere to publish — nothing changed.'); return null }
    return acct
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

function ensureLocalPassword() {
  const envText = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, 'utf8') : ''
  if (envGet(envText, 'OPENCODE_SERVER_PASSWORD')) return
  writeSecret(ENV_PATH, envSet(envText, 'OPENCODE_SERVER_PASSWORD', newPassword()))
  console.log(`opencode-pair: ✓ minted a local OpenCode password in ${ENV_PATH} (0600) — it never leaves this computer`)
}

async function publishEntry(e) {
  const r = await publishComputer({ call, idx: e.idx, computerId: e.computerId, name: e.name, relay: e.relay, secret: e.secret })
  if (!r.ok) { console.error(`opencode-pair: ✖ ${e.account || 'account'}: ${r.why}`); return false }
  console.log(`opencode-pair: ✓ "${e.name}" is in ${e.account || 'the account'}'s computers (${r.computers.length} paired)`)
  const l = await clearLegacyDirect({ call, idx: e.idx })
  if (!l.ok) console.log(`opencode-pair: ⚠ could not clear the old direct-server settings (${l.why}) — harmless while a computer is paired`)
  else if (!l.noop) console.log('opencode-pair: ✓ cleared the old direct-server address from the account (devices use the relay now)')
  return true
}

/** Remove one pairing from its account (every signed-in device drops the computer), then from this computer. For
 *  `witbitz-code uninstall`, which must report a failure and carry on — main() exits. → { ok, why } */
export async function unpairEntry(p) {
  const r = await unpublishComputer({ call, idx: p.idx, computerId: p.computerId })
  if (r.ok) writePairings(removePairings(readPairings(), p.account).doc)
  return r
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv)
  const doc = readPairings()

  if (args.status) {
    if (!doc.pairings.length) console.log('opencode-pair: not paired')
    for (const p of doc.pairings) console.log(`· "${p.name}" → ${p.account || '(account)'} · OpenCode ${p.opencodeUrl} · relay ${p.relay}`)
    return
  }

  if (args.unpair) {
    const targets = doc.pairings.filter((p) => !args.account || p.account === args.account)
    if (!targets.length) { console.error(`opencode-pair: no pairing${args.account ? ' for ' + args.account : ''} on this computer`); process.exit(1) }
    if (targets.length > 1 && !args.account) { console.error(`opencode-pair: this computer is paired with ${targets.length} accounts (${targets.map((p) => p.account).join(', ')}) — pass --account <email>`); process.exit(1) }
    if (args.dry) { console.log(`opencode-pair: --dry-run — would remove "${targets[0].name}" from ${targets[0].account}`); return }
    let ok = true
    for (const p of targets) {
      const r = await unpublishComputer({ call, idx: p.idx, computerId: p.computerId })
      if (!r.ok) { ok = false; console.error(`opencode-pair: ✖ ${p.account}: ${r.why} — kept the local pairing so you can retry`); continue }
      console.log(`opencode-pair: ✓ removed "${p.name}" from ${p.account}${r.noop ? ' (it was not listed)' : ''} — every device drops it on its next sync`)
      writePairings(removePairings(readPairings(), p.account).doc)
    }
    console.log(`opencode-pair: restart the connector (${START_HINT}) so it stops answering on the old channel.`)
    if (!ok) process.exit(1)
    return
  }

  if (args.rotate) {
    if (!doc.pairings.length) { console.error('opencode-pair: nothing to rotate — pair first'); process.exit(1) }
    const toRotate = doc.pairings.filter((x) => !args.account || x.account === args.account)
    if (args.dry) { console.log(`opencode-pair: --dry-run — would rotate ${toRotate.length} pairing(s)`); return }
    let cur = doc
    let ok = true
    for (const p of toRotate) {
      const u = upsertPairing(cur, { account: p.account, idx: p.idx, name: p.name, relay: p.relay, opencodeUrl: p.opencodeUrl }, { rotate: true })
      if (await publishEntry(u.entry)) { cur = u.doc; writePairings(cur) } else ok = false
    }
    console.log('opencode-pair: restart the connector so it listens on the new channel(s).')
    if (!ok) process.exit(1)
    return
  }

  // PAIR — the QR ritual
  if (args.dry) { console.log('opencode-pair: --dry-run — would show the QR, then publish this computer to the scanning account'); return }
  const acct = await linkByQr()
  if (!acct) { console.error('opencode-pair: pairing did not complete — nothing changed.'); process.exit(1) }
  const u = upsertPairing(doc, { account: acct.email || '', idx: acct.idx, name: args.name, opencodeUrl: args.opencodeUrl || undefined })
  ensureLocalPassword()
  if (!(await publishEntry(u.entry))) { console.error('opencode-pair: nothing saved locally — scan again to retry.'); process.exit(1) }
  writePairings(u.doc)
  console.log(`opencode-pair: ✓ ${u.isNew ? 'paired' : 'refreshed'} "${u.entry.name}" with ${u.entry.account || 'your account'} (${PAIRINGS_PATH})`)
  if (u.sharedWith.length) {
    console.log(`opencode-pair: ⚠ this computer's OpenCode (${u.entry.opencodeUrl}) is now reachable from ${u.entry.account} AND ${u.sharedWith.join(', ')}.`)
    console.log('               OpenCode has no users: they share every session, file and shell. Fine for your own accounts;')
    console.log('               for another person run a separate OpenCode (another port and OS user) and pair with --opencode-url.')
  }
  console.log(`opencode-pair: next — start OpenCode and the connector:  ${START_HINT}`)
}

// (WITBITZ_CODE_BUNDLED is defined at bundle time: inside witbitz-code.mjs every module shares one import.meta.url.)
if (process.env.WITBITZ_CODE_BUNDLED !== "1" && process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((e) => { console.error('opencode-pair: FATAL —', (e && e.message) || e); process.exit(1) })
}
