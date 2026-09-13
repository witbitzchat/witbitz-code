// tools/rc-link.mjs — make the local node an ADDED DEVICE of your Spaces account, by DEVICE-LINK (the same QR flow the
// app uses: Settings → Back up & recovery → Add a device). The node is the "new device": it shows a QR carrying an
// ephemeral PUBLIC key (no secret), your signed-in phone/desktop scans it and seals the account to that key, and the
// node opens the reply. After this the node holds the account master + the INDEX-ROOM pointer — so a room it creates
// can be written into that index and appears in your drawer on every device (tools/rc-mkroom.mjs, next).
//
// Nothing secret is in the QR (deviceLink.js inverts the obvious design). The reply is relayed content-blind through
// /api/link for ~2 minutes between two public keys the server cannot combine.
//
//   node tools/rc-link.mjs            → show the QR, wait, and write ~/.witbitz-rc.account.json (0600)
//   env: RC_LINK_ORIGIN (default https://spaces.witbitz.chat) MUST be the origin your "Add a device" runs on.
import { writeFileSync, chmodSync, renameSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { newLinkChallenge, openLinkReply, readLinkPayload } from '../spaces/public/deviceLink.js'
import { deriveKeysFromSecret, unseal } from '../spaces/public/recovery.js'
import { qrAnsi, qrSvg } from './rc-qr.mjs'

// Poll EVERY origin whose /api/link relay is live (the KV is bound on the vault + main project, but NOT on the vaulted
// app app.witbitz.chat — it 503s there), so the node connects no matter which one your phone sealed the reply to.
export const parseOrigins = (env) => String(env || 'https://spaces.witbitz.chat,https://witbitz-spaces.pages.dev').split(',').map((o) => o.trim().replace(/\/$/, '')).filter(Boolean)
const ORIGINS = parseOrigins(process.env.RC_LINK_ORIGIN)
const ACCOUNT_PATH = process.env.RC_ACCOUNT || join(homedir(), '.witbitz-rc.account.json')
const POLL_MS = 2500
const LIFE_MS = Number(process.env.RC_LINK_WAIT_MS || 300_000) // the ref is valid until a seal is posted, so we can wait out a slow (Google-failed → email-code) verification

/** The account this node now belongs to, from an opened link payload. Kept minimal: what a device needs to create a
 *  room and sync it into the drawer (master + index-room pointer), plus the identity anchor for attribution. */
export function accountFromPayload(pay) {
  if (!pay || typeof pay.master !== 'string' || !pay.master) return null
  return {
    v: 1,
    linkedAt: Date.now(),
    master: pay.master,
    code: pay.code || '',
    email: pay.email || (pay.anchor && pay.anchor.email) || '',
    idx: pay.idx || null,     // the INDEX ROOM (the drawer's sync doc) — the whole point: write a room here → it shows in the drawer
    rel: pay.rel || null,     // gated-backup release token, if the giver passed a factor — lets a future backup-pull fetch the index room when idx wasn't handed over
    pipes: pay.pipes || null,
    anchor: pay.anchor || null,
  }
}

/** GAP-CLOSER: when the link did not hand over the index-room pointer (the app hands over a keyless one), recover it the
 *  canonical way a client device does — derive the backup location from the master and read the (gated) backup blob
 *  with the release token, then take its indexRoom {room, mk}. Tries each origin; returns the pointer or null.
 *  `fetchImpl` is injectable for tests. */
export async function pullIndexRoom(account, origins, fetchImpl = fetch) {
  if (!account || !account.master) return null
  let master
  try { master = Buffer.from(String(account.master).replace(/-/g, '+').replace(/_/g, '/'), 'base64') } catch { return null }
  if (master.length !== 32) return null
  const loc = await deriveKeysFromSecret(new Uint8Array(master)) // { id, key } — same derivation as the client
  const rel = account.rel && account.rel.token
  for (const origin of origins) {
    let blob = null
    if (rel) { // gated backups: the short release token from the factor passed at link time
      try { const r = await fetchImpl(`${origin}/api/backup/release`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: rel, id: loc.id }) }).then((x) => x.json()); if (r && r.ok && r.blob) blob = r.blob } catch { /* try next origin */ }
    }
    if (!blob) continue
    try { const payload = await unseal(loc.key, blob); if (payload && payload.indexRoom && payload.indexRoom.room && payload.indexRoom.mk) return payload.indexRoom } catch { /* wrong key / tamper */ }
  }
  return null
}

/** Persist the account (0600). Returns the path. Exported for the linker + tests. */
export function storeAccount(account, path = ACCOUNT_PATH) {
  // A fresh 0600 temp file renamed over the target: the account master is never readable by others, never half-written.
  const tmp = `${path}.${process.pid}.${Date.now().toString(36)}.tmp`
  writeFileSync(tmp, JSON.stringify(account, null, 1), { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, path)
  return path
}

/**
 * Show the device-link QR, wait for a signed-in device to seal the account to this node, store it. Returns the account,
 * or null when it did not complete (expired, or a reply that would not open) — never exits the process, so the Code
 * pairing tool (and the single-file witbitz-code) can run it in-process. `accountPath` is where it is stored;
 * `lifeMs` how long to wait; `nextHint` prints the /rc follow-up.
 */
export async function linkNode({ accountPath = ACCOUNT_PATH, lifeMs = LIFE_MS, nextHint = true } = {}) {
  const ch = await newLinkChallenge()
  console.log(`rc-link: pairing this node to your account · polling ${ORIGINS.join(', ')}\n`)
  console.log('On your phone or desktop, in Spaces: Settings → Back up & recovery → Add a device, then scan this:\n')
  console.log(qrAnsi(ch.text) + '\n')
  const svg = join(homedir(), '.witbitz-rc.link.svg'); writeFileSync(svg, qrSvg(ch.text) + '\n'); chmodSync(svg, 0o600)
  console.log(`  (QR also saved to ${svg} · raw: ${ch.text})`)
  console.log(`  waiting up to ${Math.round(lifeMs / 1000)}s for your device to seal the account to this node…\n`)
  const until = Date.now() + lifeMs
  let warned503 = false
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, POLL_MS))
    let r = null
    for (const origin of ORIGINS) {
      let rr
      try { rr = await fetch(`${origin}/api/link?ref=${ch.ref}`, { cache: 'no-store' }).then((x) => x.json()) } catch { continue }
      if (rr && rr.reason === 'unavailable' && !warned503) { console.error(`rc-link: note — ${origin} has no device-link relay (OTP_KV unbound); ignoring it.`); warned503 = true }
      if (rr && rr.ok) { r = rr; break }
    }
    if (!r || !r.ok) continue // 404 on all = not sealed yet
    let pay = null
    try { pay = readLinkPayload(await openLinkReply(ch.priv, { ref: ch.ref, epk: r.epk, blob: r.blob })) } catch { /* not ours / tampered */ }
    if (!pay) { console.error('rc-link: a reply arrived but did not open — start again on both devices.'); return null }
    const account = accountFromPayload(pay)
    if (!account) { console.error('rc-link: the reply carried no account key.'); return null }
    let idxVia = account.idx ? 'link' : ''
    if (!account.idx) {
      process.stdout.write('rc-link: no index pointer in the link — recovering it from your account backup… ')
      const idx = await pullIndexRoom(account, ORIGINS).catch(() => null)
      if (idx) { account.idx = idx; idxVia = 'backup'; console.log('✓') } else console.log('not found (the release token may have expired — re-link, or use the one-tap link from rc-mkroom)')
    }
    const path = storeAccount(account, accountPath)
    console.log(`rc-link: ✓ linked as a device of ${account.email || '(your account)'}`)
    console.log(`  account → ${path} (0600)`)
    console.log(`  index room → ${account.idx ? account.idx.room + ' (via ' + idxVia + ')' : '(none — rc-mkroom will fall back to a one-tap link)'}`)
    if (nextHint) console.log(`\nnext: create a code room that lands in your drawer:  node tools/rc-mkroom.mjs`)
    return account
  }
  console.error('rc-link: the code expired before your device sealed to it. Run it again for a fresh QR.')
  return null
}

// (WITBITZ_CODE_BUNDLED is defined at bundle time: inside witbitz-code.mjs every module shares one import.meta.url.)
if (process.env.WITBITZ_CODE_BUNDLED !== "1" && process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  linkNode().then((a) => { if (!a) process.exit(1) }).catch((e) => { console.error('rc-link: FATAL —', (e && e.message) || e); process.exit(1) })
}
