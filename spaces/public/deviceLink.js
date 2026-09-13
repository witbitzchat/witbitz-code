// spaces/public/deviceLink.js — bring a NEW device in by QR, without putting a secret in the QR.
//
// The obvious design is to render the recovery code as a QR and scan it. That makes the picture the secret: one
// photograph, one screen recording, one shoulder over yours, and it works forever. So the direction is inverted.
//
//   NEW device (empty)          draws a QR: an ephemeral PUBLIC key + a random ref. Nothing secret.
//   OLD device (has the vault)  scans it, confirms with a passkey, seals the master secret to that public key,
//                               and posts the ciphertext to the ref.
//   NEW device                  polls the ref, opens it with the private half it never let out of memory.
//
// The server relays a ciphertext between two public keys it cannot combine: it sees ECDH publics and AES-GCM output,
// and holds them for two minutes. Content-blind, like everything else here.
//
// What this does NOT defend against: someone persuading you to scan THEIR QR instead of your new device's. That is the
// same exposure every device-linking QR has, and the answer is the same — the old device says plainly what it is about
// to do, and asks for a biometric first. Physical possession of the unlocked device is the price of admission either
// way, which is why this adds no reach an attacker holding it did not already have.

export const LINK_PREFIX = 'wbzlink1:'
const B64 = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const UNB64 = (s) => { const b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/')); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u }
const te = new TextEncoder(), td = new TextDecoder()
const P256 = { name: 'ECDH', namedCurve: 'P-256' }
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('')

/** Compressed P-256 point (33 bytes) so the QR stays sparse enough to scan in poor light. */
async function exportPub(key) {
  const jwk = await crypto.subtle.exportKey('jwk', key)
  const x = UNB64(jwk.x), y = UNB64(jwk.y)
  const out = new Uint8Array(33); out[0] = (y[31] & 1) ? 3 : 2; out.set(x, 1)
  return B64(out)
}

// Decompress: recover y from x via y² = x³ - 3x + b (mod p), then y = ±√ using p ≡ 3 (mod 4).
const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn
const toBig = (u8) => BigInt('0x' + hex(u8))
const toBytes = (n) => { const h = n.toString(16).padStart(64, '0'); const u = new Uint8Array(32); for (let i = 0; i < 32; i++) u[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return u }
function modPow(base, exp, m) { let r = 1n, b = base % m; while (exp > 0n) { if (exp & 1n) r = (r * b) % m; b = (b * b) % m; exp >>= 1n } return r }
async function importPub(b64) {
  const raw = UNB64(b64)
  if (raw.length !== 33 || (raw[0] !== 2 && raw[0] !== 3)) throw new Error('bad_point')
  const x = toBig(raw.subarray(1))
  if (x >= P) throw new Error('bad_point')
  const y2 = (modPow(x, 3n, P) - 3n * x + B) % P
  let y = modPow((y2 + P) % P, (P + 1n) / 4n, P)
  if ((y * y) % P !== (y2 + P) % P) throw new Error('bad_point') // x was not on the curve
  if ((y & 1n) !== BigInt(raw[0] & 1)) y = P - y
  return crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: B64(toBytes(x)), y: B64(toBytes(y)), ext: true }, P256, false, [])
}

/** Both sides derive the same AES-GCM key from the shared point, bound to the ref so a blob can't be replayed at another. */
async function sharedKey(priv, pub, ref) {
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256))
  const base = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(ref), info: te.encode('witbitz-device-link-v1') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/** NEW device: mint the challenge to draw as a QR. `priv` never leaves this process. */
export async function newLinkChallenge() {
  const kp = await crypto.subtle.generateKey(P256, false, ['deriveBits'])
  const ref = hex(crypto.getRandomValues(new Uint8Array(16)))
  const pub = await exportPub(kp.publicKey)
  return { ref, pub, priv: kp.privateKey, text: LINK_PREFIX + ref + '.' + pub }
}

/** OLD device: what the camera saw → { ref, pub }, or null for anything else pointed at it. */
export function parseChallenge(text) {
  const s = String(text ?? '')
  if (!s.startsWith(LINK_PREFIX)) return null
  const [ref, pub, ...rest] = s.slice(LINK_PREFIX.length).split('.')
  if (rest.length || !/^[0-9a-f]{32}$/.test(ref || '') || !/^[A-Za-z0-9_-]{44}$/.test(pub || '')) return null
  return { ref, pub }
}

/** OLD device: seal a payload to the scanned challenge. Returns what to POST to /api/link. */
export async function sealToChallenge({ ref, pub }, payload) {
  const theirs = await importPub(pub)
  const mine = await crypto.subtle.generateKey(P256, false, ['deriveBits'])
  const key = await sharedKey(mine.privateKey, theirs, ref)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(payload))))
  const out = new Uint8Array(iv.length + ct.length); out.set(iv); out.set(ct, iv.length)
  return { ref, epk: await exportPub(mine.publicKey), blob: B64(out) }
}

/** NEW device: open what the ref handed back. Throws on anything that isn't ours and intact. */
export async function openLinkReply(priv, { ref, epk, blob }) {
  const key = await sharedKey(priv, await importPub(epk), ref)
  const raw = UNB64(blob)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, key, raw.subarray(12))
  return JSON.parse(td.decode(pt))
}

// ── The payload ──────────────────────────────────────────────────────────────────────────────────────────────────────
// Linking a device is PROVISIONING IT INTO THE ACCOUNT, not couriering a key to it. The first build sent the master
// secret alone, which left the new device holding every Space while being nobody: no recovery code, so it could not
// derive gid/gk and therefore could not run the email factor, protect its backup or migrate a gate — and asking it to
// show the recovery code would silently MINT A SECOND ONE, putting two codes in circulation for one vault. It was not
// signed in either, so the app treated it as a guest.
//
// The code costs nothing to include: the payload already carries the master secret, which the code merely unwraps to.
// Anyone who can open this reply already holds the stronger of the two.
//
// The passkey record deliberately does NOT travel. A credential is bound to the device that enrolled it; copying the
// credId would leave the new device advertising a passkey it cannot assert against, which is worse than having none.
// It enrols its own.

/** What the giving device seals. Optional halves are ABSENT rather than empty — a blank must not overwrite anything. */
export function linkPayload({ vault, email, rel, idx, pipes, anchor } = {}) {
  const v = vault || {}
  const ptr = (p) => (p && p.room && p.mk ? { room: String(p.room), mk: String(p.mk) } : null)
  const i = ptr(idx), pp = ptr(pipes)
  // The giver's identity ANCHOR, so the linked device inherits the same email/Google login (else it lands "signed in"
  // with keys but no identity → the Settings "Login" row is blank). Google anchors are tiny; for an email anchor we drop
  // the device keypair (kept small under the relay's blob cap) — its token+email suffice for the UI, and the app
  // re-derives the kp via a silent verification on the first crypto-gated op.
  const slimAnchor = (a) => {
    if (!a || !a.method || !a.email) return null
    if (a.method === 'google') return { method: 'google', email: String(a.email), ...(a.exp ? { exp: a.exp } : {}) }
    if (a.token) return { method: String(a.method), email: String(a.email), token: String(a.token), ...(a.exp ? { exp: a.exp } : {}) }
    return null
  }
  const an = slimAnchor(anchor)
  return {
    v: 1,
    master: v.master,
    ...(v.code ? { code: v.code } : {}),
    ...(email ? { email: String(email) } : {}),
    ...(rel && rel.token ? { rel: { gid: String(rel.gid || ''), token: rel.token } } : {}),
    // The index-room (+ pipes) POINTER, so a GATED account links: the receiver can't authorize the gated backup read
    // (it has no factor), but the index room is an ordinary sealed room — syncIndexRoom absorbs every Space's key from it.
    ...(i ? { idx: i } : {}),
    ...(pp ? { pipes: pp } : {}),
    ...(an ? { anchor: an } : {}),
  }
}

/** What the receiving device applies, or null if there is no usable key in it. */
export function readLinkPayload(p) {
  if (!p || typeof p !== 'object' || typeof p.master !== 'string' || !p.master) return null
  const ptr = (x) => (x && typeof x.room === 'string' && typeof x.mk === 'string' && x.room && x.mk ? { room: x.room, mk: x.mk } : null)
  const anchor = (() => { const a = p.anchor; if (!a || (a.method !== 'google' && a.method !== 'email') || typeof a.email !== 'string' || !a.email) return null; if (a.method === 'email' && !(typeof a.token === 'string' && a.token)) return null; return { method: a.method, email: a.email, ...(typeof a.token === 'string' && a.token ? { token: a.token } : {}), ...(a.exp ? { exp: a.exp } : {}) } })()
  return {
    master: p.master,
    code: typeof p.code === 'string' ? p.code : '',
    email: typeof p.email === 'string' ? p.email : '',
    // Half a release is no release: a token-less rel must not look like one and skip the gated read.
    rel: (p.rel && typeof p.rel.token === 'string' && p.rel.token) ? { gid: String(p.rel.gid || ''), token: p.rel.token } : null,
    idx: ptr(p.idx),     // index-room pointer handed over directly (gated accounts, where the receiver can't do the backup read)
    pipes: ptr(p.pipes), // private-lanes / assistant room pointer
    anchor,              // giver's email/Google identity → the linked device shows "signed in as …" (adoptAnchor on the receiver)
  }
}
