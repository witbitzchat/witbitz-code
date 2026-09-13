// spaces/public/recovery.js — CONTENT-BLIND backup of your Spaces (the list + each room's key). A device-generated
// RECOVERY CODE is the only secret. From it we derive, by two SEPARATE HKDF labels: an `id` (which ciphertext on the
// server is yours) and an AES-GCM `key` (that opens it) — so the id can never reveal the key. The server stores ONLY the
// ciphertext under the id and can't read it. The code NEVER reaches the server. Lose the code → the backup is
// unrecoverable (that's the guarantee). Zero deps: pure Web Crypto.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' // RFC 4648 base32 (no padding), for a human-savable code
function b32encode(u8) {
  let bits = 0, val = 0, out = ''
  for (const b of u8) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5 } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31]
  return out
}
function b32decode(s) {
  const clean = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '') // tolerate spaces/hyphens/case on input
  let bits = 0, val = 0; const out = []
  for (const c of clean) { val = (val << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8 } }
  return new Uint8Array(out)
}

const enc = new TextEncoder(), dec = new TextDecoder()
const SALT = enc.encode('witbitz-spaces-backup-v1')
const b64url = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
const fromB64url = (s) => { const b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/')); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u }

/** A fresh 128-bit recovery code as grouped base32, e.g. "ABCD-EFGH-JKLM-NPQR-STUV-WX". */
export function newRecoveryCode() {
  return b32encode(crypto.getRandomValues(new Uint8Array(16))).match(/.{1,4}/g).join('-')
}

async function hkdf(codeBytes, info, len) {
  const km = await crypto.subtle.importKey('raw', codeBytes, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: enc.encode(info) }, km, len * 8))
}

/** Derive { id (hex storage key), key (AES-GCM) } from raw secret bytes. Two HKDF labels → id can't reveal key. The
 *  secret can be a typed recovery code (below) OR a passkey's PRF output (spacePasskey.js) — same 32B secret, same backup. */
export async function deriveKeysFromSecret(secretBytes) {
  if (!secretBytes || secretBytes.length < 16) throw new Error('bad_secret')
  const idBytes = await hkdf(secretBytes, 'id', 16)
  const id = Array.from(idBytes, (b) => b.toString(16).padStart(2, '0')).join('')
  const key = await crypto.subtle.importKey('raw', await hkdf(secretBytes, 'enc', 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
  // WRITE-AUTHENTICATOR: a third, DISTINCT HKDF label. The server stores only SHA-256(wt) (write-once) and checks it on
  // every overwrite, so an attacker who captured just the `id` (which can't yield wt — different label) can't clobber the
  // backup. wt reveals neither the id nor the AES key nor the code, and it can't decrypt — it only proves "the writer holds
  // the recovery code". Sent to the server per write (functions/api/backup.js) ⇒ gates OUTSIDERS, not a malicious server.
  const wt = Array.from(await hkdf(secretBytes, 'bak-write', 32), (b) => b.toString(16).padStart(2, '0')).join('')
  return { id, key, wt }
}
/** The raw 16-byte secret behind a typed recovery code. The backup vault wraps the master secret to this value. */
export function codeSecret(code) {
  const b = b32decode(code)
  if (b.length < 16) throw new Error('bad_code')
  return b
}

/** Encrypt an object → base64url(iv‖ciphertext). */
export async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))))
  const buf = new Uint8Array(iv.length + ct.length); buf.set(iv); buf.set(ct, iv.length)
  return b64url(buf)
}
/** Decrypt base64url(iv‖ciphertext) → object. Throws on a wrong code or any tamper (AES-GCM auth). */
export async function unseal(key, blob) {
  const buf = fromB64url(blob)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12))
  return JSON.parse(dec.decode(pt))
}

// ── 2-of-2 RECOVERY GATE (design A) ──────────────────────────────────────────────────────────────────────────────────
// Recovery today is BEARER: the code alone opens the backup. Design A adds a server-enforced second factor — "(code) AND
// (email OR passkey)" — WITHOUT a server-side email↔backup graph. From the SAME secret, two more HKDF labels give a `gid`
// (where the server's gate record lives — separate from the ciphertext id) and a `gk` (HMAC key). The email commitment
// HMAC(gk, email) is KEYED by the 128-bit code, so a server that holds only the commitment can neither read nor
// brute-force the email; at recovery it checks a presented HMAC before mailing a code (stops a leaked code from spraying
// mail to arbitrary addresses). The code still decrypts — this is a gate IN FRONT of the unchanged bearer secret.

const normEmail = (e) => String(e || '').trim().toLowerCase()

/** { gid (hex, where the gate record lives), gk (HMAC key bytes) } from the recovery secret. Distinct HKDF labels from
 *  deriveKeysFromSecret, so the gate id can't reveal the ciphertext id or key, and vice versa. */
export async function gateParams(secretBytes) {
  if (!secretBytes || secretBytes.length < 16) throw new Error('bad_secret')
  const gidBytes = await hkdf(secretBytes, 'gate-id', 16)
  const gid = Array.from(gidBytes, (b) => b.toString(16).padStart(2, '0')).join('')
  const gk = await hkdf(secretBytes, 'gate-commit', 32)
  return { gid, gk }
}

/** A locator (hex) for the gate id, derived from a PASSKEY secret P — so a passkey-only restore (which has no recovery
 *  code, hence can't derive the gid) can still find its gate to pass the passkey factor. Distinct HKDF label; a P-holder
 *  is already the legitimate passkey user, so this reveals nothing extra. */
export async function gatePtr(secretBytes) {
  if (!secretBytes || secretBytes.length < 16) throw new Error('bad_secret')
  const b = await hkdf(secretBytes, 'gate-ptr', 16)
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

/** Bind an email to this code: HMAC-SHA256(gk, normalized email) → hex. Stored server-side as the gate's `commit_email`;
 *  reveals nothing about the email without the code. Normalizes case + surrounding space so the same address always
 *  matches. */
export async function emailCommit(gk, email) {
  const key = await crypto.subtle.importKey('raw', gk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(normEmail(email))))
  return Array.from(mac, (b) => b.toString(16).padStart(2, '0')).join('')
}
