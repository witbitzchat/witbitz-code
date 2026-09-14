// spaces/public/nitroVerify.js — verify an AWS Nitro Enclaves attestation document, in the browser.
//
// ★ WHAT THIS BUYS. The rest of the trust ladder (D1 egress-lock CSP, D2 content-blind proof, D3 signed build cert,
// D4 reproducible build) proves things about code we PUBLISH. It cannot prove what the machine actually loaded.
// A Nitro attestation document is signed by a key that lives in hardware the operator cannot reach, and it states:
// "the enclave running right now measures to these PCRs, and it holds the private half of this public key".
// Verify it, and sealing a room key to that public key means the plaintext is reachable only by the measured image.
//
// ★★ WHAT IT DOES NOT BUY — and the copy must say so, because the whole point of this programme is not overclaiming:
//   1. It proves the MEASUREMENT, not the BEHAVIOUR. PCR0 is a hash. If you cannot rebuild that hash from published
//      source (D4), "measured" tells you the image didn't change, not that it does what the docs say.
//   2. A document with no nonce proves an enclave EXISTED, not that it is the one answering you now. Freshness comes
//      from a challenge (`nonce`), not from a timestamp the same party chose.
//   3. Model egress is untouched. Attestation protects the key and the code. It does not stop plaintext going to a
//      model vendor, because that is what the room is FOR.
//
// Everything here runs on WebCrypto and nothing else, so the same file serves the Lambda and the page.

import { decode, encodeArray, encodeBytes, encodeText } from './cbor.js'
import { bytesEqual, importSpki, verifyChain } from './x509.js'

/** The AWS Nitro Enclaves root, G1 — https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
 *  SHA-256 of this DER: 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b (AWS publishes the same).
 *  ★ PINNED ON PURPOSE. The document carries its own root in `cabundle[0]`; we ignore that copy and start from this
 *  one. A verifier that trusts the anchor its input supplied is not verifying anything. */
export const NITRO_ROOT_G1_B64 =
  'MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoG' +
  'A1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQG' +
  'EwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuB' +
  'BAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ' +
  '3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0P' +
  'AQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi' +
  '85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y='

const COSE_ALG_ES384 = -35 // COSE header label 1 (alg); ES384 is the only algorithm Nitro emits
const MAX_DOC = 1 << 20
const MAX_FIELD = 1024
const MAX_CABUNDLE = 8

export function b64ToBytes(b64) {
  const s = String(b64).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')

const isBytes = (x) => x instanceof Uint8Array
const optBytes = (m, k) => {
  const v = m.get(k)
  if (v === null || v === undefined) return null
  if (!isBytes(v) || v.length > MAX_FIELD) throw new Error(`attestation: bad ${k}`)
  return v.length ? v : null
}

/** Rebuild the exact bytes COSE_Sign1 signs: ["Signature1", protected, external_aad, payload]. */
function sigStructure(protectedBytes, payloadBytes) {
  return encodeArray([
    encodeText('Signature1'),
    encodeBytes(protectedBytes),
    encodeBytes(new Uint8Array(0)), // external_aad — always empty for Nitro
    encodeBytes(payloadBytes),
  ])
}

function parseDocument(payloadBytes) {
  const m = decode(payloadBytes)
  if (!(m instanceof Map)) throw new Error('attestation: payload is not a map')

  const moduleId = m.get('module_id')
  if (typeof moduleId !== 'string' || !moduleId || moduleId.length > MAX_FIELD) throw new Error('attestation: bad module_id')

  const digest = m.get('digest')
  if (digest !== 'SHA384') throw new Error(`attestation: unexpected digest ${digest}`)

  const timestamp = m.get('timestamp')
  if (typeof timestamp !== 'number' || !(timestamp > 0)) throw new Error('attestation: bad timestamp')

  const pcrsMap = m.get('pcrs')
  if (!(pcrsMap instanceof Map) || pcrsMap.size < 1 || pcrsMap.size > 32) throw new Error('attestation: bad pcrs')
  const pcrs = {}
  for (const [k, v] of pcrsMap) {
    if (!Number.isInteger(k) || k < 0 || k > 31) throw new Error('attestation: bad PCR index')
    if (!isBytes(v) || (v.length !== 32 && v.length !== 48 && v.length !== 64)) throw new Error(`attestation: bad PCR${k}`)
    pcrs[k] = toHex(v)
  }

  const certificate = m.get('certificate')
  if (!isBytes(certificate) || !certificate.length) throw new Error('attestation: missing certificate')

  const cabundle = m.get('cabundle')
  if (!Array.isArray(cabundle) || !cabundle.length || cabundle.length > MAX_CABUNDLE) throw new Error('attestation: bad cabundle')
  for (const c of cabundle) if (!isBytes(c) || !c.length) throw new Error('attestation: bad cabundle entry')

  return {
    moduleId,
    timestamp,
    digest,
    pcrs,
    certificate,
    cabundle,
    publicKey: optBytes(m, 'public_key'),
    userData: optBytes(m, 'user_data'),
    nonce: optBytes(m, 'nonce'),
  }
}

/**
 * Verify a Nitro attestation document. Throws with a specific reason on any failure; never returns a partial result.
 *
 * @param cose      raw COSE_Sign1 bytes (as returned by the NSM)
 * @param root      trust anchor DER; defaults to the pinned AWS Nitro root G1
 * @param now       verification time, ms
 * @param maxAgeMs  reject a document older than this. A WEAK freshness check — see the header note; prefer `nonce`.
 * @param expectedPCRs  { [index]: hex } that must match exactly. Omit and you have verified genuine AWS hardware
 *                      but NOT which image it is running — which is almost never what you want.
 * @param nonce     the challenge you sent; must come back byte-identical. The only real proof of liveness.
 */
// §ROLLOVER-SET. A pin is one hex digest, or a SET of them. The set exists for exactly one purpose: while a new image
// rolls out, {outgoing, incoming} must BOTH verify, or whichever side has not moved yet is refused — which is what
// turns an update into a synchronized cutover. It is CAPPED because a pin's whole value is that it is narrow; an
// unbounded list stops being a pin and becomes a standing menu of accepted images.
export const MAX_PIN_SET = 2
export function acceptedSet(pin, label = 'pin') {
  const list = (Array.isArray(pin) ? pin : [pin]).map((h) => String(h).toLowerCase())
  if (!list.length) throw new Error(`attestation: ${label} pins an empty set — that is not a check`)
  if (list.length > MAX_PIN_SET) throw new Error(`attestation: ${label} pins ${list.length} values; at most ${MAX_PIN_SET} (a rollover is {outgoing, incoming})`)
  return list
}

export async function verifyAttestation(cose, { root, now = Date.now(), maxAgeMs = 0, expectedPCRs = null, nonce = null } = {}) {
  const raw = cose instanceof Uint8Array ? cose : new Uint8Array(cose)
  if (!raw.length || raw.length > MAX_DOC) throw new Error('attestation: implausible document size')

  const cs = decode(raw)
  if (!Array.isArray(cs) || cs.length !== 4) throw new Error('attestation: not a COSE_Sign1 structure')
  const [protectedBytes, unprotected, payloadBytes, signature] = cs
  if (!isBytes(protectedBytes) || !isBytes(payloadBytes) || !isBytes(signature)) throw new Error('attestation: malformed COSE_Sign1')
  if (!(unprotected instanceof Map)) throw new Error('attestation: malformed COSE header')

  // The algorithm must come from the PROTECTED header — an unprotected one is attacker-editable without breaking
  // the signature, so reading `alg` from there is how "verified with the algorithm of the attacker's choice" happens.
  // RFC 8152 encodes an EMPTY protected bucket as a zero-length byte string, not as an encoded empty map — so this
  // must be handled as "no algorithm stated" and rejected on its merits, not as a CBOR parse error.
  const ph = protectedBytes.length ? decode(protectedBytes) : new Map()
  if (!(ph instanceof Map) || ph.get(1) !== COSE_ALG_ES384) throw new Error('attestation: protected header must specify ES384')
  if (signature.length !== 96) throw new Error('attestation: ES384 signature must be 96 bytes')

  const doc = parseDocument(payloadBytes)

  // Chain from OUR anchor, not the document's. cabundle[0] is the document's copy of the root and is discarded.
  const anchor = root ? (root instanceof Uint8Array ? root : new Uint8Array(root)) : b64ToBytes(NITRO_ROOT_G1_B64)
  const leaf = await verifyChain([anchor, ...doc.cabundle.slice(1), doc.certificate], { now })

  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-384' },
    await importSpki(leaf),
    signature,
    sigStructure(protectedBytes, payloadBytes),
  )
  if (!ok) throw new Error('attestation: COSE signature does not verify under the leaf certificate')

  if (maxAgeMs > 0 && now - doc.timestamp > maxAgeMs) {
    throw new Error(`attestation: document is ${Math.round((now - doc.timestamp) / 1000)}s old`)
  }

  if (nonce) {
    const want = typeof nonce === 'string' ? new TextEncoder().encode(nonce) : new Uint8Array(nonce)
    if (!doc.nonce || !bytesEqual(doc.nonce, want)) throw new Error('attestation: nonce does not match the challenge')
  }

  if (expectedPCRs) {
    const wanted = Object.entries(expectedPCRs)
    if (!wanted.length) throw new Error('attestation: expectedPCRs was empty — that is not a check')
    for (const [idx, pin] of wanted) {
      // A key that isn't a register index means the caller pinned nothing at all. This already failed closed, but
      // with "PCRPCR0 is absent" — say what actually went wrong instead of letting a typo look like a hardware fault.
      const n = Number(idx)
      if (!Number.isInteger(n) || n < 0 || n > 31) {
        throw new Error(`attestation: expectedPCRs key ${JSON.stringify(idx)} is not a PCR index (0-31)`)
      }
      const accepted = acceptedSet(pin, `PCR${idx}`)
      const got = doc.pcrs[n]
      if (!got) throw new Error(`attestation: PCR${idx} is absent from the document`)
      if (!accepted.includes(got)) throw new Error(`attestation: PCR${idx} mismatch\n  expected ${accepted.join(' or ')}\n  got      ${got}`)
    }
  }

  return { ok: true, ...doc, leaf }
}

/** Same check, shaped for a UI: `{ ok, reason, doc }` rather than an exception. */
export async function tryVerifyAttestation(cose, opts) {
  try {
    return { ok: true, reason: '', doc: await verifyAttestation(cose, opts) }
  } catch (e) {
    return { ok: false, reason: (e && e.message) || 'attestation: failed', doc: null }
  }
}

/** Import the enclave's attested public key (DER SubjectPublicKeyInfo) for sealing to it. */
export async function importAttestedKey(doc, usages = []) {
  if (!doc || !doc.publicKey) throw new Error('attestation: document carries no public key')
  return crypto.subtle.importKey('spki', doc.publicKey, { name: 'ECDH', namedCurve: 'P-384' }, false, usages)
}
