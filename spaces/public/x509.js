// spaces/public/x509.js — just enough DER/X.509 to verify an ECDSA certificate chain in a browser.
//
// ★ WHY THIS FILE EXISTS AT ALL. WebCrypto can verify a *signature*, but it cannot verify a *certificate chain* —
// there is no browser API for "is this cert signed by that one, and is it in date". So a page that wants to check an
// AWS Nitro attestation document has to walk the chain itself. That is the single biggest reason browser-side
// attestation verification gets waved at and never shipped, and it is why this was built before the enclave.
//
// SCOPE, deliberately narrow: ECDSA (P-256/P-384) certificates, which is all the Nitro PKI issues. No RSA, no name
// constraints, no CRL/OCSP, no policy processing, no wildcard/SAN matching (there is no hostname here to match).
// Issuer/subject are compared as raw DER bytes — stricter than RFC 5280 name matching, and the strictness is the point.

const TAG = { INT: 0x02, BITSTRING: 0x03, OID: 0x06, SEQ: 0x30, UTCTIME: 0x17, GENTIME: 0x18 }

// ecdsa-with-SHA256 / SHA384 / SHA512
const SIG_OIDS = new Map([
  ['1.2.840.10045.4.3.2', { hash: 'SHA-256' }],
  ['1.2.840.10045.4.3.3', { hash: 'SHA-384' }],
  ['1.2.840.10045.4.3.4', { hash: 'SHA-512' }],
])
// The curve OID lives in the SPKI; we read it so the caller can import the key with the right namedCurve.
const CURVE_OIDS = new Map([
  ['1.2.840.10045.3.1.7', { curve: 'P-256', size: 32 }],
  ['1.3.132.0.34', { curve: 'P-384', size: 48 }],
  ['1.3.132.0.35', { curve: 'P-521', size: 66 }],
])

/** Read one DER TLV at `off`. → { tag, start, contentStart, contentEnd } where [start, contentEnd) is the full element. */
function readTLV(b, off) {
  if (off + 2 > b.length) throw new Error('der: truncated tag')
  const tag = b[off]
  if ((tag & 0x1f) === 0x1f) throw new Error('der: multi-byte tags not supported')
  let p = off + 1
  let len = b[p++]
  if (len & 0x80) {
    const n = len & 0x7f
    if (n === 0) throw new Error('der: indefinite length is not valid DER')
    if (n > 4) throw new Error('der: length too large')
    if (p + n > b.length) throw new Error('der: truncated length')
    len = 0
    for (let i = 0; i < n; i++) len = len * 256 + b[p++]
  }
  const contentEnd = p + len
  if (contentEnd > b.length) throw new Error('der: truncated content')
  return { tag, start: off, contentStart: p, contentEnd }
}

function expect(b, off, tag, what) {
  const t = readTLV(b, off)
  if (t.tag !== tag) throw new Error(`der: expected ${what} (tag 0x${tag.toString(16)}), got 0x${t.tag.toString(16)}`)
  return t
}

/** Walk the direct children of a constructed element. */
function children(b, t) {
  const out = []
  let p = t.contentStart
  while (p < t.contentEnd) { const c = readTLV(b, p); out.push(c); p = c.contentEnd }
  return out
}

function oidString(b, t) {
  const c = b.subarray(t.contentStart, t.contentEnd)
  if (!c.length) throw new Error('der: empty OID')
  const parts = [Math.floor(c[0] / 40), c[0] % 40]
  let v = 0
  for (let i = 1; i < c.length; i++) {
    // Each arc is base-128, high bit = "more bytes follow".
    v = v * 128 + (c[i] & 0x7f)
    if (!(c[i] & 0x80)) { parts.push(v); v = 0 }
  }
  return parts.join('.')
}

/** DER times: UTCTime is 2-digit-year (the 2050 pivot per RFC 5280), GeneralizedTime is 4. */
function parseTime(b, t) {
  const s = String.fromCharCode(...b.subarray(t.contentStart, t.contentEnd))
  let m
  if (t.tag === TAG.UTCTIME) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    if (!m) throw new Error('der: bad UTCTime')
    const yy = Number(m[1])
    return Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]))
  }
  if (t.tag === TAG.GENTIME) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    if (!m) throw new Error('der: bad GeneralizedTime')
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]))
  }
  throw new Error('der: unsupported time tag')
}

/** An ECDSA signature in X.509 is DER SEQUENCE{INTEGER r, INTEGER s}; WebCrypto wants raw r‖s, each left-padded to
 *  the curve size. (COSE, by contrast, already carries the raw form — hence this conversion lives here only.) */
export function derSigToRaw(der, size) {
  const b = der instanceof Uint8Array ? der : new Uint8Array(der)
  const seq = expect(b, 0, TAG.SEQ, 'signature SEQUENCE')
  const [rT, sT] = children(b, seq)
  if (!rT || !sT || rT.tag !== TAG.INT || sT.tag !== TAG.INT) throw new Error('der: bad ECDSA signature')
  const out = new Uint8Array(size * 2)
  for (const [i, t] of [[0, rT], [1, sT]]) {
    let v = b.subarray(t.contentStart, t.contentEnd)
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1) // strip the sign byte DER adds to keep INTEGERs positive
    if (v.length > size) throw new Error('der: ECDSA integer too large for curve')
    out.set(v, i * size + (size - v.length))
  }
  return out
}

/**
 * Parse an X.509 certificate.
 * → { tbs, sig, sigHash, spki, curve, size, issuer, subject, notBefore, notAfter, isCA }
 * `tbs` is the raw DER of tbsCertificate INCLUDING its header — that is precisely the byte range a CA signs, and
 * re-serialising it instead of slicing it is how verifiers acquire signature-validity bugs.
 */
export function parseCertificate(der) {
  const b = der instanceof Uint8Array ? der : new Uint8Array(der)
  const cert = expect(b, 0, TAG.SEQ, 'Certificate')
  const [tbsT, algT, sigT] = children(b, cert)
  if (!tbsT || !algT || !sigT) throw new Error('der: Certificate needs 3 fields')
  if (sigT.tag !== TAG.BITSTRING) throw new Error('der: signatureValue must be a BIT STRING')

  const sigAlgOid = oidString(b, expect(b, algT.contentStart, TAG.OID, 'signature algorithm'))
  const sigAlg = SIG_OIDS.get(sigAlgOid)
  if (!sigAlg) throw new Error(`der: unsupported signature algorithm ${sigAlgOid}`)

  // BIT STRING content begins with an "unused bits" count, which must be 0 for a signature.
  if (b[sigT.contentStart] !== 0x00) throw new Error('der: signature BIT STRING has unused bits')
  const sigDer = b.subarray(sigT.contentStart + 1, sigT.contentEnd)

  const kids = children(b, tbsT)
  const base = kids[0] && kids[0].tag === 0xa0 ? 1 : 0 // [0] EXPLICIT version — absent means v1
  const [serialT, innerAlgT, issuerT, validityT, subjectT, spkiT] = kids.slice(base, base + 6)
  if (!serialT || !innerAlgT || !issuerT || !validityT || !subjectT || !spkiT) throw new Error('der: malformed tbsCertificate')

  // RFC 5280 §4.1.1.2: the inner and outer algorithm identifiers must match. If they don't, one of them is decoration
  // and a verifier can be steered to check the wrong thing.
  const innerOid = oidString(b, expect(b, innerAlgT.contentStart, TAG.OID, 'inner signature algorithm'))
  if (innerOid !== sigAlgOid) throw new Error('der: signature algorithm mismatch between tbs and certificate')

  const [nbT, naT] = children(b, validityT)
  if (!nbT || !naT) throw new Error('der: malformed validity')

  // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const [spkiAlgT] = children(b, spkiT)
  const spkiAlgKids = children(b, spkiAlgT)
  if (spkiAlgKids.length < 2) throw new Error('der: SPKI algorithm needs a curve parameter')
  const keyOid = oidString(b, spkiAlgKids[0])
  if (keyOid !== '1.2.840.10045.2.1') throw new Error(`der: not an EC public key (${keyOid})`)
  const curveOid = oidString(b, spkiAlgKids[1])
  const curve = CURVE_OIDS.get(curveOid)
  if (!curve) throw new Error(`der: unsupported curve ${curveOid}`)

  // basicConstraints cA — read from the extensions, if present ([3] EXPLICIT).
  let isCA = false
  for (const k of kids.slice(base + 6)) {
    if (k.tag !== 0xa3) continue
    for (const ext of children(b, children(b, k)[0] || k)) {
      const extKids = children(b, ext)
      if (!extKids.length || oidString(b, extKids[0]) !== '2.5.29.19') continue
      const octet = extKids[extKids.length - 1]
      const bcSeq = readTLV(b, octet.contentStart)
      const bcKids = children(b, bcSeq)
      isCA = !!(bcKids[0] && bcKids[0].tag === 0x01 && b[bcKids[0].contentStart] !== 0x00)
    }
  }

  return {
    tbs: b.subarray(tbsT.start, tbsT.contentEnd),
    sig: derSigToRaw(sigDer, curve.size),
    sigHash: sigAlg.hash,
    spki: b.slice(spkiT.start, spkiT.contentEnd), // copy: this is handed to WebCrypto, which wants its own buffer
    curve: curve.curve,
    size: curve.size,
    issuer: b.subarray(issuerT.start, issuerT.contentEnd),
    subject: b.subarray(subjectT.start, subjectT.contentEnd),
    notBefore: parseTime(b, nbT),
    notAfter: parseTime(b, naT),
    isCA,
  }
}

export function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
  return d === 0
}

async function importSpki(cert) {
  return crypto.subtle.importKey('spki', cert.spki, { name: 'ECDSA', namedCurve: cert.curve }, false, ['verify'])
}

/**
 * Verify a certificate chain ordered ANCHOR-FIRST: chain[0] is the trust anchor and is never itself verified — trust
 * has to start somewhere, and it starts with a key the *verifier* pinned, not one the document supplied.
 * Each subsequent certificate must be signed by its predecessor, in date, and issued to it by name.
 * → the parsed leaf, so the caller can verify a payload signature under it.
 */
export async function verifyChain(chainDer, { now = Date.now() } = {}) {
  if (!Array.isArray(chainDer) || chainDer.length < 2) throw new Error('chain: need an anchor and at least one certificate')
  const certs = chainDer.map((d, i) => {
    try { return parseCertificate(d) } catch (e) { throw new Error(`chain: certificate ${i} unparseable: ${e.message}`) }
  })
  for (let i = 1; i < certs.length; i++) {
    const child = certs[i]
    const parent = certs[i - 1]
    if (!bytesEqual(child.issuer, parent.subject)) throw new Error(`chain: certificate ${i} was not issued by certificate ${i - 1}`)
    // Every cert that signs another must actually be a CA. Without this, a leaf can mint further certificates.
    if (i > 1 && !parent.isCA) throw new Error(`chain: certificate ${i - 1} signs but is not a CA`)
    if (now < child.notBefore) throw new Error(`chain: certificate ${i} is not yet valid`)
    if (now > child.notAfter) throw new Error(`chain: certificate ${i} has expired`)
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: child.sigHash }, await importSpki(parent), child.sig, child.tbs)
    if (!ok) throw new Error(`chain: certificate ${i} has a bad signature`)
  }
  return certs[certs.length - 1]
}

export { importSpki }
