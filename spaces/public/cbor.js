// spaces/public/cbor.js — the small CBOR subset a Nitro attestation document needs.
//
// WHY NOT A LIBRARY. This runs in the browser as part of a *trust* claim: the user is verifying that the code which
// handled their plaintext was measured hardware. Every byte of that path they have to take on faith weakens the claim,
// and a general CBOR library is thousands of lines of generality we don't want auditors reading. The subset an
// attestation document actually uses is small enough to read in one sitting, so it is written out here.
//
// DELIBERATELY MISSING: bignums, half-floats, and every tag but transparent unwrapping. A document using them is
// rejected rather than guessed at — a parser that accepts more than the producer emits is a place for two
// implementations to disagree, and disagreement in a verifier means a forged document that "verifies".
//
// ★ INDEFINITE LENGTHS ARE SUPPORTED, AND THAT WAS NOT OPTIONAL. This decoder originally rejected them on exactly the
// reasoning above — and then a document captured from live Nitro hardware (2026-07-29) turned out to open with 0xbf,
// an indefinite-length map. Current NSM firmware STREAMS the attestation payload. Both public fixtures we had (2022
// and 2025) use definite-length maps, so nothing in the suite could catch it: the verifier would have rejected every
// document from current hardware. The lesson is the inverse of the one above — being stricter than the producer is
// not caution, it is a bug, and only real output shows you which you have.
//
// Re-encoding is never involved (COSE is verified over the RAW payload bytes), so accepting the streamed form
// introduces no canonicalisation ambiguity.

const MAX_LEN = 1 << 22 // 4MB — an attestation document is ~5KB; anything near this is an attack, not a document.

/** Decode one CBOR item. Maps come back as `Map` (attestation PCRs are keyed by INTEGER, so an object would lie).
 *  Throws on anything malformed or outside the supported subset. */
export function decode(bytes) {
  const b = toBytes(bytes)
  const [value, off] = readItem(b, 0)
  if (value === BREAK) throw new Error('cbor: stray break byte')
  if (off !== b.length) throw new Error(`cbor: ${b.length - off} trailing bytes`)
  return value
}

function toBytes(x) {
  if (x instanceof Uint8Array) return x
  if (x instanceof ArrayBuffer) return new Uint8Array(x)
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
  throw new Error('cbor: expected bytes')
}

function need(b, off, n) {
  if (n < 0 || off + n > b.length) throw new Error('cbor: truncated')
  return off + n
}

/** Read the initial byte + argument. → [major, value, nextOffset] */
function readHead(b, off) {
  need(b, off, 1)
  const ib = b[off]
  const major = ib >> 5
  const ai = ib & 31
  if (ai < 24) return [major, ai, off + 1]
  if (ai === 24) { need(b, off + 1, 1); return [major, b[off + 1], off + 2] }
  if (ai === 25) { need(b, off + 1, 2); return [major, (b[off + 1] << 8) | b[off + 2], off + 3] }
  if (ai === 26) {
    need(b, off + 1, 4)
    // >>> 0 because a 4-byte length with the high bit set is positive in CBOR but negative under JS's signed `<<`.
    const v = ((b[off + 1] << 24) | (b[off + 2] << 16) | (b[off + 3] << 8) | b[off + 4]) >>> 0
    return [major, v, off + 5]
  }
  if (ai === 27) {
    need(b, off + 1, 8)
    let v = 0
    for (let i = 1; i <= 8; i++) v = v * 256 + b[off + i]
    if (!Number.isSafeInteger(v)) throw new Error('cbor: 64-bit value exceeds safe integer range')
    return [major, v, off + 9]
  }
  if (ai === 31) throw new Error('cbor: indefinite length handled by the caller')
  throw new Error(`cbor: reserved additional information ${ai}`)
}

/** Returned for the 0xff "break" byte. Only the indefinite-length readers may consume it; anywhere else it is an
 *  error, which is what stops a stray break from silently truncating a structure. */
const BREAK = Symbol('cbor-break')

/** An indefinite-length string is a run of DEFINITE-length chunks of the same major type, ended by a break. */
function readChunked(b, off, major, depth) {
  const parts = []
  let total = 0
  let p = off
  for (;;) {
    need(b, p, 1)
    const head = b[p]
    if (head === 0xff) { p += 1; break }
    // RFC 8949: each chunk must be a DEFINITE-length string of the SAME major type. Checking the decoded value
    // instead of the head byte would silently accept a nested indefinite chunk, which is malformed.
    if ((head >> 5) !== major || (head & 31) === 31) {
      throw new Error('cbor: indefinite-length string contains a chunk of the wrong kind')
    }
    const [chunk, next] = readItem(b, p, depth + 1)
    p = next
    const bytes = major === 2 ? chunk : new TextEncoder().encode(chunk)
    total += bytes.length
    if (total > MAX_LEN) throw new Error('cbor: indefinite-length string too large')
    parts.push(bytes)
  }
  const out = concat(...parts)
  return [major === 2 ? out : new TextDecoder('utf-8', { fatal: true }).decode(out), p]
}

function readItem(b, off, depth = 0) {
  if (depth > 16) throw new Error('cbor: nesting too deep')
  need(b, off, 1)
  const ib = b[off]
  const major0 = ib >> 5

  if ((ib & 31) === 31) {
    if (major0 === 7) return [BREAK, off + 1]
    if (major0 === 2 || major0 === 3) return readChunked(b, off + 1, major0, depth)
    if (major0 === 4 || major0 === 5) {
      // Streamed array/map: read items until the break. Nitro's NSM emits the attestation payload this way.
      const isMap = major0 === 5
      const arr = []
      const map = new Map()
      let p = off + 1
      let n = 0
      for (;;) {
        const [k, n1] = readItem(b, p, depth + 1)
        p = n1
        if (k === BREAK) break
        if (++n > MAX_LEN) throw new Error('cbor: indefinite-length collection too large')
        if (!isMap) { arr.push(k); continue }
        const [v, n2] = readItem(b, p, depth + 1)
        p = n2
        if (v === BREAK) throw new Error('cbor: indefinite-length map ended between a key and its value')
        if (map.has(k)) throw new Error('cbor: duplicate map key')
        map.set(k, v)
      }
      return [isMap ? map : arr, p]
    }
    throw new Error(`cbor: indefinite length is not valid for major type ${major0}`)
  }

  const [major, value, p] = readHead(b, off)
  switch (major) {
    case 0: return [value, p]
    case 1: return [-1 - value, p]
    case 2: { // byte string
      if (value > MAX_LEN) throw new Error('cbor: byte string too large')
      const end = need(b, p, value)
      return [b.slice(p, end), end]
    }
    case 3: { // text string
      if (value > MAX_LEN) throw new Error('cbor: text string too large')
      const end = need(b, p, value)
      return [new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(p, end)), end]
    }
    case 4: { // array
      if (value > MAX_LEN) throw new Error('cbor: array too long')
      const out = []
      let q = p
      for (let i = 0; i < value; i++) {
        const [v, n] = readItem(b, q, depth + 1)
        if (v === BREAK) throw new Error('cbor: break inside a definite-length array')
        out.push(v); q = n
      }
      return [out, q]
    }
    case 5: { // map
      if (value > MAX_LEN) throw new Error('cbor: map too large')
      const out = new Map()
      let q = p
      for (let i = 0; i < value; i++) {
        const [k, n1] = readItem(b, q, depth + 1)
        const [v, n2] = readItem(b, n1, depth + 1)
        if (k === BREAK || v === BREAK) throw new Error('cbor: break inside a definite-length map')
        // A duplicate key lets a producer show one value to us and another to a different parser. Reject.
        if (out.has(k)) throw new Error('cbor: duplicate map key')
        out.set(k, v)
        q = n2
      }
      return [out, q]
    }
    case 6: { // tag — unwrapped transparently (COSE_Sign1 is emitted both tagged and bare in the wild)
      const [v, n] = readItem(b, p, depth + 1)
      return [v, n]
    }
    case 7:
      if (value === 20) return [false, p]
      if (value === 21) return [true, p]
      if (value === 22) return [null, p]
      if (value === 23) return [undefined, p]
      throw new Error(`cbor: unsupported simple/float value ${value}`)
    default:
      throw new Error('cbor: unreachable')
  }
}

// ---- encoding -------------------------------------------------------------------------------------------------
// Only what building a COSE Sig_structure needs: definite-length arrays, text strings, byte strings. The encoder
// exists so we can RE-CREATE the exact bytes that were signed; it is not a general serialiser.

function head(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value)
  if (value < 0x100) return Uint8Array.of((major << 5) | 24, value)
  if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff)
  if (value < 0x100000000) {
    return Uint8Array.of((major << 5) | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)
  }
  throw new Error('cbor: length too large to encode')
}

export function encodeBytes(u8) {
  const b = toBytes(u8)
  return concat(head(2, b.length), b)
}

export function encodeText(s) {
  const b = new TextEncoder().encode(String(s))
  return concat(head(3, b.length), b)
}

/** Encode a definite-length array of already-encoded items. */
export function encodeArray(items) {
  return concat(head(4, items.length), ...items)
}

export function concat(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}
