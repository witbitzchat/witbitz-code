// agent/nitroToolAttest.mjs — attest Witbitz's own KEYLESS tools enclave (write_pdf, fetch_url) before a byte leaves
// for it. The `nitro:` half of what tinfoilAttest.mjs does for Tinfoil: same contract for attestedTool.mjs —
// `ensureToolAttested(decl) → { fingerprint, measurement, ... }`, 10-minute TTL, failures never cached,
// `forgetToolAttestation(decl)` on a TLS pin mismatch.
//
// Evidence: GET https://<host>/attest?nonce=<32 random bytes, hex> → { cose, cert }. `cose` is the NSM attestation
// document (base64), verified INSIDE this enclave with the client's own verifier (spaces/public/nitroVerify.js —
// pinned AWS Nitro root G1, ES384 over the COSE, chain, nonce byte-identical) and held to BOTH registers the
// declaration names: PCR0 (the image) and PCR<n> (the one tool blob the bytes go to). `cert` is the enclave's
// self-signed TLS certificate; it counts only if its SubjectPublicKeyInfo IS the document's `public_key` — so the
// pin attestedTool.mjs enforces (sha256 over that SPKI) binds the TLS session to the attested key, and `ca` lets
// Node validate the self-signed leaf without trusting anything but what the hardware just vouched for.
// The /attest request itself is NOT pinned (it cannot be: this is how the pin is learned) — and needs no pin, because
// the answer is self-authenticating: signed by AWS, bound to our fresh nonce, naming the registers we demanded.
// For the same reason it cannot be CHAIN-validated either: the enclave's leaf is self-signed (no CA on earth signs a
// key that exists only inside the hardware), so the default transport below is https.request with the chain check
// off — a plain `fetch` refuses the leaf and every nitro tool reads "attest unreachable". Nothing rides on that
// unauthenticated hop: a forged answer fails the AWS-root signature or the nonce, and the real call is pinned.
import https from 'node:https'
import { X509Certificate, createHash, randomBytes } from 'node:crypto'
import { verifyAttestation, b64ToBytes } from '../spaces/public/nitroVerify.js'

const TTL_MS = 600_000
const ATTEST_TIMEOUT_MS = 10_000 // one small GET; slower is a stall
const NONCE_BYTES = 32
const fail = (code, detail) => { const e = new Error(`${code}${detail ? `: ${detail}` : ''}`); e.code = code; return e }
const cacheKey = (d) => `${d.host}|${d.repo}`
const spkiHex = (der) => createHash('sha256').update(der).digest('hex')

/** The default /attest transport: one GET over a fresh TLS session, chain validation OFF (see the header), fetch-shaped
 *  ({ ok, status, json() }) so a test can hand in a plain `fetch` stub instead. `port`/`lookup` exist for the
 *  in-process test server only. */
export function attestGet(url, { signal, port = 443, lookup } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const req = https.request({
      host: u.hostname, port, servername: u.hostname, path: u.pathname + u.search, method: 'GET',
      headers: { accept: 'application/json' }, rejectUnauthorized: false, agent: false, signal, ...(lookup ? { lookup } : {}),
    }, (res) => {
      const chunks = []
      res.on('data', (d) => chunks.push(d))
      res.on('error', reject)
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: async () => JSON.parse(Buffer.concat(chunks).toString('utf8')) }))
    })
    req.on('error', reject)
    req.end()
  })
}

/** Fetch { cose:Buffer, cert:string(PEM) } for a fresh `nonce` (Buffer). HTTPS only. */
export async function fetchNitroEvidence(decl, nonce, { fetchImpl = attestGet, timeoutMs = ATTEST_TIMEOUT_MS, port, lookup } = {}) {
  let res
  try {
    res = await fetchImpl(`https://${decl.host}/attest?nonce=${Buffer.from(nonce).toString('hex')}`, { method: 'GET', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs), port, lookup })
  } catch (e) { throw fail('tool_unattested', `attest unreachable (${String((e && e.message) || e).slice(0, 80)})`) }
  if (!res || !res.ok) throw fail('tool_unattested', `attest http ${res && res.status}`)
  let b
  try { b = await res.json() } catch { throw fail('tool_unattested', 'attest response malformed') }
  if (!b || typeof b !== 'object' || typeof b.cose !== 'string' || typeof b.cert !== 'string') throw fail('tool_unattested', 'attest response malformed')
  return { cose: Buffer.from(b64ToBytes(b.cose)), cert: b.cert }
}

/** Verify the evidence against the declaration and the nonce. Resolves { fingerprint, measurement, ca, pcrs, repo, host, at }
 *  or throws tool_unattested (not genuine hardware / wrong nonce / wrong key) or tool_measurement_unpinned (wrong registers). */
export async function verifyNitroEvidence({ cose, cert }, decl, nonce, { now = Date.now(), verify = verifyAttestation } = {}) {
  if (!decl || decl.root !== 'nitro' || !decl.pcr0 || !decl.pcrDigest) throw fail('tool_unattested', 'declaration is not a nitro tool')
  let doc
  try {
    doc = await verify(cose, { now, nonce, expectedPCRs: { 0: decl.pcr0, [decl.pcrIndex]: decl.pcrDigest } })
  } catch (e) {
    const msg = String((e && e.message) || e)
    throw fail(/PCR\d+ mismatch/.test(msg) ? 'tool_measurement_unpinned' : 'tool_unattested', msg.slice(0, 160))
  }
  if (!doc || !doc.publicKey || !doc.publicKey.length) throw fail('tool_unattested', 'attestation carries no public key')
  let x
  try { x = new X509Certificate(cert) } catch { throw fail('tool_unattested', 'tls certificate malformed') }
  const certSpki = x.publicKey.export({ type: 'spki', format: 'der' })
  const fingerprint = spkiHex(certSpki)
  if (fingerprint !== spkiHex(Buffer.from(doc.publicKey))) throw fail('tool_unattested', 'tls certificate key is not the attested key')
  return { fingerprint, measurement: doc.pcrs[0], pcrs: doc.pcrs, ca: cert, repo: decl.repo, host: decl.host, at: now }
}

const cache = new Map() // key → { at, result }
/** Attested facts for a declared nitro tool, verified at most once per TTL. Throws (never caches) on failure. */
export async function ensureToolAttested(decl, { fetchImpl, now = Date.now(), ttlMs = TTL_MS, verify, nonce, port, lookup } = {}) {
  const k = cacheKey(decl)
  const hit = cache.get(k)
  if (hit && now - hit.at < ttlMs) return hit.result
  const n = nonce ? Buffer.from(nonce) : randomBytes(NONCE_BYTES)
  const evidence = await fetchNitroEvidence(decl, n, { fetchImpl, port, lookup })
  const result = await verifyNitroEvidence(evidence, decl, n, { now, verify })
  cache.set(k, { at: now, result })
  return result
}
/** Drop the cached verdict (a TLS pin mismatch means the enclave restarted with a new key → re-attest). */
export function forgetToolAttestation(decl) { cache.delete(cacheKey(decl)) }
