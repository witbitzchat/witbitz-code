// agent/tinfoilAttest.mjs — verify a TINFOIL enclave's attestation before the turn hands it a document (P3 phase 2).
//
// The first tool to leave the Nitro enclave is read_file: a shared document's bytes go to Tinfoil's document
// enclave (AMD SEV-SNP) for text extraction instead of ~10 MB of parser code living in our measured payload. The
// contract that makes that honest is the same one the LLM route already has (gatewayAttest.mjs): verify the
// endpoint's LIVE hardware evidence and BIND the connection to it before any byte crosses, fail closed — a document
// is never handed to an endpoint that did not just prove what it runs. Concretely:
//   1. the Attestation Transparency Cache (atc.tinfoil.sh) returns a bundle for the declared host: the SEV-SNP report,
//      AMD's VCEK for that chip, the Sigstore provenance of the declared GitHub repo's latest release, and the
//      enclave's TLS certificate;
//   2. `@tinfoilsh/verifier` checks it OFFLINE (AMD root + Sigstore trust root are compiled in): the report's
//      signature chains to AMD, the measured code equals the Sigstore-signed release of `repo` (built by GitHub's
//      OIDC identity for that repo), and the report binds the TLS key the certificate carries;
//   3. the caller pins the TLS session to that key (attestedTool.mjs) — a proxy, a CDN, a re-issued cert, or a
//      different enclave behind the same name cannot read the bytes.
// What is pinned: the ROOT (AMD hardware) and the code IDENTITY (Sigstore: this repo's releases). Not a release digest
// by default — the router ships every few days and pinning a hex would couple our repin cycle to their deploys; an
// optional `measurements` list adds that for a deployment that wants it. The measurement is always returned so drift
// is observable. Honest scope: `tinfoilsh/confidential-model-router` is the enclave we attest; its measured code
// verifies the document enclave it forwards to. That is stated on /trust, not hidden.
import { Verifier } from '@tinfoilsh/verifier'

export const ATC_URL = 'https://atc.tinfoil.sh/attestation'
const TTL_MS = 600_000 // like ensureGatewayAttested: re-verify every 10 min, or sooner on a TLS pin mismatch
const ATC_TIMEOUT_MS = 10_000 // the bundle is one small POST; anything slower is a stall, not a slow answer
const HEX96 = /^[0-9a-f]{96}$/
const HEX64 = /^[0-9a-f]{64}$/

const fail = (code, detail) => { const e = new Error(`${code}${detail ? `: ${detail}` : ''}`); e.code = code; return e }
const cacheKey = (d) => `${d.host}|${d.repo}`

/** Fetch the ATC bundle for a declared tool endpoint ({ host, repo }). HTTPS only: the bundle is the trust root. */
export async function fetchTinfoilBundle(decl, { fetchImpl = fetch, atcUrl = ATC_URL } = {}) {
  if (!/^https:\/\//.test(atcUrl)) throw fail('tool_unattested', 'atc url must be https')
  let res
  try {
    // BOUNDED. This had no timeout, and `fetch` has no default one — so a stalled connection to the ATC hung the
    // whole turn with no error and no reply, which inside the enclave presents as "stuck thinking" forever.
    // Everything downstream of here is already bounded (pinnedRequest); this was the one unbounded await.
    res = await fetchImpl(atcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enclaveUrl: `https://${decl.host}`, repo: decl.repo }), signal: AbortSignal.timeout(ATC_TIMEOUT_MS) })
  } catch (e) { throw fail('tool_unattested', `atc unreachable (${String((e && e.message) || e).slice(0, 80)})`) }
  if (!res || !res.ok) throw fail('tool_unattested', `atc http ${res && res.status}`)
  const b = await res.json()
  if (!b || typeof b !== 'object' || !b.enclaveAttestationReport) throw fail('tool_unattested', 'atc bundle malformed')
  return b
}

/** Verify a bundle against the declaration. Resolves { fingerprint, measurement, repo, host, releaseTag } or throws
 *  tool_unattested (evidence does not prove `repo` on AMD hardware at `host`) / tool_measurement_unpinned. */
export async function verifyTinfoilBundle(bundle, { repo, host, measurements = [] } = {}) {
  if (!bundle || bundle.domain !== host) throw fail('tool_unattested', `bundle is for ${bundle && bundle.domain}, not ${host}`)
  const verifier = new Verifier({ configRepo: repo })
  let r
  try { r = await verifier.verifyBundle(bundle) } catch (e) { throw fail('tool_unattested', String((e && e.message) || e).slice(0, 160)) }
  const fingerprint = String((r && r.tlsPublicKeyFingerprint) || '').toLowerCase()
  const measurement = String((r && r.measurement && r.measurement.registers && r.measurement.registers[0]) || '').toLowerCase()
  if (!HEX64.test(fingerprint) || !HEX96.test(measurement)) throw fail('tool_unattested', 'verifier returned no key binding')
  const pins = (Array.isArray(measurements) ? measurements : []).map((m) => String(m).toLowerCase()).filter((m) => HEX96.test(m))
  if (pins.length && !pins.includes(measurement)) throw fail('tool_measurement_unpinned', measurement)
  const doc = typeof verifier.getVerificationDocument === 'function' ? verifier.getVerificationDocument() : null
  return { fingerprint, measurement, repo, host, releaseTag: (doc && doc.releaseTag) || null, at: Date.now() }
}

const cache = new Map() // key → { at, result }
/** Attested facts for a declared tool, verified at most once per TTL. Throws (never caches) on failure. */
export async function ensureToolAttested(decl, { fetchImpl = fetch, now = Date.now(), ttlMs = TTL_MS, measurements, atcUrl } = {}) {
  const k = cacheKey(decl)
  const hit = cache.get(k)
  if (hit && now - hit.at < ttlMs) return hit.result
  const bundle = await fetchTinfoilBundle(decl, { fetchImpl, atcUrl })
  const result = await verifyTinfoilBundle(bundle, { repo: decl.repo, host: decl.host, measurements })
  cache.set(k, { at: now, result })
  return result
}
/** Drop the cached verdict (a TLS pin mismatch means the enclave restarted with a new key → re-attest). */
export function forgetToolAttestation(decl) { cache.delete(cacheKey(decl)) }
