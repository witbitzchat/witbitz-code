// agent/gatewayAttest.mjs — verify the LLM GATEWAY's confidential-computing attestation BEFORE sending plaintext.
//
// The attested-inference route (docs: witbitz-confidential-inference-buy-vs-build) concatenates our runtime to
// TrustedRouter's TEE gateway: their GET /attestation returns a LIVE Google Confidential Space JWT (Intel TDX,
// secure-boot, debug-off, ~1h validity, TLS-cert-bound nonce, image digest ↔ their signed release record). This
// module verifies that evidence and GATES the model call on it, fail-closed: no valid attestation ⇒ the turn is
// REFUSED, never silently routed to an unattested path. Because the enclave runs this same agent payload, the
// Nitro tier inherits the gate inside its MEASURED image — verifying our PCR0 transitively covers this policy
// ("buy the runtime, KEEP the verification").
//
// PINNING MODEL (honest label) — THREE layers, deliberately at different strengths, because they fail differently:
//   1. IDENTITY (always on) — Google-signed TDX attestation for the operator's project/audience, secboot on, debug
//      off. Stops anyone else's enclave standing in.
//   2. REPOSITORY (always on, DEFAULTS.imageRepo) — the launched `image_reference` must name the operator's own
//      registry path. Until 2026-09 this field was read and RETURNED but never CHECKED, so layer 1 was the whole
//      gate: any container image, from any registry, passed as long as it ran in their project. The repo is stable
//      across their release cadence, so enforcing it costs no availability — which is exactly why it can be the
//      always-on half that layer 3 cannot be.
//   3. BUILD (opt-in, LLM_ATTEST_DIGESTS) — the exact image digest, comma-separated sha256:… set. OFF by default
//      and in every deployment today: their releases roll every few days, and a fail-closed single-hex pin refuses a
//      legitimate rollout at whatever hour it ships. `tools/check-gateway-pin.mjs` samples the LIVE fleet with THIS
//      verifier and names the current digest set, which is what makes turning layer 3 on survivable.
// The served digest is always RETURNED + logged, and a CHANGE logs a loud one-line DRIFT warning, so a swapped build
// is observable even with layer 3 off. What none of this covers: layer 3 bounds WHICH build, never what that build
// does — for the model hop behind the gateway we rely on their attested code verifying it (see the /trust page).
//
// Zero deps: RS256 via Web Crypto, same discipline as spaceOidc.mjs.

const DEFAULTS = {
  attestUrl: 'https://api.trustedrouter.com/attestation',
  iss: 'https://confidentialcomputing.googleapis.com',
  jwksUrl: 'https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com',
  aud: 'quill-cloud', // TrustedRouter's attestation audience (their gateway codebase is "quill")
  subProject: 'quill-cloud-proxy', // the GCE project in the attestation subject — the operator identity
  hwmodel: 'GCP_INTEL_TDX',
  swname: 'CONFIDENTIAL_SPACE',
  // The operator's own registry path. Confidential Space puts the LAUNCHED image reference in the Google-signed
  // token, so this is attested input, not a claim the gateway makes about itself. Pinning it closes the gap that
  // `image_digest` alone could not afford to: the digest rolls every few days (pinning a hex fail-closed would
  // refuse a legitimate rollout until someone repinned, at whatever hour it shipped), but the REPOSITORY is stable,
  // so this check can be ALWAYS ON at zero availability cost. A list is accepted for the same reason the PCR pins
  // take a set — a rename is {outgoing, incoming}, carried without an outage window. null/'' disables it, for an
  // operator running their own gateway build; that opt-out loosens NOTHING else.
  imageRepo: 'us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi',
}

/** Does an OCI image reference name one of the pinned repositories? Boundary-aware ON PURPOSE: a bare startsWith()
 *  would accept `…/enclave-multi-evil:latest`, a DIFFERENT repository that merely shares a prefix. A reference is
 *  `<repo>:<tag>` or `<repo>@<digest>`, so the pinned repo must be followed by `:` or `@` — or be the whole string. */
export function imageRepoMatches(reference, pins) {
  const list = (Array.isArray(pins) ? pins : [pins]).map((s) => String(s || '').trim()).filter(Boolean)
  if (!list.length) return true // no pin configured ⇒ this check is not the one gating
  const ref = String(reference || '')
  return list.some((repo) => ref === repo || ref.startsWith(repo + ':') || ref.startsWith(repo + '@'))
}
const RS256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
const dec = new TextDecoder()
const fromB64u = (s) => Uint8Array.from(Buffer.from(String(s), 'base64url'))

let _jwks = null // { at, keys: Map(kid→CryptoKey) } — Google rotates rarely; 1h cache
async function jwksKey(kid, jwksUrl, fetchImpl, now) {
  if (!_jwks || now - _jwks.at > 3600_000 || !_jwks.keys.has(kid)) {
    const r = await fetchImpl(jwksUrl)
    if (!r || !r.ok) throw new Error('attest_jwks_fetch_failed')
    const body = await r.json()
    const keys = new Map()
    for (const k of body.keys || []) {
      if (!k || !k.kid || k.kty !== 'RSA') continue
      try { keys.set(k.kid, await crypto.subtle.importKey('jwk', { kty: k.kty, n: k.n, e: k.e }, RS256, false, ['verify'])) } catch { /* skip unusable key */ }
    }
    _jwks = { at: now, keys }
  }
  return _jwks.keys.get(kid) || null
}

/** Verify ONE Google Confidential Space JWT against our gateway policy (identity pin + optional build pin).
 *  Shared by the session-level /attestation gate and the per-turn inference-receipt check (whose `att` header is
 *  the same kind of token). Returns { ok:true, claims, imageDigest, imageReference, sub, exp } or { ok:false, error }
 *  — NEVER throws. `digests` (cfg) / LLM_ATTEST_DIGESTS optionally pin the measured image. */
export async function verifyConfidentialSpaceJwt(token, { fetchImpl = fetch, now = Date.now(), ...cfg } = {}) {
  const c = { ...DEFAULTS, ...cfg }
  try {
    const [h64, p64, s64] = String(token || '').trim().split('.')
    if (!h64 || !p64 || !s64) return { ok: false, error: 'attest_not_jwt' }
    const header = JSON.parse(dec.decode(fromB64u(h64)))
    if (header.alg !== 'RS256' || !header.kid) return { ok: false, error: 'attest_bad_header' }
    const key = await jwksKey(header.kid, c.jwksUrl, fetchImpl, now)
    if (!key) return { ok: false, error: 'attest_unknown_kid' }
    const okSig = await crypto.subtle.verify(RS256, key, fromB64u(s64), new TextEncoder().encode(h64 + '.' + p64))
    if (!okSig) return { ok: false, error: 'attest_bad_signature' }
    const p = JSON.parse(dec.decode(fromB64u(p64)))
    const sec = Math.floor(now / 1000)
    if (!(p.iat <= sec + 60 && p.exp >= sec - 60)) return { ok: false, error: 'attest_stale' }
    if (p.iss !== c.iss) return { ok: false, error: 'attest_wrong_iss' }
    if (p.aud !== c.aud) return { ok: false, error: 'attest_wrong_aud' }
    if (!String(p.sub || '').includes('/projects/' + c.subProject + '/')) return { ok: false, error: 'attest_wrong_operator' }
    if (p.hwmodel !== c.hwmodel || p.swname !== c.swname) return { ok: false, error: 'attest_wrong_platform' }
    if (p.secboot !== true) return { ok: false, error: 'attest_no_secboot' }
    if (p.dbgstat !== 'disabled-since-boot') return { ok: false, error: 'attest_debug_enabled' }
    const cont = (p.submods && p.submods.container) || {}
    const digest = String(cont.image_digest || '')
    if (!/^sha256:[0-9a-f]{64}$/.test(digest)) return { ok: false, error: 'attest_no_image_digest' }
    const reference = String(cont.image_reference || '')
    // REPO PIN (always on, see DEFAULTS.imageRepo). Until this existed, `image_reference` was read and returned but
    // never CHECKED — any image from any registry passed the gate. The refusal NAMES the reference it saw, because a
    // repo change is nearly always a legitimate operator move and the next step is a human deciding to add it.
    // `c.imageRepo` always resolves — DEFAULTS supplies it, a caller may override it, and null/'' opts out.
    // inferenceReceipt.mjs passes neither, so the PER-TURN receipt attestation inherits this pin as well as the
    // session-level gate: both doors, one check.
    if (!imageRepoMatches(reference, c.imageRepo)) return { ok: false, error: 'attest_wrong_image_repo', imageDigest: digest, imageReference: reference }
    // Optional build-level pinning (LLM_ATTEST_DIGESTS / cfg.digests): the measured image digest must be one we accept.
    const pins = Array.isArray(c.digests) ? c.digests : String(process.env.LLM_ATTEST_DIGESTS || '').split(',').map((s) => s.trim()).filter(Boolean)
    if (pins.length && !pins.includes(digest)) return { ok: false, error: 'attest_unpinned_image', imageDigest: digest, imageReference: reference }
    return { ok: true, claims: p, imageDigest: digest, imageReference: reference, sub: String(p.sub || ''), exp: p.exp }
  } catch (e) { return { ok: false, error: 'attest_' + String((e && e.message) || e).slice(0, 80) } }
}

/** Fetch + verify the gateway's live attestation. Returns { ok:true, imageDigest, imageReference, sub, exp }
 *  or { ok:false, error } — NEVER throws (callers gate on .ok, fail-closed). */
export async function verifyGatewayAttestation({ fetchImpl = fetch, now = Date.now(), ...cfg } = {}) {
  const c = { ...DEFAULTS, ...cfg }
  let token
  try {
    const r = await fetchImpl(c.attestUrl)
    if (!r || !r.ok) return { ok: false, error: 'attest_fetch_' + (r && r.status) }
    token = await r.text()
  } catch (e) { return { ok: false, error: 'attest_' + String((e && e.message) || e).slice(0, 80) } }
  return verifyConfidentialSpaceJwt(token, { fetchImpl, now, ...cfg })
}

// The turn-path gate: cached verification (the JWT is ~1h; re-verify every 10 min), FAIL-CLOSED. Enabled by
// LLM_REQUIRE_ATTEST=gcp-cs on the deployment that routes to the attested gateway; absent ⇒ no-op (every existing
// deployment untouched). On failure the model call throws — the turn errors rather than sending plaintext onward.
let _gate = null // { at, ok, error, imageDigest }
let _lastDigest = null // last GOOD digest seen — drift is diffed against this, not against a pin
export async function ensureGatewayAttested({ fetchImpl = fetch, now = Date.now(), ttlMs = 600_000 } = {}) {
  if (process.env.LLM_REQUIRE_ATTEST !== 'gcp-cs') return
  if (_gate && now - _gate.at < ttlMs && _gate.ok) return
  const v = await verifyGatewayAttestation({ fetchImpl, now })
  _gate = { at: now, ok: v.ok, error: v.error, imageDigest: v.imageDigest }
  if (v.ok) {
    // DRIFT is the only warning you get before a silently-swapped gateway build. The repo pin bounds WHO may ship it;
    // nothing bounds WHICH build unless LLM_ATTEST_DIGESTS is set, so the digest change must be loud and greppable
    // rather than buried in the steady-state ok line. One line per change, not per turn.
    try {
      if (_lastDigest && _lastDigest !== v.imageDigest) console.warn('gateway-attest DRIFT: image changed', _lastDigest, '->', v.imageDigest, v.imageReference)
      _lastDigest = v.imageDigest
      console.log('gateway-attest ok', v.imageReference, v.imageDigest.slice(0, 19))
    } catch { /* */ }
    return
  }
  try { console.error('gateway-attest REFUSED:', v.error) } catch { /* */ }
  throw new Error('llm_gateway_unattested: ' + v.error)
}
export function _resetGatewayAttestCache() { _jwks = null; _gate = null; _lastDigest = null } // tests
/** The image digest of the last GOOD session-level gateway attestation (or null) — for receipt drift logging. */
export function lastAttestedGatewayDigest() { return (_gate && _gate.ok && _gate.imageDigest) || null }
