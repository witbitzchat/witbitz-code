// agent/inferenceReceipt.mjs — verify TrustedRouter's SIGNED INFERENCE RECEIPT for every model call, fail-closed.
//
// gatewayAttest.mjs proves WHO we are talking to (a Google-attested TDX gateway running a known image). That alone
// does not prove what that gateway did with THIS request: which upstream it chose, and whether it actually
// verified that upstream's TEE before forwarding our plaintext. The gateway answers that per call with an
// `inference_receipt` — a JWS (spec: quill-cloud-proxy docs/design/signed-receipts-wire-format.md,
// `inference-receipt/1`) signed by an instance key whose commitment is baked into the gateway's Confidential Space
// attestation (`eat_nonce`), binding: the exact request bytes we sent, the exact `data:` events we received, the
// nonce we chose, and the `upstream` verdict {tier, policy, verification window}.
//
// This module REFUSES the turn unless, for this call: signature valid under the attested key ∧ nonce echoed ∧ both
// hashes match ∧ receipt is the last event ∧ upstream.tier == 'tee-verified' with an ALLOW-LISTED policy ∧ the
// verification window covers the receipt. Anything less (tls-webpki, unknown policy, missing receipt) ⇒ throw —
// the model call is treated as never having happened. Zero deps: Ed25519 via node:crypto, RS256 via gatewayAttest.
//
// Wire notes we rely on (validated against live bytes, fixtures/inference-receipt/): the receipt is only
// EMBEDDED WITH ITS ATTESTATION (`att` header) in the streaming form, and TR runs several instances behind one
// LB, so /receipt-key may describe a different signer than the one that signed a compact header receipt. Hence:
// when a receipt is required we ALWAYS stream (openaiStep/attestedLlmFetch force stream:true).
import { createHash, createPublicKey, randomBytes, verify as edVerify } from 'node:crypto'
import { verifyConfidentialSpaceJwt, lastAttestedGatewayDigest } from './gatewayAttest.mjs'

export const RECEIPT_ISS = 'https://api.trustedrouter.com' // PINNED — never taken from the receipt
export const RECEIPT_ROUTE = 'chat.completions'
/** Upstream verification policies we accept — each names a measured verifier in the gateway's audited source
 *  (enclave-go/internal/llm/): SEV-SNP dual-source (tinfoil), TDX+NVIDIA+E2E (chutes), TDX+NVIDIA direct (near-ai).
 *  A new policy name means new verifier code: it is NOT trusted until audited and added here (or LLM_RECEIPT_POLICIES). */
export const DEFAULT_POLICIES = Object.freeze(['tinfoil-snp-dual-source-v1', 'chutes-tdx-nvidia-e2e-v1', 'near-ai-tdx-nvidia-direct-v1'])
const KEY_COMMIT_PREFIX = 'inference-receipt-key-v1'
const IAT_SKEW_SEC = 60

/** Same switch as the gateway gate: the receipt is required exactly where the attested route is required. */
export function receiptRequired() { return process.env.LLM_REQUIRE_ATTEST === 'gcp-cs' }
export function allowedPolicies() {
  const env = String(process.env.LLM_RECEIPT_POLICIES || '').split(',').map((s) => s.trim()).filter(Boolean)
  return new Set(env.length ? env : DEFAULT_POLICIES)
}
/** Fresh per-call nonce (32 random bytes, base64url ⇒ 43 chars — within the spec's [A-Za-z0-9_-]{1,88}). */
export function newReceiptNonce() { return randomBytes(32).toString('base64url') }

/** Capture of what the stream reader saw, in wire order: `datas` = exact `data:` payload bytes (excluding the
 *  receipt event and [DONE]), `receipt` = parsed inference_receipt (first seen), `afterReceipt` = data events
 *  that arrived after it (spec: must be 0), `ids` = chunk ids (all must equal the receipt's jti). */
export function newSseCapture() { return { datas: [], receipt: null, receiptId: null, afterReceipt: 0, ids: new Set() } }
/** Feed one `data:` payload (string, already trimmed) — mirrors readOpenAIChatStream's framing exactly. */
export function feedSsePayload(cap, payload) {
  if (payload === '[DONE]') return
  let ev = null
  try { ev = JSON.parse(payload) } catch { /* unparseable: still hashed as a data event below */ }
  if (ev && ev.inference_receipt && !cap.receipt) {
    cap.receipt = ev.inference_receipt
    cap.receiptId = ev.id
    return
  }
  if (cap.receipt) cap.afterReceipt += 1
  cap.datas.push(Buffer.from(payload, 'utf8'))
  if (ev && ev.id) cap.ids.add(String(ev.id))
}

const b64uJson = (s) => JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8'))
const sha256 = (buf) => createHash('sha256').update(buf).digest()
const sseDataV1 = (datas) => sha256(Buffer.concat(datas.flatMap((d) => [d, Buffer.from('\n')]))).toString('base64url')
const commitHex = (xB64u) => createHash('sha256').update(Buffer.concat([Buffer.from(KEY_COMMIT_PREFIX), Buffer.from([0]), Buffer.from(xB64u, 'base64url')])).digest('hex')

/** Verify the captured receipt against what we sent/received. Returns { ok:true, claims, kid, imageDigest } or
 *  { ok:false, error } — never throws. `now` in ms; `fetchImpl`/`digests` flow to the attestation verifier. */
export async function verifyInferenceReceipt({ capture, requestBody, nonce, now = Date.now(), fetchImpl = fetch, digests, policies } = {}) {
  try {
    const r = capture && capture.receipt
    if (!r || typeof r.protected !== 'string' || typeof r.payload !== 'string' || typeof r.signature !== 'string') return { ok: false, error: 'receipt_missing' }
    const header = b64uJson(r.protected)
    const jwk = header.jwk || {}
    if (header.alg !== 'EdDSA' || header.typ !== 'inference-receipt+jws' || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return { ok: false, error: 'receipt_bad_header' }
    const xRaw = Buffer.from(jwk.x, 'base64url')
    if (xRaw.length !== 32 || header.kid !== sha256(xRaw).toString('base64url')) return { ok: false, error: 'receipt_bad_kid' }
    if (header.att_kind !== 'gcp-cs-jwt' || typeof header.att !== 'string') return { ok: false, error: 'receipt_att_kind' }
    const pub = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' })
    if (!edVerify(null, Buffer.from(r.protected + '.' + r.payload), pub, Buffer.from(r.signature, 'base64url'))) return { ok: false, error: 'receipt_bad_signature' }
    const c = b64uJson(r.payload)
    if (c.rv !== 1 || c.iss !== RECEIPT_ISS) return { ok: false, error: 'receipt_wrong_iss' }
    if (c.route !== RECEIPT_ROUTE) return { ok: false, error: 'receipt_wrong_route' }
    const sec = Math.floor(now / 1000)
    if (!(Number.isFinite(c.iat) && c.iat <= sec + IAT_SKEW_SEC && c.iat >= sec - 3600)) return { ok: false, error: 'receipt_stale' }
    if (!nonce || c.nonce !== nonce) return { ok: false, error: 'receipt_nonce_mismatch' }
    // Bind-or-refuse: the exact bytes we sent and the exact data events we received.
    const req = c.req || {}
    if (req.alg !== 'sha256' || req.of !== 'body' || req.hash !== sha256(Buffer.from(requestBody)).toString('base64url')) return { ok: false, error: 'receipt_req_hash' }
    if (capture.afterReceipt > 0) return { ok: false, error: 'receipt_not_last' }
    const resp = c.resp || {}
    if (resp.alg !== 'sha256' || resp.of !== 'sse-data-v1' || resp.events !== capture.datas.length || resp.hash !== sseDataV1(capture.datas)) return { ok: false, error: 'receipt_resp_hash' }
    if (typeof c.jti !== 'string' || !c.jti || (capture.receiptId && capture.receiptId !== c.jti) || [...capture.ids].some((id) => id !== c.jti)) return { ok: false, error: 'receipt_jti_mismatch' }
    // The verdict we actually care about: the gateway's measured code verified the model enclave for THIS call.
    const up = c.upstream || {}
    if (up.tier !== 'tee-verified') return { ok: false, error: 'receipt_upstream_unverified' }
    const allow = policies instanceof Set ? policies : allowedPolicies()
    if (!allow.has(up.policy)) return { ok: false, error: 'receipt_policy_unlisted' }
    if (!(Number.isFinite(up.verified_at) && Number.isFinite(up.verification_expires_at) && up.verified_at <= c.iat && c.iat < up.verification_expires_at)) return { ok: false, error: 'receipt_verification_window' }
    // The signing key must be the one the ATTESTED gateway committed to: hex(C) ∈ att.eat_nonce, att itself valid
    // under the same policy as the session gate (Google-signed, TDX, secboot, debug-off, operator project, pins).
    const att = await verifyConfidentialSpaceJwt(header.att, { fetchImpl, now, ...(digests ? { digests } : {}) })
    if (!att.ok) return { ok: false, error: 'receipt_att_' + att.error }
    const nonces = Array.isArray(att.claims.eat_nonce) ? att.claims.eat_nonce : [att.claims.eat_nonce]
    if (!nonces.map((n) => String(n || '').toLowerCase()).includes(commitHex(jwk.x))) return { ok: false, error: 'receipt_key_uncommitted' }
    return { ok: true, claims: c, kid: header.kid, imageDigest: att.imageDigest }
  } catch (e) { return { ok: false, error: 'receipt_' + String((e && e.message) || e).slice(0, 80) } }
}

/** Turn-path enforcement: verify or THROW (`llm_receipt_unverified: <reason>`), plus drift/verdict logging. */
export async function enforceInferenceReceipt(args) {
  const v = await verifyInferenceReceipt(args)
  if (!v.ok) {
    try { console.error('inference-receipt REFUSED:', v.error) } catch { /* */ }
    throw new Error('llm_receipt_unverified: ' + v.error)
  }
  try {
    const m = v.claims.model || {}, up = v.claims.upstream || {}
    const sessionDigest = lastAttestedGatewayDigest()
    const drift = sessionDigest && sessionDigest !== v.imageDigest ? ' (gateway image differs from session attestation ' + sessionDigest.slice(0, 19) + ')' : ''
    console.log('inference-receipt ok', m.endpoint || m.selected, up.policy, v.imageDigest.slice(0, 19) + drift)
  } catch { /* */ }
  return v
}
