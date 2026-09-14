// Tests for the per-turn inference-receipt check (agent/inferenceReceipt.mjs). Two layers:
//   1. REAL vectors — a stream captured from api.trustedrouter.com (fixtures/inference-receipt/) with the exact request
//      bytes, the nonce we sent, and Google's JWKS as served that minute. Every signature in the fixture is genuine;
//      `now` is pinned to the receipt's iat so the check is hermetic and deterministic.
//   2. MINTED vectors — our own Ed25519 receipt key + our own RSA "Google" key, to walk the refuse matrix (each check
//      must fail closed on exactly the field it guards).
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash, generateKeyPairSync, sign as edSign } from 'node:crypto'
import { newSseCapture, feedSsePayload, verifyInferenceReceipt, newReceiptNonce, receiptRequired, DEFAULT_POLICIES } from './inferenceReceipt.mjs'
import { _resetGatewayAttestCache } from './gatewayAttest.mjs'

const FIX = new URL('./fixtures/inference-receipt/', import.meta.url)
const stream = readFileSync(new URL('stream.sse', FIX))
const request = readFileSync(new URL('request.json', FIX))
const meta = JSON.parse(readFileSync(new URL('meta.json', FIX), 'utf8'))
const jwksFetch = async () => ({ ok: true, status: 200, json: async () => meta.googleJwks, text: async () => JSON.stringify(meta.googleJwks) })

/** Feed a raw SSE body through the capture exactly the way the stream reader does (frame by frame, `data:` lines). */
function captureOf(bytes) {
  const cap = newSseCapture()
  for (const frame of bytes.toString('utf8').split('\n\n')) {
    const line = frame.split('\n').find((l) => l.startsWith('data:'))
    if (line) feedSsePayload(cap, line.slice(5).trim())
  }
  return cap
}

test('real TrustedRouter receipt verifies end to end (signature, nonce, both hashes, tee-verified, attested key)', async () => {
  _resetGatewayAttestCache()
  const cap = captureOf(stream)
  assert.ok(cap.receipt, 'receipt chunk captured')
  assert.equal(cap.datas.length, meta.expect.events)
  const v = await verifyInferenceReceipt({ capture: cap, requestBody: request, nonce: meta.nonce, now: meta.nowMs, fetchImpl: jwksFetch })
  assert.equal(v.ok, true, v.error)
  assert.equal(v.kid, meta.expect.kid)
  assert.equal(v.claims.jti, meta.expect.jti)
  assert.equal(v.claims.upstream.policy, meta.expect.policy)
  assert.equal(v.imageDigest, meta.expect.imageDigest)
})

test('real receipt: any change to what we sent or received is refused', async () => {
  _resetGatewayAttestCache()
  const ok = { capture: captureOf(stream), requestBody: request, nonce: meta.nonce, now: meta.nowMs, fetchImpl: jwksFetch }
  assert.equal((await verifyInferenceReceipt({ ...ok, requestBody: Buffer.concat([request, Buffer.from(' ')]) })).error, 'receipt_req_hash')
  assert.equal((await verifyInferenceReceipt({ ...ok, nonce: 'someone-elses-nonce' })).error, 'receipt_nonce_mismatch')
  const tampered = captureOf(stream); tampered.datas[1] = Buffer.from(tampered.datas[1].toString().replace('"OK"', '"NO"'))
  assert.equal((await verifyInferenceReceipt({ ...ok, capture: tampered })).error, 'receipt_resp_hash')
  const dropped = captureOf(stream); dropped.datas.pop()
  assert.equal((await verifyInferenceReceipt({ ...ok, capture: dropped })).error, 'receipt_resp_hash')
  const trailing = captureOf(stream); feedSsePayload(trailing, '{"id":"x","choices":[{"delta":{"content":"late"}}]}')
  assert.equal((await verifyInferenceReceipt({ ...ok, capture: trailing })).error, 'receipt_not_last')
  assert.equal((await verifyInferenceReceipt({ ...ok, now: meta.nowMs + 3600_000 })).error, 'receipt_stale')
  assert.equal((await verifyInferenceReceipt({ ...ok, capture: newSseCapture() })).error, 'receipt_missing')
})

// ── minted vectors: our own keys, so each guarded field can be broken on purpose ─────────────────────────────────
const b64u = (o) => Buffer.from(typeof o === 'string' || Buffer.isBuffer(o) ? o : JSON.stringify(o)).toString('base64url')
const RS256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
const rsa = await crypto.subtle.generateKey({ ...RS256, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify'])
const rsaJwk = { ...(await crypto.subtle.exportKey('jwk', rsa.publicKey)), kid: 'g1', alg: 'RS256', use: 'sig' }
const ed = generateKeyPairSync('ed25519')
const edX = ed.publicKey.export({ format: 'jwk' }).x
const kidOf = (x) => createHash('sha256').update(Buffer.from(x, 'base64url')).digest('base64url')
const commitOf = (x) => createHash('sha256').update(Buffer.concat([Buffer.from('inference-receipt-key-v1'), Buffer.from([0]), Buffer.from(x, 'base64url')])).digest('hex')
const NOW = 1_800_000_000_000
const SEC = Math.floor(NOW / 1000)
const DIGEST = 'sha256:' + 'b'.repeat(64)
const sha = (b) => createHash('sha256').update(b).digest('base64url')

async function mintAtt(over = {}, commit = commitOf(edX)) {
  const claims = {
    iss: 'https://confidentialcomputing.googleapis.com', aud: 'quill-cloud',
    sub: 'https://www.googleapis.com/compute/v1/projects/quill-cloud-proxy/zones/z/instances/i',
    iat: SEC - 600, nbf: SEC - 600, exp: SEC + 3000, eat_nonce: ['0'.repeat(64), commit],
    hwmodel: 'GCP_INTEL_TDX', swname: 'CONFIDENTIAL_SPACE', secboot: true, dbgstat: 'disabled-since-boot',
    // The REAL operator registry path (as served live), so the always-on repo pin in gatewayAttest is exercised by
    // these fixtures rather than bypassed by a placeholder that no deployment would ever see.
    submods: { container: { image_digest: DIGEST, image_reference: 'us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi:gcp-release-cd1539b' } }, ...over,
  }
  const h = b64u({ alg: 'RS256', kid: 'g1', typ: 'JWT' }), p = b64u(claims)
  const s = Buffer.from(await crypto.subtle.sign(RS256, rsa.privateKey, Buffer.from(h + '.' + p))).toString('base64url')
  return h + '.' + p + '.' + s
}
const REQ = Buffer.from('{"model":"m","messages":[],"stream":true}')
const DATAS = ['{"id":"chatcmpl-1","choices":[{"delta":{"content":"hi"}}]}', '{"id":"chatcmpl-1","choices":[{"delta":{},"finish_reason":"stop"}]}']
const sseHash = (datas) => sha(Buffer.concat(datas.map((d) => Buffer.concat([Buffer.from(d), Buffer.from('\n')]))))
async function mintReceipt({ claims: over = {}, header: hover = {}, att, datas = DATAS, key = ed.privateKey, x = edX } = {}) {
  const claims = {
    rv: 1, iss: 'https://api.trustedrouter.com', iat: SEC, jti: 'chatcmpl-1', nonce: 'n0nce', route: 'chat.completions',
    req: { alg: 'sha256', hash: sha(REQ), of: 'body' }, resp: { alg: 'sha256', hash: sseHash(datas), of: 'sse-data-v1', events: datas.length },
    model: { requested: 'm', selected: 'm', provider: 'tinfoil', endpoint: 'm@tinfoil/prepaid' },
    upstream: { tier: 'tee-verified', policy: 'tinfoil-snp-dual-source-v1', verified_at: SEC - 100, verification_expires_at: SEC + 800 }, ...over,
  }
  const header = { alg: 'EdDSA', typ: 'inference-receipt+jws', kid: kidOf(x), jwk: { kty: 'OKP', crv: 'Ed25519', x }, att: att || await mintAtt(), att_kind: 'gcp-cs-jwt', ...hover }
  const protectedB = b64u(header), payload = b64u(claims)
  const signature = edSign(null, Buffer.from(protectedB + '.' + payload), key).toString('base64url')
  const cap = newSseCapture()
  for (const d of datas) feedSsePayload(cap, d)
  feedSsePayload(cap, JSON.stringify({ id: 'chatcmpl-1', object: 'chat.completion.chunk', choices: [], inference_receipt: { protected: protectedB, payload, signature } }))
  feedSsePayload(cap, '[DONE]')
  return cap
}
const mockFetch = async () => ({ ok: true, status: 200, json: async () => ({ keys: [rsaJwk] }) })
const run = (cap, over = {}) => verifyInferenceReceipt({ capture: cap, requestBody: REQ, nonce: 'n0nce', now: NOW, fetchImpl: mockFetch, ...over })

test('minted receipt: accepted when every field is right', async () => {
  _resetGatewayAttestCache()
  const v = await run(await mintReceipt())
  assert.equal(v.ok, true, v.error)
  assert.equal(v.imageDigest, DIGEST)
})

test('minted receipt: refuse matrix — each guarded field fails closed by name', async () => {
  const other = generateKeyPairSync('ed25519')
  const cases = [
    ['receipt_bad_signature', await mintReceipt({ key: other.privateKey })],
    ['receipt_bad_kid', await mintReceipt({ header: { kid: 'not-the-hash' } })],
    ['receipt_bad_header', await mintReceipt({ header: { alg: 'HS256' } })],
    ['receipt_wrong_iss', await mintReceipt({ claims: { iss: 'https://api.trustedrouter.com.evil' } })],
    ['receipt_wrong_route', await mintReceipt({ claims: { route: 'responses' } })],
    ['receipt_stale', await mintReceipt({ claims: { iat: SEC + 120 } })],
    ['receipt_jti_mismatch', await mintReceipt({ claims: { jti: 'chatcmpl-other' } })],
    ['receipt_upstream_unverified', await mintReceipt({ claims: { upstream: { tier: 'tls-webpki', cert_sha256: 'x' } } })],
    ['receipt_policy_unlisted', await mintReceipt({ claims: { upstream: { tier: 'tee-verified', policy: 'vendor-says-so-v0', verified_at: SEC - 1, verification_expires_at: SEC + 1 } } })],
    ['receipt_verification_window', await mintReceipt({ claims: { upstream: { tier: 'tee-verified', policy: 'tinfoil-snp-dual-source-v1', verified_at: SEC - 900, verification_expires_at: SEC - 1 } } })],
    ['receipt_att_kind', await mintReceipt({ header: { att_kind: 'aws-nitro-cose' } })],
    ['receipt_key_uncommitted', await mintReceipt({ att: await mintAtt({}, 'f'.repeat(64)) })],
    ['receipt_att_attest_wrong_operator', await mintReceipt({ att: await mintAtt({ sub: 'https://www.googleapis.com/compute/v1/projects/evil/zones/z/instances/i' }) })],
    ['receipt_att_attest_debug_enabled', await mintReceipt({ att: await mintAtt({ dbgstat: 'enabled' }) })],
  ]
  for (const [err, cap] of cases) {
    _resetGatewayAttestCache()
    const v = await run(cap)
    assert.equal(v.ok, false, err)
    assert.equal(v.error, err)
  }
})

test('minted receipt: image digest pin applies to the receipt attestation too', async () => {
  _resetGatewayAttestCache()
  assert.equal((await run(await mintReceipt(), { digests: ['sha256:' + 'c'.repeat(64)] })).error, 'receipt_att_attest_unpinned_image')
  _resetGatewayAttestCache()
  assert.equal((await run(await mintReceipt(), { digests: [DIGEST] })).ok, true)
})

test('policy allow-list is the registered set and env-overridable', () => {
  assert.deepEqual([...DEFAULT_POLICIES].sort(), ['chutes-tdx-nvidia-e2e-v1', 'near-ai-tdx-nvidia-direct-v1', 'tinfoil-snp-dual-source-v1'])
})

test('nonce + gate switch', () => {
  const n = newReceiptNonce()
  assert.match(n, /^[A-Za-z0-9_-]{32,88}$/)
  assert.notEqual(n, newReceiptNonce())
  const prev = process.env.LLM_REQUIRE_ATTEST
  delete process.env.LLM_REQUIRE_ATTEST; assert.equal(receiptRequired(), false)
  process.env.LLM_REQUIRE_ATTEST = 'gcp-cs'; assert.equal(receiptRequired(), true)
  if (prev === undefined) delete process.env.LLM_REQUIRE_ATTEST; else process.env.LLM_REQUIRE_ATTEST = prev
})
