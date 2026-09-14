// Tests for the gateway-attestation gate (agent/gatewayAttest.mjs): mint a fake Google-CS-shaped JWT with our own
// RSA key + a mock JWKS, and prove the verifier's full accept/refuse matrix + the fail-closed gate. Hermetic.
import test from 'node:test'
import assert from 'node:assert/strict'
import { verifyGatewayAttestation, ensureGatewayAttested, _resetGatewayAttestCache, imageRepoMatches } from './gatewayAttest.mjs'

const RS256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
const b64u = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url')
const kp = await crypto.subtle.generateKey({ ...RS256, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify'])
const pubJwk = { ...(await crypto.subtle.exportKey('jwk', kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }

const NOW = 1_800_000_000_000
// The operator's real registry path, as served live by api.trustedrouter.com/attestation (sampled across 5 instances
// in 3 regions — all identical). Fixtures use the REAL value so the default repo pin is exercised, not bypassed.
const REPO = 'us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-multi'
function claims(over = {}) {
  const sec = Math.floor(NOW / 1000)
  return {
    iss: 'https://confidentialcomputing.googleapis.com', aud: 'quill-cloud',
    sub: 'https://www.googleapis.com/compute/v1/projects/quill-cloud-proxy/zones/x/instances/i-1',
    iat: sec - 10, nbf: sec - 10, exp: sec + 3590,
    hwmodel: 'GCP_INTEL_TDX', swname: 'CONFIDENTIAL_SPACE', secboot: true, dbgstat: 'disabled-since-boot',
    submods: { container: { image_digest: 'sha256:' + 'a'.repeat(64), image_reference: REPO + ':gcp-release-cd1539b' } },
    ...over,
  }
}
async function mint(over = {}, kid = 'k1') {
  const h = b64u({ alg: 'RS256', kid, typ: 'JWT' }), p = b64u(claims(over))
  const sig = Buffer.from(await crypto.subtle.sign(RS256, kp.privateKey, new TextEncoder().encode(h + '.' + p))).toString('base64url')
  return h + '.' + p + '.' + sig
}
const mockFetch = (token) => async (url) => ({
  ok: true, status: 200,
  text: async () => token,
  json: async () => ({ keys: [pubJwk] }),
})

test('valid attestation passes and returns the measured image', async () => {
  _resetGatewayAttestCache()
  const v = await verifyGatewayAttestation({ fetchImpl: mockFetch(await mint()), now: NOW })
  assert.equal(v.ok, true)
  assert.equal(v.imageDigest, 'sha256:' + 'a'.repeat(64))
  assert.match(v.imageReference, /enclave-multi/)
})

test('refuses: wrong aud, wrong operator project, wrong platform, debug enabled, no secboot, stale, bad signature', async () => {
  const cases = [
    [{ aud: 'evil' }, 'attest_wrong_aud'],
    [{ sub: 'https://www.googleapis.com/compute/v1/projects/evil-project/zones/x/instances/i' }, 'attest_wrong_operator'],
    [{ hwmodel: 'GCP_AMD_SEV' }, 'attest_wrong_platform'],
    [{ dbgstat: 'enabled' }, 'attest_debug_enabled'],
    [{ secboot: false }, 'attest_no_secboot'],
    [{ exp: Math.floor(NOW / 1000) - 500 }, 'attest_stale'],
  ]
  for (const [over, err] of cases) {
    _resetGatewayAttestCache()
    const v = await verifyGatewayAttestation({ fetchImpl: mockFetch(await mint(over)), now: NOW })
    assert.equal(v.ok, false, err); assert.equal(v.error, err)
  }
  _resetGatewayAttestCache()
  const t = await mint(); const tampered = t.slice(0, -6) + 'AAAAAA'
  const v = await verifyGatewayAttestation({ fetchImpl: mockFetch(tampered), now: NOW })
  assert.equal(v.ok, false); assert.equal(v.error, 'attest_bad_signature')
})

test('optional digest pinning: pinned digest passes, unpinned refuses', async () => {
  _resetGatewayAttestCache()
  const good = await verifyGatewayAttestation({ fetchImpl: mockFetch(await mint()), now: NOW, digests: ['sha256:' + 'a'.repeat(64)] })
  assert.equal(good.ok, true)
  _resetGatewayAttestCache()
  const bad = await verifyGatewayAttestation({ fetchImpl: mockFetch(await mint()), now: NOW, digests: ['sha256:' + 'b'.repeat(64)] })
  assert.equal(bad.ok, false); assert.equal(bad.error, 'attest_unpinned_image'); assert.equal(bad.imageDigest, 'sha256:' + 'a'.repeat(64))
})

test('ensureGatewayAttested: no-op without the flag; fail-closed THROW with it; caches a pass', async () => {
  _resetGatewayAttestCache(); delete process.env.LLM_REQUIRE_ATTEST
  await ensureGatewayAttested({ fetchImpl: async () => { throw new Error('must not fetch') } }) // flag off → no-op
  process.env.LLM_REQUIRE_ATTEST = 'gcp-cs'
  _resetGatewayAttestCache()
  const evil = mockFetch(await mint({ aud: 'evil' }))
  await assert.rejects(() => ensureGatewayAttested({ fetchImpl: evil, now: NOW }), /llm_gateway_unattested: attest_wrong_aud/)
  _resetGatewayAttestCache()
  let fetches = 0
  const f = async (u) => { fetches++; return mockFetch(await mint())(u) }
  await ensureGatewayAttested({ fetchImpl: f, now: NOW })
  await ensureGatewayAttested({ fetchImpl: f, now: NOW + 1000 }) // cached — no re-verify
  assert.equal(fetches, 2) // attestation + jwks, once
  delete process.env.LLM_REQUIRE_ATTEST
})

// ── IMAGE-REPO PIN (the hole this closes) ────────────────────────────────────────────────────────────────────────
// Before this, `image_reference` was READ and RETURNED but never CHECKED: any container image, from any registry,
// passed as long as it ran under Confidential Space in the operator's GCP project. The digest pin that would have
// caught it (LLM_ATTEST_DIGESTS) is unset in every deployment — verified: it appears nowhere in infra/*.tf — so the
// build-level check was optional-and-off. The repo pin is the half that can be ALWAYS ON: the operator's own
// registry path is stable across their (every-few-days) release cadence, so enforcing it adds no outage surface,
// while a build-digest pin would refuse a legitimate rollout until someone repins.
test('image-repo pin: the operator registry passes; a foreign registry REFUSES', async () => {
  _resetGatewayAttestCache()
  const ok = await verifyGatewayAttestation({ fetchImpl: mockFetch(await mint()), now: NOW })
  assert.equal(ok.ok, true, 'the real operator repo must pass')

  const evil = 'evil.example.com/attacker/gateway:latest'
  const bad = await verifyGatewayAttestation({
    fetchImpl: mockFetch(await mint({ submods: { container: { image_digest: 'sha256:' + 'a'.repeat(64), image_reference: evil } } })),
    now: NOW,
  })
  assert.equal(bad.ok, false)
  assert.equal(bad.error, 'attest_wrong_image_repo')
  assert.equal(bad.imageReference, evil, 'the refusal must NAME what it saw, so drift is diagnosable')
})

test('image-repo pin: accepts the repo@sha256 reference form, and a pinned SET (rename/rollover)', async () => {
  _resetGatewayAttestCache()
  const byDigest = REPO + '@sha256:' + 'b'.repeat(64)
  const v = await verifyGatewayAttestation({
    fetchImpl: mockFetch(await mint({ submods: { container: { image_digest: 'sha256:' + 'b'.repeat(64), image_reference: byDigest } } })),
    now: NOW,
  })
  assert.equal(v.ok, true, 'repo@digest is a valid OCI reference form and must not be refused')

  // A SET, exactly like the PCR pins: {outgoing, incoming} carries a rename without an outage window.
  const renamed = 'us-central1-docker.pkg.dev/quill-cloud-proxy/quill/enclave-next'
  const set = await verifyGatewayAttestation({
    fetchImpl: mockFetch(await mint({ submods: { container: { image_digest: 'sha256:' + 'c'.repeat(64), image_reference: renamed + ':r9' } } })),
    now: NOW, imageRepo: [REPO, renamed],
  })
  assert.equal(set.ok, true)
})

test('image-repo pin: a prefix that is not a REPO BOUNDARY must not pass', async () => {
  _resetGatewayAttestCache()
  // `…/enclave-multi-evil` starts with the pinned repo string but is a DIFFERENT repository. A naive startsWith()
  // would accept it; the boundary (`:` tag or `@` digest) is what makes the check mean "this repo", not "this prefix".
  const sneaky = REPO + '-evil:latest'
  const v = await verifyGatewayAttestation({
    fetchImpl: mockFetch(await mint({ submods: { container: { image_digest: 'sha256:' + 'd'.repeat(64), image_reference: sneaky } } })),
    now: NOW,
  })
  assert.equal(v.ok, false)
  assert.equal(v.error, 'attest_wrong_image_repo')
})

test('image-repo pin: explicitly disabled (imageRepo:null) still verifies everything else', async () => {
  _resetGatewayAttestCache()
  const v = await verifyGatewayAttestation({
    fetchImpl: mockFetch(await mint({ submods: { container: { image_digest: 'sha256:' + 'e'.repeat(64), image_reference: 'anything/at/all:x' } } })),
    now: NOW, imageRepo: null,
  })
  assert.equal(v.ok, true, 'an operator running their own gateway build can opt out of OUR repo pin')
  const stillGated = await verifyGatewayAttestation({ fetchImpl: mockFetch(await mint({ secboot: false })), now: NOW, imageRepo: null })
  assert.equal(stillGated.error, 'attest_no_secboot', 'opting out of the repo pin must not loosen the platform gates')
})

test('image-repo pin: a MISSING image_reference fails closed when a repo is pinned', async () => {
  _resetGatewayAttestCache()
  // Confidential Space always populates this, so absence means something is wrong with the evidence — never a pass.
  const v = await verifyGatewayAttestation({
    fetchImpl: mockFetch(await mint({ submods: { container: { image_digest: 'sha256:' + 'f'.repeat(64) } } })),
    now: NOW,
  })
  assert.equal(v.ok, false)
  assert.equal(v.error, 'attest_wrong_image_repo')
})

test('imageRepoMatches: pin shapes — string, list, and the three "unset" spellings', () => {
  const REF = REPO + ':gcp-release-cd1539b'
  assert.equal(imageRepoMatches(REF, REPO), true, 'bare string pin')
  assert.equal(imageRepoMatches(REF, [REPO]), true, 'single-element list')
  assert.equal(imageRepoMatches(REF, ['other/repo', REPO]), true, 'match anywhere in the set')
  assert.equal(imageRepoMatches(REF, 'other/repo'), false)
  // Unset spellings all mean "this check is not the one gating" — never "allow nothing", which would take the
  // model route down for any deployment that cleared the pin.
  for (const unset of [null, undefined, '', []]) assert.equal(imageRepoMatches(REF, unset), true, `unset: ${JSON.stringify(unset)}`)
  // …and an unset pin must not rescue an empty reference into a match against a REAL pin.
  assert.equal(imageRepoMatches('', REPO), false)
})
