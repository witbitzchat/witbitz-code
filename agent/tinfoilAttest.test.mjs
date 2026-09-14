// tinfoilAttest.test — verify a Tinfoil enclave's attestation bundle OFFLINE and pin the TLS key it proves.
// Fixture: a real ATC bundle for inference.tinfoil.sh (confidential-model-router v0.0.144), recorded 2026-09-07.
// Every check here is offline (the verifier carries the AMD root + Sigstore trust root); the VCEK is valid to 2033.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { verifyTinfoilBundle, fetchTinfoilBundle, ensureToolAttested, forgetToolAttestation } from './tinfoilAttest.mjs'

const REPO = 'tinfoilsh/confidential-model-router'
const HOST = 'inference.tinfoil.sh'
const DECL = { root: 'tinfoil', repo: REPO, host: HOST, path: '/v1/convert/file' }
const bundle = () => JSON.parse(readFileSync(new URL('./fixtures/tinfoil-router-bundle.json', import.meta.url), 'utf8'))
const FP = '90ec0a8e743b98b0' // sha256(SPKI DER) prefix of the key the fixture's report binds

test('verifyTinfoilBundle: a genuine bundle → the attested TLS key fingerprint + SEV-SNP measurement', async () => {
  const r = await verifyTinfoilBundle(bundle(), { repo: REPO, host: HOST })
  assert.equal(r.fingerprint.slice(0, 16), FP)
  assert.match(r.fingerprint, /^[0-9a-f]{64}$/)
  assert.match(r.measurement, /^[0-9a-f]{96}$/)
  assert.equal(r.repo, REPO)
  assert.equal(r.host, HOST)
})

test('verifyTinfoilBundle: the wrong repo (Sigstore identity), the wrong host, or a tampered report is REFUSED', async () => {
  await assert.rejects(verifyTinfoilBundle(bundle(), { repo: 'tinfoilsh/doc-upload', host: HOST }), /tool_unattested/)
  await assert.rejects(verifyTinfoilBundle(bundle(), { repo: REPO, host: 'router.inf6.tinfoil.sh' }), /tool_unattested/)
  const b = bundle()
  const raw = Buffer.from(b.enclaveAttestationReport.body, 'base64'); raw[raw.length - 40] ^= 0x01
  b.enclaveAttestationReport.body = raw.toString('base64')
  await assert.rejects(verifyTinfoilBundle(b, { repo: REPO, host: HOST }), /tool_unattested/)
})

test('verifyTinfoilBundle: an optional measurement pin must match the attested code measurement', async () => {
  const r = await verifyTinfoilBundle(bundle(), { repo: REPO, host: HOST })
  const ok = await verifyTinfoilBundle(bundle(), { repo: REPO, host: HOST, measurements: ['f'.repeat(96), r.measurement] })
  assert.equal(ok.measurement, r.measurement)
  await assert.rejects(verifyTinfoilBundle(bundle(), { repo: REPO, host: HOST, measurements: ['f'.repeat(96)] }), /tool_measurement_unpinned/)
})

test('fetchTinfoilBundle: POSTs {enclaveUrl, repo} to the ATC over HTTPS only; a non-2xx is tool_unattested', async () => {
  const calls = []
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return { ok: true, status: 200, json: async () => bundle() } }
  const b = await fetchTinfoilBundle(DECL, { fetchImpl })
  assert.equal(b.domain, HOST)
  assert.equal(calls[0].url, 'https://atc.tinfoil.sh/attestation')
  assert.equal(calls[0].init.method, 'POST')
  assert.deepEqual(JSON.parse(calls[0].init.body), { enclaveUrl: `https://${HOST}`, repo: REPO })
  await assert.rejects(fetchTinfoilBundle(DECL, { fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }) }), /tool_unattested/)
  await assert.rejects(fetchTinfoilBundle(DECL, { fetchImpl, atcUrl: 'http://atc.tinfoil.sh/attestation' }), /tool_unattested/)
})

test('ensureToolAttested: verifies once per (host, repo) within the TTL; forgetToolAttestation forces a re-fetch', async () => {
  let n = 0
  const fetchImpl = async () => { n++; return { ok: true, status: 200, json: async () => bundle() } }
  forgetToolAttestation(DECL)
  const a = await ensureToolAttested(DECL, { fetchImpl, now: 1000 })
  const b = await ensureToolAttested(DECL, { fetchImpl, now: 1000 + 60_000 })
  assert.equal(n, 1)
  assert.equal(a.fingerprint, b.fingerprint)
  await ensureToolAttested(DECL, { fetchImpl, now: 1000 + 601_000 }) // past the TTL → re-verify
  assert.equal(n, 2)
  forgetToolAttestation(DECL)
  await ensureToolAttested(DECL, { fetchImpl, now: 1000 + 601_000 })
  assert.equal(n, 3)
  forgetToolAttestation(DECL)
})

test('ensureToolAttested: a verification failure is NOT cached (the next call tries again) and never yields a key', async () => {
  let bad = true
  const fetchImpl = async () => ({ ok: true, status: 200, json: async () => { if (bad) { const b = bundle(); b.digest = 'a'.repeat(64); return b } return bundle() } })
  forgetToolAttestation(DECL)
  await assert.rejects(ensureToolAttested(DECL, { fetchImpl, now: 5 }), /tool_unattested/)
  bad = false
  const r = await ensureToolAttested(DECL, { fetchImpl, now: 5 })
  assert.equal(r.fingerprint.slice(0, 16), FP)
  forgetToolAttestation(DECL)
})
