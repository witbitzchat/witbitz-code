import { test } from 'node:test'
import assert from 'node:assert/strict'
import { modelProviderFor, isByoModel, describeProvider } from './modelConfig.mjs'

// BYO model is the prerequisite for the attested tier: attestation proves which CODE touched the plaintext, not where
// that code sent it. These tests are mostly about refusing to fall back silently — a misconfigured BYO Space that
// quietly runs on our managed key would bill us AND send the tenant's content somewhere they did not agree to.

test('a full config becomes a provider descriptor', () => {
  const p = modelProviderFor({ provider: 'openai', key: 'sk-tenant', model: 'gpt-5.5', baseUrl: 'https://acme.openai.azure.com/' })
  assert.deepEqual(p, { provider: 'openai', key: 'sk-tenant', model: 'gpt-5.5', baseUrl: 'https://acme.openai.azure.com' })
})

test('no key → null, and null means MANAGED — never a half-configured BYO', () => {
  assert.equal(modelProviderFor({ provider: 'openai', model: 'gpt-5.5' }), null)
  assert.equal(modelProviderFor({}), null)
  assert.equal(modelProviderFor(null), null)
})

test('an unusable baseUrl is REFUSED, not ignored', () => {
  // Silently dropping a typo'd endpoint would send the tenant's content to our managed account instead of theirs.
  for (const bad of ['http://acme.example', 'ftp://x.example', 'https://localhost', 'not a url', 'https://nohost']) {
    const p = modelProviderFor({ key: 'k', baseUrl: bad })
    assert.equal(p.baseUrl, undefined, `${bad} must not become a baseUrl`)
  }
})

test('an unknown provider falls back to the OpenAI-compatible shape, which is what a custom endpoint speaks', () => {
  assert.equal(modelProviderFor({ key: 'k', provider: 'wat' }).provider, 'openai')
  assert.equal(modelProviderFor({ key: 'k', provider: 'anthropic' }).provider, 'anthropic')
})

test('untrusted strings are bounded — this comes out of a sealed config an agent may have written', () => {
  const p = modelProviderFor({ key: 'k'.repeat(9999), model: 'm'.repeat(9999), baseUrl: 'https://a.example/' + 'p'.repeat(9999) })
  assert.ok(p.key.length <= 400)
  assert.ok(p.model.length <= 80)
})

test('isByoModel distinguishes the two honestly', () => {
  assert.equal(isByoModel({ key: 'k' }), true)
  assert.equal(isByoModel({ model: 'gpt-5.5' }), false, 'naming a model without a key is NOT bring-your-own')
})

test('the descriptor can be logged without leaking the credential', () => {
  const p = modelProviderFor({ key: 'sk-secret-value', provider: 'openai', model: 'gpt-5.5', baseUrl: 'https://acme.example' })
  const s = describeProvider(p)
  assert.equal(s.includes('sk-secret-value'), false, 'a key must never reach CloudWatch')
  assert.match(s, /openai:gpt-5\.5 @custom/)
  assert.equal(describeProvider(null), 'managed')
})
