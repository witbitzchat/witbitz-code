import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveModel, resolveEntry, catalogForTier, pickKey, providerFromDescriptor, catalogSelection, turnProvider, isModelUnavailable, DEFAULTS } from './modelCatalog.mjs'

// The curated model catalog + resolver (docs/per-room-model-selection.md). These pin: the settled defaults (gpt-5.5
// regular / deepseek confidential), the two routes, the confidential FLOOR stamped by tier, fail-safe fallback for a
// bad/ineligible selection, param merge, and key-env fallback.

test('default regular room → gpt-5.5 on the direct OpenAI route (no floor)', () => {
  const d = resolveModel(undefined, 'regular')
  assert.equal(d.modelId, 'gpt-5.5')
  assert.equal(d.route, 'openai-direct')
  assert.equal(d.transport, 'responses')
  assert.equal(d.baseUrl, null)
  assert.deepEqual(d.keyEnvs, ['OPENAI_API_KEY'])
  assert.equal(d.requireAttest, null)
  assert.equal(d.extraBody, undefined)
})

test('default confidential room → deepseek via TR with the measured floor stamped', () => {
  const d = resolveModel(undefined, 'confidential')
  assert.equal(d.modelId, 'deepseek-v4-flash')
  assert.equal(d.route, 'trustedrouter')
  assert.equal(d.transport, 'chat')
  assert.equal(d.baseUrl, 'https://api.trustedrouter.com/v1/chat/completions')
  assert.equal(d.requireAttest, 'gcp-cs')
  assert.deepEqual(d.extraBody, { provider: { min_privacy: 'confidential' } })
  assert.equal(d.params.reasoning_effort, 'low')
})

test('regular room may choose a TR model (advanced)', () => {
  const d = resolveModel({ model: 'gemini-2.5-pro' }, 'regular')
  assert.equal(d.modelId, 'gemini-2.5-pro')
  assert.equal(d.route, 'trustedrouter')
  assert.equal(d.model, 'google/gemini-2.5-pro')
  assert.equal(d.requireAttest, null) // regular tier: no floor
})

test('FAIL-SAFE: a tier-ineligible selection falls back to the tier default', () => {
  // gpt-5.5 is regular-ONLY; asking for it on a confidential room must NOT downgrade off the floor.
  const d = resolveModel({ model: 'gpt-5.5' }, 'confidential')
  assert.equal(d.modelId, DEFAULTS.confidential, 'ineligible → confidential default, not the requested regular-only model')
  assert.equal(d.requireAttest, 'gcp-cs')
  assert.deepEqual(d.extraBody, { provider: { min_privacy: 'confidential' } })
})

test('FAIL-SAFE: an unknown id falls back to the tier default', () => {
  assert.equal(resolveModel({ model: 'no-such-model' }, 'regular').modelId, DEFAULTS.regular)
})

test('per-room params merge OVER the catalog defaults', () => {
  const d = resolveModel({ model: 'deepseek-v4-flash', params: { max_tokens: 40000 } }, 'regular')
  assert.equal(d.params.reasoning_effort, 'low', 'catalog default kept')
  assert.equal(d.params.max_tokens, 40000, 'room override applied')
})

test('catalogForTier filters by tier and flags the default', () => {
  const conf = catalogForTier('confidential')
  assert.deepEqual(conf.map((e) => e.id).sort(), ['deepseek-v4-flash', 'gemma-4-31b', 'glm-5.3', 'glm-5.3-flash', 'gpt-oss-120b', 'kimi-k3', 'llama-3.3-70b'], 'confidential picker = the TR-confidential subset (LIVE-probed 2026-09-06: receipt OK under min_privacy=confidential + gcp-cs)')
  assert.ok(!conf.some((e) => ['deepseek-v4-pro', 'qwen-3.6-plus', 'mistral-large', 'gemma-4-uncensored', 'grok-4.6'].includes(e.id)), 'models TR REFUSES at min_privacy=confidential are never offered to enclave rooms')
  assert.equal(conf.find((e) => e.id === 'deepseek-v4-flash').default, true)
  const reg = catalogForTier('regular')
  assert.ok(reg.some((e) => e.id === 'gpt-5.5' && e.default === true), 'regular default = gpt-5.5')
  assert.ok(reg.some((e) => e.id === 'gemini-2.5-pro'), 'regular menu includes TR models')
  assert.ok(!reg.some((e) => e.id === 'gpt-5.5' && e.default !== true) && !conf.some((e) => e.id === 'gpt-5.5'), 'gpt-5.5 never offered to confidential rooms')
})

test('obsolescence: a retired entry follows supersededBy to its live successor', () => {
  const cat = [
    { id: 'old', route: 'trustedrouter', model: 'x/old', tiers: ['regular'], retired: true, supersededBy: 'new' },
    { id: 'new', route: 'trustedrouter', model: 'x/new', tiers: ['regular'] },
  ]
  assert.equal(resolveEntry(cat, 'old', 'regular').id, 'new', 'a room that picked the obsolete model lands on the successor')
})

test('obsolescence: a chain of supersessions resolves to the final live entry', () => {
  const cat = [
    { id: 'a', tiers: ['regular'], route: 'trustedrouter', model: 'x/a', retired: true, supersededBy: 'b' },
    { id: 'b', tiers: ['regular'], route: 'trustedrouter', model: 'x/b', retired: true, supersededBy: 'c' },
    { id: 'c', tiers: ['regular'], route: 'trustedrouter', model: 'x/c' },
  ]
  assert.equal(resolveEntry(cat, 'a', 'regular').id, 'c')
})

test('obsolescence: retired-with-no-successor and a supersededBy CYCLE dead-end to undefined (bounded, no infinite loop)', () => {
  assert.equal(resolveEntry([{ id: 'gone', tiers: ['regular'], retired: true }], 'gone', 'regular'), undefined)
  const cyc = [
    { id: 'a', tiers: ['regular'], retired: true, supersededBy: 'b' },
    { id: 'b', tiers: ['regular'], retired: true, supersededBy: 'a' },
  ]
  assert.equal(resolveEntry(cyc, 'a', 'regular'), undefined)
})

test('real DEFAULTS are live → resolveModel never returns null for a valid tier (the caller only fails closed on a dead default)', () => {
  assert.ok(resolveModel(undefined, 'regular'))
  assert.ok(resolveModel(undefined, 'confidential'))
  // shipped CATALOG carries no retired entries yet, so both pickers are non-empty
  assert.ok(catalogForTier('regular').length > 0 && catalogForTier('confidential').length > 0)
})

test('TR (chat) models get lean reasoning defaults (fast + non-starving); openai-direct is untouched', () => {
  const g = resolveModel({ model: 'gemini-2.5-pro' }, 'regular')
  assert.equal(g.params.max_tokens, 8000, 'bounded-but-ample budget')
  assert.equal(g.params.reasoning_effort, 'low', 'minimal reasoning by default (fast + decisive)')
  assert.equal(resolveModel(undefined, 'regular').params.max_tokens, undefined, 'gpt-5.5 (openai-direct/Responses) keeps the Lambda default (2500)')
  assert.equal(resolveModel(undefined, 'regular').params.reasoning_effort, undefined, 'and no reasoning_effort on the direct route')
  assert.equal(resolveModel({ model: 'gemini-2.5-pro', params: { max_tokens: 500, reasoning_effort: 'high' } }, 'regular').params.max_tokens, 500, 'room max_tokens override wins')
  assert.equal(resolveModel({ model: 'gemini-2.5-pro', params: { reasoning_effort: 'high' } }, 'regular').params.reasoning_effort, 'high', 'room reasoning override wins')
  assert.equal(resolveModel(undefined, 'confidential').params.max_tokens, 24000, 'deepseek keeps its explicit budget')
})

test('providerFromDescriptor: regular default → Responses transport, direct key, no baseUrl override', () => {
  const ov = providerFromDescriptor(resolveModel(undefined, 'regular'), { OPENAI_API_KEY: 'sk-direct' })
  assert.equal(ov.provider, 'openai')
  assert.equal(ov.useResponses, true, 'openai-direct → Responses API')
  assert.equal(ov.baseUrl, undefined)
  assert.equal(ov.key, 'sk-direct')
  assert.equal(ov.model, 'gpt-5.5')
  assert.equal(ov.extraBody, undefined)
})

test('providerFromDescriptor: confidential → Chat transport via TR with the floor + params', () => {
  const ov = providerFromDescriptor(resolveModel(undefined, 'confidential'), { OPENAI_API_KEY: 'tr-bearer' })
  assert.equal(ov.useResponses, false, 'TR → Chat Completions')
  assert.equal(ov.baseUrl, 'https://api.trustedrouter.com/v1/chat/completions')
  assert.equal(ov.key, 'tr-bearer')
  assert.deepEqual(ov.extraBody, { provider: { min_privacy: 'confidential' } })
  assert.equal(ov.params.reasoning_effort, 'low')
})

test('catalogSelection: string id / { catalog, params } are selections; a BYO object is not', () => {
  assert.deepEqual(catalogSelection('deepseek-v4-flash'), { model: 'deepseek-v4-flash' })
  assert.deepEqual(catalogSelection({ catalog: 'gemini-2.5-pro', params: { max_tokens: 5 } }), { model: 'gemini-2.5-pro', params: { max_tokens: 5 } })
  assert.equal(catalogSelection({ provider: 'openai', key: 'sk' }), null, 'a BYO {provider,key} object is not a catalog selection')
  assert.equal(catalogSelection(null), null)
})

test('turnProvider: BYO wins; catalog only under MODEL_CATALOG; managed default (null) otherwise', () => {
  const env = { OPENAI_API_KEY: 'sk-direct', TRUSTEDROUTER_API_KEY: 'tr' }
  // BYO (tenant key present) → passthrough regardless of the flag
  assert.equal(turnProvider({ provider: 'openai', key: 'tenant', model: 'x' }, env).key, 'tenant')
  // a catalog id with the flag OFF → null (managed default; behaviour-neutral for every existing room)
  assert.equal(turnProvider('gemini-2.5-pro', env), null)
  // a catalog id with the flag ON → a resolved override on the REGULAR tier (no floor)
  const ov = turnProvider('gemini-2.5-pro', { ...env, MODEL_CATALOG: '1' })
  assert.equal(ov.model, 'google/gemini-2.5-pro')
  assert.equal(ov.baseUrl, 'https://api.trustedrouter.com/v1/chat/completions')
  assert.equal(ov.useResponses, false)
  assert.equal(ov.extraBody, undefined, 'regular tier carries no confidential floor')
  assert.equal(ov.key, 'tr', 'TR route uses the dedicated key on the regular Lambda')
  // no selection → null
  assert.equal(turnProvider(undefined, { ...env, MODEL_CATALOG: '1' }), null)
})

test('isModelUnavailable: matches model-gone errors, not generic failures', () => {
  for (const m of ['openai-compatible 404 {"error":{"code":"model_not_found"}}', 'The model `deepseek/x` does not exist', 'unknown model', 'invalid model: foo', 'model is deprecated', 'no such model here'])
    assert.equal(isModelUnavailable(new Error(m)), true, `should trip: ${m}`)
  for (const m of ['rate limited', '500 internal error', 'request timeout', 'the request was refused', 'context length exceeded'])
    assert.equal(isModelUnavailable(new Error(m)), false, `must NOT trip (no silent model swap): ${m}`)
})

test('pickKey: TR route falls back OPENAI_API_KEY when TRUSTEDROUTER_API_KEY is absent (enclave case)', () => {
  const d = resolveModel(undefined, 'confidential')
  assert.equal(pickKey(d, { OPENAI_API_KEY: 'tr-bearer' }), 'tr-bearer', 'enclave: TR bearer lives in OPENAI_API_KEY')
  assert.equal(pickKey(d, { TRUSTEDROUTER_API_KEY: 'dedicated', OPENAI_API_KEY: 'direct' }), 'dedicated', 'regular Lambda: dedicated key wins')
  assert.equal(pickKey(d, {}), '', 'no key present → empty (caller fails closed)')
})

test('turnProvider: TURN_TIER=confidential (the enclave) resolves with the FLOOR + fail-safes an ineligible pick', () => {
  const env = { OPENAI_API_KEY: 'tr-bearer', MODEL_CATALOG: '1', TURN_TIER: 'confidential' }
  // a confidential-eligible pick keeps its model AND gets the measured floor stamped
  const kimi = turnProvider('kimi-k3', env)
  assert.equal(kimi.model, 'moonshotai/kimi-k3')
  assert.equal(kimi.baseUrl, 'https://api.trustedrouter.com/v1/chat/completions', 'TR chat route')
  assert.equal(kimi.useResponses, false)
  assert.deepEqual(kimi.extraBody, { provider: { min_privacy: 'confidential' } }, 'the confidential floor is stamped')
  assert.equal(kimi.key, 'tr-bearer', 'enclave: the TR bearer lives in OPENAI_API_KEY')
  // an INELIGIBLE pick (a regular-only model) can never downgrade off the floor → falls back to the confidential default
  const bad = turnProvider('gpt-5.5', env)
  assert.equal(bad.model, 'deepseek/deepseek-v4-flash', 'a regular-only pick fail-safes to the confidential default')
  assert.deepEqual(bad.extraBody, { provider: { min_privacy: 'confidential' } }, 'still on the floor')
  // and the SAME env WITHOUT TURN_TIER (the regular Lambda) resolves regular — no floor — proving tier is by env, not config
  const reg = turnProvider('gemini-2.5-pro', { OPENAI_API_KEY: 'tr-bearer', MODEL_CATALOG: '1' })
  assert.equal(reg.extraBody, undefined, 'no TURN_TIER → regular → no floor (unchanged)')
})
