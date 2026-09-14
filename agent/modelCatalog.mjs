// agent/modelCatalog.mjs — the curated model catalog + resolver. See docs/per-room-model-selection.md.
//
// The catalog is a PRODUCT/UX artifact (which models to offer), NOT a security allow-list: confidential-tier safety is
// enforced by the enclave's MEASURED policy (route=TrustedRouter + min_privacy=confidential + gcp-cs attest), so the
// model NAME is free per-room config. For the REGULAR Lambda editing this list is a plain deploy. ⚑ For the ENCLAVE it is
// NOT zero-PCR0 today: this module sits in spaceHandler's import closure, which build-payload.sh vendors INTO the EIF,
// so widening the confidential subset needs a rebuilt image + PCR0 repin — and the enclave's resolveModel fail-safes any
// id ITS copy doesn't know back to the confidential default, so a Lambda-only deploy would show a picker the enclave
// silently ignores. Ship both together (until the two-stage measured launch moves the catalog out of PCR0).

// A ROUTE = HOW to reach a model. `transport` picks the brain step — 'responses' (OpenAI Responses API) | 'chat'
// (OpenAI-compatible Chat Completions, used for TrustedRouter). `keyEnvs` is tried in order: the regular Lambda holds a
// dedicated TRUSTEDROUTER_API_KEY; the enclave reuses OPENAI_API_KEY (already the TR bearer there), hence the fallback.
import { modelProviderFor } from './modelConfig.mjs' // BYO model (tenant's own key) — takes precedence over the catalog

export const ROUTES = {
  'openai-direct': { provider: 'openai', transport: 'responses', baseUrl: null, keyEnvs: ['OPENAI_API_KEY'] },
  'trustedrouter': { provider: 'openai', transport: 'chat', baseUrl: 'https://api.trustedrouter.com/v1/chat/completions', keyEnvs: ['TRUSTEDROUTER_API_KEY', 'OPENAI_API_KEY'] }, // FULL url — openaiStep uses an explicit baseUrl VERBATIM (unlike openaiChatUrl, which appends /chat/completions to LLM_BASE_URL). A base-only URL 404s "route not found".
}

// `tiers` = which room tiers may offer this entry. `params` = catalog default behaviour params (merged UNDER any
// per-room override). Add entries freely — an id's `model` must match the wire model name its route expects (TR uses
// provider/model). OpenAI-direct is regular-only by construction (OpenAI sees plaintext → never confidential-eligible).
// Model ids VALIDATED against TrustedRouter's live /v1/models (2026-09-03). Keep them real — an unknown id 404s the turn
// (fail-safe only catches "model gone" errors, not a typo'd id). deepseek-v4-pro / claude-sonnet-4-6 are NOT offered by TR.
// CONFIDENTIAL eligibility is LIVE-PROBED (2026-09-06, scratchpad tr-probe: min_privacy=confidential + gcp-cs + per-call
// receipt verified) — TR's /v1/models metadata does NOT expose pool membership, so a probe is the only ground truth.
// Passing, tinfoil-snp policy (fast): deepseek-v4-flash, kimi-k3, glm-5.3(-flash), gpt-oss-120b, gemma-4-31b-it,
// llama-3.3-70b-INSTRUCT (the bare `meta-llama/llama-3.3-70b` id has no confidential route). Passing but on the SLOW
// chutes-tdx policy (10–20s TTFB, not offered): glm-5.1, kimi-k2.6, qwen3.5-397b, deepseek-v3.2. REFUSED ("no route
// candidates"): deepseek-v4-pro, kimi-k3-fast, minimax, qwen3.6-plus, mistral, nemotron-3, gemma-4-uncensored.
// `vision: false` marks a model that CANNOT take image parts on its route. Sending pixels to one is not a soft
// failure: TrustedRouter answers 502 under the confidential floor and the whole turn dies ("I couldn't complete that
// one" on a shared photo, 2026-09-09). Absent ⇒ images are passed as before (BYO + the managed default). Probed with a
// real PNG: SEES = gpt-5.1, claude-*, gemini-*, grok-4.6, gemma-4-31b/uncensored (and gpt-5.5 via Responses).
// ★Capability is per-ROUTE, not per-model: kimi-k3 reads images on Tinfoil direct but is blind through TR.
// A blind model still answers about a picture — it calls look_at_image (agent/tinfoilVision.mjs).
export const CATALOG = [
  { id: 'gpt-5.5',           label: 'GPT-5.5',           route: 'openai-direct', model: 'gpt-5.5',                     tiers: ['regular'] },
  { id: 'gpt-5.1',           label: 'GPT-5.1',           route: 'trustedrouter', model: 'openai/gpt-5.1',              tiers: ['regular'] },
  { id: 'claude-opus-5',     label: 'Claude Opus 5',     route: 'trustedrouter', model: 'anthropic/claude-opus-5',     tiers: ['regular'] },
  { id: 'claude-sonnet-4.6', label: 'Claude Sonnet 4.6', route: 'trustedrouter', model: 'anthropic/claude-sonnet-4.6', tiers: ['regular'] },
  { id: 'claude-haiku-4.5',  label: 'Claude Haiku 4.5',  route: 'trustedrouter', model: 'anthropic/claude-haiku-4.5',  tiers: ['regular'] },
  { id: 'gemini-2.5-pro',    label: 'Gemini 2.5 Pro',    route: 'trustedrouter', model: 'google/gemini-2.5-pro',       tiers: ['regular'] },
  { id: 'gemini-2.5-flash',  label: 'Gemini 2.5 Flash',  route: 'trustedrouter', model: 'google/gemini-2.5-flash',     tiers: ['regular'] },
  { id: 'deepseek-v4-pro',   label: 'DeepSeek V4 Pro',   route: 'trustedrouter', model: 'deepseek/deepseek-v4-pro',    tiers: ['regular'], vision: false, params: { reasoning_effort: 'low', max_tokens: 24000 } }, // NOT confidential on TR (refuses min_privacy=confidential)
  { id: 'deepseek-v4-flash', label: 'DeepSeek V4 Flash', route: 'trustedrouter', model: 'deepseek/deepseek-v4-flash',  tiers: ['regular', 'confidential'], vision: false, params: { reasoning_effort: 'low', max_tokens: 24000 } },
  { id: 'grok-4.6',          label: 'Grok 4.6',          route: 'trustedrouter', model: 'x-ai/grok-4.6',               tiers: ['regular'] },
  { id: 'kimi-k3',           label: 'Kimi K3',           route: 'trustedrouter', model: 'moonshotai/kimi-k3',          tiers: ['regular', 'confidential'], vision: false }, // confidential-capable on TR (verified min_privacy=confidential)
  { id: 'glm-5.3-flash',     label: 'GLM 5.3 Flash',     route: 'trustedrouter', model: 'z-ai/glm-5.3-flash',          tiers: ['regular', 'confidential'], vision: false },
  { id: 'glm-5.3',           label: 'GLM 5.3',           route: 'trustedrouter', model: 'z-ai/glm-5.3',                tiers: ['regular', 'confidential'], vision: false },
  { id: 'gpt-oss-120b',      label: 'GPT-OSS 120B',      route: 'trustedrouter', model: 'openai/gpt-oss-120b',         tiers: ['regular', 'confidential'], vision: false },
  { id: 'gemma-4-31b',       label: 'Gemma 4 31B',       route: 'trustedrouter', model: 'google/gemma-4-31b-it',       tiers: ['regular', 'confidential'] },
  { id: 'llama-3.3-70b',     label: 'Llama 3.3 70B',     route: 'trustedrouter', model: 'meta-llama/llama-3.3-70b-instruct', tiers: ['regular', 'confidential'], vision: false }, // -instruct: the id with a confidential route
  { id: 'mistral-large',     label: 'Mistral Large',     route: 'trustedrouter', model: 'mistralai/mistral-large',     tiers: ['regular'], vision: false },
  { id: 'qwen-3.6-plus',     label: 'Qwen 3.6 Plus',     route: 'trustedrouter', model: 'qwen/qwen3.6-plus',            tiers: ['regular'], vision: false },
  { id: 'gemma-4-uncensored', label: 'Gemma 4', route: 'trustedrouter', model: 'google/gemma-4-uncensored', tiers: ['regular'] },
]

export const DEFAULTS = { regular: 'gpt-5.5', confidential: 'deepseek-v4-flash' }

const tierOf = (t) => (t === 'confidential' ? 'confidential' : 'regular')

// The picker list for a tier: eligible entries with the current default flagged. Served to the client (UX only).
export function catalogForTier(tier) {
  const t = tierOf(tier)
  return CATALOG.filter((e) => e.tiers.includes(t) && !e.retired).map((e) => ({ id: e.id, label: e.label, route: e.route, params: e.params || {}, default: DEFAULTS[t] === e.id }))
}

// Resolve an id to a LIVE, tier-eligible catalog entry, following `supersededBy` when an entry is `retired` (so a room
// that picked a now-obsolete model lands on its named successor, not the generic default). Returns undefined if it
// dead-ends: no such id, retired-with-no-live-successor, tier-ineligible, or a supersededBy cycle (bounded by _hops).
// Pure (catalog passed in) → the obsolescence logic is unit-testable against crafted catalogs without touching CATALOG.
export function resolveEntry(catalog, id, tier, _hops = 0) {
  if (!id || _hops > 8) return undefined
  const e = catalog.find((x) => x.id === id)
  if (!e) return undefined
  if (e.retired) return e.supersededBy ? resolveEntry(catalog, e.supersededBy, tier, _hops + 1) : undefined
  return e.tiers.includes(tier) ? e : undefined
}

// Resolve a per-room selection into a brain backend descriptor. `selection` may be undefined/partial (→ tier default).
// ★FAIL-SAFE: an unknown / retired / tier-INELIGIBLE id falls back to the tier default (via supersededBy first), so a
// bad, stale, or hostile selection can never break a turn nor — on the confidential tier — escape the floor. The
// confidential FLOOR (min_privacy + gcp-cs) is stamped by TIER, never taken from the selection.
// ★NULL CONTRACT: returns null ONLY when even the tier default resolves to nothing (its id missing / retired-with-no-
// live-successor). The caller MUST fail closed — refuse the turn with an honest error, NEVER call a dead/unknown model,
// and NEVER downgrade a confidential room off the floor. Operational rule: keep DEFAULTS[tier] pointing at a live model.
export function resolveModel(selection, tier) {
  const t = tierOf(tier)
  const wantId = (selection && selection.model) || DEFAULTS[t]
  const entry = resolveEntry(CATALOG, wantId, t) || resolveEntry(CATALOG, DEFAULTS[t], t)
  if (!entry) return null
  const route = ROUTES[entry.route]
  const params = { ...(entry.params || {}), ...((selection && selection.params) || {}) }
  // TR (chat) route defaults for REASONING models — they spend hidden reasoning INSIDE max_tokens, and the regular
  // Lambda's default budget (OPENAI_BRAIN_MAX_OUTPUT=2500, tuned for gpt-5.5) is too tight: reasoning either starves the
  // reply to EMPTY, or — uncapped — rambles thousands of tokens PER tool-loop round and the turn STICKS (Grok 4.6 did
  // both). So default reasoning_effort=low (minimal CoT → fast + decisive, ~halves Grok's reasoning) + a bounded-but-
  // ample max_tokens. Both overridable per entry/room. gpt-5.5 stays on openai-direct/Responses (no shared-budget issue).
  if (route.transport === 'chat') {
    if (params.reasoning_effort == null) params.reasoning_effort = 'low'
    if (params.max_tokens == null) params.max_tokens = 8000
  }
  return {
    modelId: entry.id,
    route: entry.route,
    provider: route.provider,
    model: entry.model,
    transport: route.transport,
    baseUrl: route.baseUrl,
    keyEnvs: route.keyEnvs,
    // ★Carry the catalog's capability flag THROUGH. Without this line the flag exists but never reaches the brain:
    // resolveModel builds an explicit object, so a field absent here is silently dropped and the vision gate never
    // fires (shipped that way once — a blind model still received pixels and the turn still died).
    vision: entry.vision,
    requireAttest: t === 'confidential' ? 'gcp-cs' : null,
    extraBody: t === 'confidential' ? { provider: { min_privacy: 'confidential' } } : undefined,
    params,
  }
}

// Pick the first present key env for a resolved descriptor. Kept separate from resolveModel so the resolver stays PURE
// (no process.env) and testable; the caller resolves the actual secret from its OWN env at call time.
/** Is this model KNOWN to be unable to take image parts? Keyed on the WIRE model name (what actually goes on the
 *  request), because the room may have picked nothing at all — then no catalog entry is resolved and the brain runs
 *  the ENV DEFAULT (the enclave's `deepseek/deepseek-v4-flash`), which carries no flag. Unknown/BYO ⇒ false (allow),
 *  so this can only ever WITHHOLD pixels from a model we have positively measured as blind, never from a new one.
 *  ★This is the second half of the gate: keying only on the resolved descriptor missed every default-model room —
 *  which is most of them — and the turn kept dying. */
export function modelIsBlind(wireModel) {
  const m = String(wireModel || '').trim()
  if (!m) return false
  return CATALOG.some((e) => e.vision === false && (e.model === m || e.id === m))
}

export function pickKey(desc, env = process.env) {
  for (const n of (desc && desc.keyEnvs) || []) { const v = (env[n] || '').trim(); if (v) return v }
  return ''
}

// Map a resolved descriptor → the per-call `provider` override that brain.respondWithTools accepts (it threads
// baseUrl/useResponses/extraBody/params into the brain step). transport 'responses' → OpenAI Responses API; 'chat' →
// the OpenAI-compatible Chat Completions transport (TrustedRouter). Key is resolved from the CALLER's env, never parked.
export function providerFromDescriptor(desc, env = process.env) {
  if (!desc) return null
  return {
    provider: desc.provider,
    key: pickKey(desc, env),
    model: desc.model,
    baseUrl: desc.baseUrl || undefined,
    useResponses: desc.transport === 'responses',
    vision: desc.vision,
    extraBody: desc.extraBody,
    params: desc.params,
  }
}

// Interpret a room's `model` config as a CATALOG selection: a bare id string, or { catalog, params }. Returns
// { model, params } for resolveModel, or null when it isn't a catalog selection (e.g. a BYO { provider, key } object,
// which modelProviderFor handles first).
export function catalogSelection(m) {
  if (typeof m === 'string' && m.trim()) return { model: m.trim() }
  if (m && typeof m === 'object' && typeof m.catalog === 'string' && m.catalog.trim()) return { model: m.catalog.trim(), params: (m.params && typeof m.params === 'object') ? m.params : undefined }
  return null
}

// Resolve a room's `model` config → the per-call brain override. BYO (tenant's own key, sealed in config) WINS; else,
// flag-gated (MODEL_CATALOG=1) a curated-catalog selection resolves to a platform-keyed override; null → the managed default.
// ★ TIER by WHERE THE CODE RUNS, not the per-room config. The ENCLAVE (the confidential tier) sets TURN_TIER=confidential
// in its MEASURED image (turn.mjs), so every turn it runs resolves with the confidential FLOOR stamped (min_privacy +
// gcp-cs, via resolveModel) and can only land on a confidential-eligible model — resolveModel FAIL-SAFES any ineligible
// pick back to the confidential default (deepseek), so a bad/hostile `model` can never downgrade off the floor. The
// regular Lambda leaves TURN_TIER unset → 'regular' (no floor), unchanged. A confidential turn never reaches the regular
// Lambda (its mk is sealed to the enclave's key — the Lambda can't unseal it), so this env is the honest source of tier.
export function turnProvider(model, env = process.env) {
  const byo = modelProviderFor(model)
  if (byo) return byo
  if (env.MODEL_CATALOG === '1') {
    const tier = env.TURN_TIER === 'confidential' ? 'confidential' : 'regular'
    const sel = catalogSelection(model)
    if (sel) return providerFromDescriptor(resolveModel(sel, tier), env)
  }
  return null
}

// True for a provider error that means the requested MODEL is gone/unknown (retired upstream BEFORE we updated the
// catalog) — used to retry a turn once on the managed default (obsolescence belt-and-suspenders). Deliberately TARGETED:
// a generic 4xx / rate-limit / timeout / context-length error must NOT trigger a silent model swap.
export function isModelUnavailable(err) {
  const s = String((err && err.message) || err || '').toLowerCase()
  return /model_not_found|no such model|unknown model|invalid model|model[^.]{0,40}(not found|does not exist|is not available|is not supported|deprecated|decommission)/.test(s)
}
