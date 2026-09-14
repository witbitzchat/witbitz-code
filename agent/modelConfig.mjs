// agent/modelConfig.mjs — BRING YOUR OWN MODEL: a Space can name the LLM deployment its turns run on.
//
// WHY THIS IS THE PREREQUISITE FOR THE ATTESTED TIER. Attestation proves which code touched the plaintext. It says
// nothing about where that code then SENT it. Without BYO, the attested tier's honest claim is "unobservable in use —
// except the plaintext we forward to OpenAI on our account", which a security reviewer finds immediately and which
// makes the premium unsellable. With it: "the code that touches your content is measured and published, and the only
// other party is the model vendor you already contract with."
//
// ★ NEVER process.env. The Space Lambda is SHARED across every tenant and `process.env` survives across invocations on
// a warm container — resolving a per-tenant key that way leaks tenant A's credential into tenant B's turn,
// intermittently and under load. The existing managed key does exactly this (ensureOpenAIKey parks it in the
// environment), which is safe only because there is one of it. A per-Space key must be threaded explicitly, used, and
// dropped — the same discipline as mk.
//
// Custody: the config rides INSIDE the mk-sealed Space config, so the credential is ciphertext at rest and is opened
// only during a turn, by a member who already holds the room key. That is strictly better than a vault we can read —
// though weaker than the room content itself, whose key we never hold at all. Say so plainly rather than blurring them.

const PROVIDERS = new Set(['openai', 'anthropic', 'grok', 'gemini'])
const clip = (v, n) => String(v == null ? '' : v).slice(0, n)

/** An https URL on a real host — an OpenAI-compatible endpoint (Azure, vLLM, a gateway). Anything else is refused
 *  rather than silently ignored: a typo'd baseUrl must not quietly send a tenant's content to our managed account. */
function safeBaseUrl(u) {
  const s = clip(u, 300).trim()
  if (!s) return null
  try {
    const url = new URL(s)
    if (url.protocol !== 'https:') return null
    if (!url.hostname.includes('.')) return null // no bare hosts / localhost
    return url.origin + url.pathname.replace(/\/+$/, '')
  } catch { return null }
}

/** Shape a Space's `model` config into the descriptor runToolLoopWithProvider expects, or null to use the managed
 *  default. Returns { provider, key, model, baseUrl } — `key` is the tenant's credential, held only for this turn. */
export function modelProviderFor(cfg) {
  if (!cfg || typeof cfg !== 'object') return null
  const provider = PROVIDERS.has(cfg.provider) ? cfg.provider : 'openai' // an OpenAI-compatible endpoint is the common case
  const key = clip(cfg.key, 400).trim()
  const baseUrl = safeBaseUrl(cfg.baseUrl)
  // A key is required. Without one there is nothing to authenticate with, and falling back to the managed key would
  // silently bill us and send their content to our account — the exact opposite of what BYO is for.
  if (!key) return null
  const model = clip(cfg.model, 80).trim()
  return { provider, key, ...(model ? { model } : {}), ...(baseUrl ? { baseUrl } : {}) }
}

/** True when this Space brings its own model. Useful for honest copy: a Space on BYO can say its content reaches only
 *  the tenant's own deployment; one on the managed key cannot. */
export const isByoModel = (cfg) => modelProviderFor(cfg) !== null

/** Redact a provider descriptor for logs/telemetry — the key must never reach CloudWatch. */
export const describeProvider = (p) => (p ? `${p.provider}${p.model ? ':' + p.model : ''}${p.baseUrl ? ' @custom' : ''}` : 'managed')
