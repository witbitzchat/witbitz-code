// agent/tinfoilVision.mjs — look_at_image's eyes: an image goes to Tinfoil's attested vision enclave and comes back
// as TEXT, so ANY model — including a blind one — can answer a question about a picture.
//
// WHY A TOOL. Images were handed to the room's brain NATIVELY (asyncTurn perceivedImages → image_url parts). On the
// confidential tier the default brain is deepseek-v4-flash, which is not multimodal: TrustedRouter answers 502 under
// the min_privacy floor, the turn throws, and the member sees "I couldn't complete that one" — the whole answer lost,
// not just the picture (reported 2026-09-09, a photo of a water meter). Vision as a FUNCTION tool is portable the same
// way web_search is: the model asks to look, we look, we hand back words.
//
// Trust story is read_file's, unchanged: the bytes go to an AMD SEV-SNP enclave whose measurement the turn verifies
// first (tinfoilAttest) and whose TLS key the request is pinned to (attestedTool) — never to an unattested endpoint.
// Probed 2026-09-09 on inference.tinfoil.sh: gemma4-31b described a real photo in 6s; kimi-k3 works but narrates its
// reasoning; deepseek-v4-flash answers a clean 400 "is not a multimodal model" (vs TR's opaque 502).
const DEFAULT_MODEL = 'gemma4-31b'   // Tinfoil's OWN id — NOT TrustedRouter's 'google/gemma-4-31b-it'
const DEFAULT_TIMEOUT_MS = 60_000    // must stay under the turn budget, as read_file's does
const MAX_BYTES = 12 * 1024 * 1024   // a shared photo is far below this; a guard, not a policy
const MAX_CHARS = 4000
const fail = (code, msg) => { const e = new Error(msg); e.code = code; return e }

/** The instruction for the vision model. A specific question makes it READ and COUNT rather than write prose that
 *  buries the detail — the same lesson brain.describeImage's look_at_image path already carries. */
export function visionPrompt(question) {
  const q = String(question || '').trim()
  return q
    ? `${q}\n\nAnswer from what is ACTUALLY VISIBLE in the image — concrete and brief, the direct answer first (a number, a word, a short phrase). Quote any visible text or digits verbatim. If it genuinely cannot be told from the image, say so. No preamble.`
    : 'Describe this image for someone who cannot see it: the main subject, the setting, and any visible text or numbers (quote them verbatim). Be concrete; do not guess beyond what is visible. No preamble.'
}

/** Build the looker: `(image, { question }) → text`, or throws. TIER-INJECTED transport, like read_file's extractor:
 *  enclave → `call` + `decl` (callAttestedTool, TLS pinned to the attested measurement); Lambda → `fetchImpl`. */
export function makeTinfoilVision({ apiKey, model = DEFAULT_MODEL, call, decl, fetchImpl, timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = MAX_BYTES } = {}) {
  return async function look(image = {}, opts = {}) {
    if (!apiKey || (!fetchImpl && !(call && decl))) throw fail('tool_unavailable', 'look_at_image is unavailable in this Space (no attested vision endpoint is declared for this build)')
    const b64 = typeof image.b64 === 'string' ? image.b64 : image.bytes ? Buffer.from(image.bytes).toString('base64') : ''
    if (!b64) throw new Error('no image to look at')
    if (Buffer.byteLength(b64, 'base64') > maxBytes) throw new Error('that image is too large to look at')
    const body = {
      model,
      max_tokens: 900,
      messages: [{ role: 'user', content: [{ type: 'text', text: visionPrompt(opts.question) }, { type: 'image_url', image_url: { url: `data:${image.mime || 'image/png'};base64,${b64}` } }] }],
    }
    let data
    try {
      if (call && decl) {
        const res = await call(decl, { apiKey, json: body, timeoutMs })
        if (!res || res.status !== 200) throw new Error(`vision endpoint answered ${res && res.status}`)
        data = JSON.parse(res.body.toString('utf8'))
      } else {
        const res = await fetchImpl(`https://inference.tinfoil.sh/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) })
        if (!res.ok) throw new Error(`vision endpoint answered ${res.status}`)
        data = await res.json()
      }
    } catch (e) {
      const code = e && e.code
      if (code === 'tool_unattested' || code === 'tool_measurement_unpinned' || code === 'tool_pin_mismatch') throw fail('tool_unavailable', `look_at_image is unavailable in this Space (${code})`)
      throw new Error(`could not look at that image (${String((e && e.message) || e).slice(0, 120)})`)
    }
    const text = String((data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '').trim()
    if (!text) throw new Error('the vision model returned nothing')
    return text.length > MAX_CHARS ? text.slice(0, MAX_CHARS) + '\n…(truncated)' : text
  }
}
