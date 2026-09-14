// tools/code-confidential.mjs — the local TrustedRouter proxy that makes a "confidential" model in Code confidential.
// The receipt path is proven on REAL bytes: agent/fixtures/inference-receipt/ is a stream captured from
// api.trustedrouter.com with its genuine signature, the exact request bytes, the nonce, and Google's JWKS of that minute.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  startConfidentialProxy, confidentialModels, stampFloor, unreadableParts, convertUnreadable, makeTinfoilReader,
  makeAnswerGate, proxyConfig, proxyPortFor, HOLD_BEFORE_LAPSE_SEC,
} from './code-confidential.mjs'
import { _resetGatewayAttestCache } from '../agent/gatewayAttest.mjs'
import { verifyInferenceReceipt } from '../agent/inferenceReceipt.mjs'

const FIX = new URL('../agent/fixtures/inference-receipt/', import.meta.url)
const STREAM = readFileSync(new URL('stream.sse', FIX), 'utf8')
const REQUEST = readFileSync(new URL('request.json', FIX), 'utf8')
const META = JSON.parse(readFileSync(new URL('meta.json', FIX), 'utf8'))
const JWKS_URL = /googleapis\.com\/service_accounts/
const PNG = 'data:image/png;base64,' + Buffer.from('not really a png').toString('base64')

/** A fake network: TrustedRouter answers with `stream` (in small pieces, as the wire does); Google's JWKS as captured. */
function fakeNet({ stream = STREAM, status = 200 } = {}) {
  const calls = []
  const fetchImpl = async (url, init = {}) => {
    if (JWKS_URL.test(url)) return new Response(JSON.stringify(META.googleJwks), { status: 200, headers: { 'content-type': 'application/json' } })
    calls.push({ url, headers: init.headers || {}, body: typeof init.body === 'string' ? init.body : Buffer.isBuffer(init.body) ? init.body.toString('utf8') : init.body })
    if (status !== 200) return new Response(JSON.stringify({ error: { message: 'upstream said no' } }), { status, headers: { 'content-type': 'application/json' } })
    const bytes = new TextEncoder().encode(stream)
    const body = new ReadableStream({ start(c) { for (let i = 0; i < bytes.length; i += 97) c.enqueue(bytes.slice(i, i + 97)); c.close() } })
    return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
  }
  return { calls, fetchImpl }
}

async function proxy(t, opts = {}) {
  _resetGatewayAttestCache()
  const net = opts.net || fakeNet()
  const p = await startConfidentialProxy({ upstream: 'https://tr.test', fetchImpl: net.fetchImpl, gate: async () => ({ ok: true }), nonce: () => META.nonce, now: () => META.nowMs, reader: null, log: () => {}, ...opts })
  t.after(() => p.close())
  const post = (body, headers = {}) => fetch(`http://127.0.0.1:${p.port}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer user-own-tr-key', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) })
  return { p, net, post }
}
const SAY_OK = { model: 'deepseek/deepseek-v4-flash', messages: [{ role: 'user', content: 'Say OK.' }], max_tokens: 5, stream: true }

test('the catalog\'s confidential tier is the list; the floor makes EXACTLY the bytes a confidential room sends', () => {
  const m = confidentialModels()
  assert.ok(m.has('deepseek/deepseek-v4-flash') && m.has('moonshotai/kimi-k3'))
  assert.equal(m.get('moonshotai/kimi-k3').vision, false)
  assert.equal(m.has('openai/gpt-5.1'), false, 'a regular-only model is not confidential')
  assert.equal(JSON.stringify(stampFloor(SAY_OK)), REQUEST, 'byte-identical to the captured request the receipt signed')
  assert.equal(proxyPortFor(4096), 4196)
})

test('a confidential answer streams through; the receipt verifies on the real captured bytes; the receipt itself never reaches OpenCode', { skip: typeof ReadableStream === 'undefined' }, async (t) => {
  const { net, post } = await proxy(t)
  const r = await post(SAY_OK)
  assert.equal(r.status, 200)
  const text = await r.text()
  assert.equal(net.calls.length, 1)
  assert.equal(net.calls[0].body, REQUEST, 'min_privacy + streaming stamped, nothing else changed')
  assert.equal(net.calls[0].headers['x-inference-receipt'], META.nonce, 'a receipt was asked for')
  assert.equal(net.calls[0].headers.authorization, 'Bearer user-own-tr-key', 'the user\'s own TrustedRouter key, passed through')
  assert.match(text, /"content":"OK"/)
  assert.match(text, /"finish_reason":"stop"/)
  assert.match(text, /data: \[DONE\]/)
  assert.ok(!text.includes('inference_receipt'), 'the receipt event is ours, not OpenCode\'s')
})

test('a receipt that does not match what arrived ends the step with an error — no finish, no [DONE], so no tool runs', async (t) => {
  const { post } = await proxy(t, { net: fakeNet({ stream: STREAM.replace('"content":"OK"', '"content":"NO"') }) })
  const text = await (await post(SAY_OK)).text()
  assert.match(text, /not confidential: .*receipt_resp_hash/)
  assert.ok(!/"finish_reason":"stop"/.test(text) && !text.includes('[DONE]'), text)
})

// ── receipt_verification_window: the one refusal asked again (the owner: "I sometimes get this") ──
/** A verifier that says `receipt_verification_window` for the attempts listed (1-based), and really verifies the rest. */
function lapsing(...lapsed) {
  let n = 0
  const fn = async (args) => (lapsed.includes(++n) ? { ok: false, error: 'receipt_verification_window' } : verifyInferenceReceipt(args))
  fn.count = () => n
  return fn
}
const noWait = async () => {}
const count = (text, re) => (text.match(re) || []).length

test('a lapsed proof before anything reached OpenCode is asked again, with a fresh nonce, and verified again', async (t) => {
  const verify = lapsing(1)
  let nonces = 0
  const logs = []
  const { net, post } = await proxy(t, { verify, sleep: noWait, nonce: () => { nonces++; return META.nonce }, log: (l) => logs.push(l) })
  const r = await post({ ...SAY_OK, stream: false })
  assert.equal(r.status, 200)
  assert.equal((await r.json()).choices[0].message.content, 'OK.')
  assert.equal(net.calls.length, 2, 'asked twice')
  assert.equal(nonces, 2, 'each call has its own receipt nonce')
  assert.equal(verify.count(), 2, 'the second answer went through the whole check')
  assert.match(logs.join('\n'), /REFUSED deepseek\/deepseek-v4-flash — receipt_verification_window[\s\S]*↻/)
})

test('an answer already streaming when its proof lapsed is not asked again — no text twice, and the message says what to do', async (t) => {
  const { net, post } = await proxy(t, { verify: lapsing(1), sleep: noWait })
  const text = await (await post(SAY_OK)).text()
  assert.equal(net.calls.length, 1)
  assert.equal(count(text, /"content":"OK"/g), 1)
  assert.match(text, /TrustedRouter renewed its proof of the model's enclave while this answer was on its way[^"]*Send your message again to continue\. \(receipt_verification_window\)/)
  assert.ok(!text.includes('[DONE]') && !/"finish_reason":"stop"/.test(text), 'nothing committed')
})

test('an answer that starts close to the end of the last proof is held back whole, so a lapse is asked again unseen', async (t) => {
  let clock = META.nowMs
  const verify = lapsing(2)
  const { net, post } = await proxy(t, { verify, sleep: noWait, now: () => clock })
  await (await post(SAY_OK)).text() // learns when this model's proof ends (the captured receipt: 1788680807)
  clock = (1788680807 - HOLD_BEFORE_LAPSE_SEC + 10) * 1000
  const text = await (await post(SAY_OK)).text()
  assert.equal(net.calls.length, 3, 'the held answer was asked again')
  assert.equal(count(text, /"content":"OK"/g), 1, 'the refused answer never reached OpenCode')
  assert.match(text, /"finish_reason":"stop"[\s\S]*data: \[DONE\]/)
  assert.ok(!text.includes('error'), text)
})

test('a proof far from its end streams live; asked again and lapsed again is a real refusal; other reasons are never asked again', async (t) => {
  const { net, post } = await proxy(t, { verify: lapsing(1, 2), sleep: noWait })
  const r = await post({ ...SAY_OK, stream: false })
  assert.equal(r.status, 502)
  assert.match((await r.json()).error.message, /receipt_verification_window/)
  assert.equal(net.calls.length, 2, 'once more, not a loop')
  const other = await proxy(t, { sleep: noWait, verify: async () => ({ ok: false, error: 'receipt_resp_hash' }) })
  const r2 = await other.post({ ...SAY_OK, stream: false })
  assert.match((await r2.json()).error.message, /not confidential: .*receipt_resp_hash/)
  assert.equal(other.net.calls.length, 1)
  const live = makeAnswerGate()
  assert.equal(live.push('data: {"choices":[{"delta":{"content":"hi"}}]}\n\n').length, 1)
  assert.equal(makeAnswerGate({ hold: true }).push('data: {"choices":[{"delta":{"content":"hi"}}]}\n\n').length, 0)
})

test('a caller that did not ask to stream gets one verified chat.completion', async (t) => {
  const { net, post } = await proxy(t)
  const r = await post({ ...SAY_OK, stream: false }) // OpenCode's non-streaming calls (titles) — still streamed upstream, for the receipt
  assert.equal(net.calls[0].body, REQUEST, 'upstream it is the same streamed, floored request')
  assert.equal(r.status, 200)
  const c = await r.json()
  assert.equal(c.object, 'chat.completion')
  assert.equal(c.choices[0].message.content, 'OK.')
  assert.equal(c.choices[0].finish_reason, 'stop')
  assert.equal(c.usage.total_tokens, 10)
})

test('a model outside the confidential tier passes through byte for byte — no floor, no receipt', async (t) => {
  const { net, post } = await proxy(t)
  const raw = JSON.stringify({ model: 'openai/gpt-5.1', messages: [{ role: 'user', content: 'hi' }], stream: true })
  const r = await post(raw)
  assert.equal(r.status, 200)
  await r.text()
  assert.equal(net.calls[0].body, raw)
  assert.equal(net.calls[0].headers['x-inference-receipt'], undefined)
})

test('the gateway must prove its attestation before a confidential request leaves', async (t) => {
  const { net, post } = await proxy(t, { gate: async () => ({ ok: false, error: 'attest_bad_signature' }) })
  const r = await post(SAY_OK)
  assert.equal(r.status, 502)
  assert.match((await r.json()).error.message, /did not prove it runs attested code \(attest_bad_signature\)/)
  assert.equal(net.calls.length, 0, 'nothing was sent')
})

test('an image for a text-only confidential model: refused without a Tinfoil key, never sent', async (t) => {
  const { net, post } = await proxy(t)
  const r = await post({ ...SAY_OK, model: 'moonshotai/kimi-k3', messages: [{ role: 'user', content: [{ type: 'text', text: 'what is this' }, { type: 'image_url', image_url: { url: PNG } }] }] })
  assert.equal(r.status, 400)
  const e = (await r.json()).error
  assert.equal(e.type, 'tinfoil_key_missing')
  assert.match(e.message, /Kimi K3 \(confidential\) cannot read images or files, and this computer has no Tinfoil key/)
  assert.equal(net.calls.length, 0)
})

test('with a Tinfoil reader the image becomes text before TrustedRouter sees the request; a vision model keeps its image', async (t) => {
  const seen = []
  const reader = async (item, question) => { seen.push({ kind: item.kind, question }); return 'A settings sheet with a model field.' }
  const { net, post } = await proxy(t, { reader, net: fakeNet({ status: 418 }) }) // upstream answer irrelevant here
  await post({ ...SAY_OK, model: 'moonshotai/kimi-k3', messages: [{ role: 'user', content: [{ type: 'text', text: 'what is this' }, { type: 'image_url', image_url: { url: PNG } }] }] })
  const sent = JSON.parse(net.calls[0].body)
  assert.deepEqual(sent.messages[0].content.map((p) => p.type), ['text', 'text'], 'no image part left')
  assert.match(sent.messages[0].content[1].text, /read inside Tinfoil's attested enclave[\s\S]*A settings sheet with a model field\./)
  assert.match(seen[0].question, /The person's message with it: "what is this"/)
  assert.equal(JSON.stringify(sent).includes('base64'), false, 'the image bytes never went to TrustedRouter')
  await post({ ...SAY_OK, model: 'google/gemma-4-31b-it', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: PNG } }] }] })
  assert.equal(JSON.parse(net.calls[1].body).messages[0].content[0].type, 'image_url', 'a confidential model that CAN see gets the picture')
})

test('files: found wherever OpenCode puts them; the reader is asked once per distinct content', async () => {
  const body = { messages: [{ role: 'user', content: [{ type: 'file', file: { filename: 'spec.docx', file_data: 'data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,UEsDBA==' } }] }, { role: 'user', content: 'plain' }] }
  const parts = unreadableParts(body)
  assert.deepEqual(parts.map((p) => [p.kind, p.name, p.at]), [['file', 'spec.docx', [0, 0]]])
  let looks = 0, reads = 0
  const toText = makeTinfoilReader({ vision: async () => { looks++; return 'img' }, docs: async () => { reads++; return { text: 'doc text' } } })
  for (let i = 0; i < 3; i++) await convertUnreadable(body, { label: 'X', toText })
  assert.equal(reads, 1, 'OpenCode re-sends the conversation every step — the document is read once')
  const out = await convertUnreadable(body, { label: 'X', toText })
  assert.match(out.body.messages[0].content[0].text, /"spec\.docx"[\s\S]*doc text/)
  assert.equal(body.messages[0].content[0].type, 'file', 'the caller\'s request object is not mutated')
})

test('Tinfoil that cannot prove its enclave: the file is not sent, and the reason says so', async () => {
  const body = { messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: PNG } }] }] }
  const toText = async () => { const e = new Error('look_at_image is unavailable in this Space (tool_unattested)'); e.code = 'tool_unavailable'; throw e }
  await assert.rejects(convertUnreadable(body, { label: 'GLM 5.3 (confidential)', toText }), (e) => e.type === 'tinfoil_unattested' && /did not prove what it runs/.test(e.message))
})

test('the answer gate: text flows, commitments wait', () => {
  const g = makeAnswerGate()
  const live = g.push('data: {"id":"a","choices":[{"delta":{"content":"Hi"},"index":0}]}\n\ndata: {"id":"a","choices":[{"delta":{"tool_calls":[{"index":0,"id":"t","function":{"name":"read","arguments":"{}"}}]},"index":0}]}\n\ndata: {"id":"a","choices":[{"delta":{"content":"late"},"index":0}]}\n\n')
  assert.equal(live.length, 1, 'only the text before the first tool call goes live')
  assert.equal(g.held().length, 2, 'the tool call and everything after it wait for the receipt, in order')
})

test('OpenCode is pointed at the proxy, and a text-only confidential model is declared able to take images', () => {
  const c = proxyConfig(4196)
  assert.equal(c.provider.trustedrouter.options.baseURL, 'http://127.0.0.1:4196/v1')
  const k3 = c.provider.trustedrouter.models['moonshotai/kimi-k3']
  assert.equal(k3.name, 'Kimi K3 · confidential')
  assert.deepEqual(k3.modalities.input, ['text', 'image'])
  assert.equal(c.provider.trustedrouter.options.apiKey, undefined, 'no key in the injected config: OpenCode keeps its own')
})
