// tinfoilDocRead.test — the enclave tier's read_file extractor: a shared document's bytes go to Tinfoil's document
// enclave over the attested channel (attestedTool.mjs, injected here) and come back as text in fileText's shape.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { makeTinfoilExtractor, fileKind } from './tinfoilDocRead.mjs'

const DECL = { root: 'tinfoil', repo: 'tinfoilsh/confidential-model-router', host: 'inference.tinfoil.sh', path: '/v1/convert/file' }
const b64 = (s) => Buffer.from(s).toString('base64')
const reply = (md, status = 200) => ({ status, headers: {}, body: Buffer.from(JSON.stringify({ document: { md_content: md }, status: 'ok' })) })

test('fileKind: mirrors fileText\'s classification from mime then extension', () => {
  assert.equal(fileKind({ mime: 'application/pdf' }), 'pdf')
  assert.equal(fileKind({ name: 'x.PDF' }), 'pdf')
  assert.equal(fileKind({ mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }), 'docx')
  assert.equal(fileKind({ name: 'a.xlsx' }), 'xlsx')
  assert.equal(fileKind({ mime: 'text/csv' }), 'csv')
  assert.equal(fileKind({ name: 'notes.md' }), 'text')
  assert.equal(fileKind({ name: 'blob.bin', mime: 'application/octet-stream' }), 'file')
})

test('extract: sends the file bytes as one multipart part (mode=text) with the key, maps md_content → {kind, text, truncated}', async () => {
  const calls = []
  const call = async (decl, req) => { calls.push({ decl, req }); return reply('# Title\n\nHello **doc**') }
  const extract = makeTinfoilExtractor({ decl: DECL, apiKey: 'k', call })
  const r = await extract({ b64: b64('%PDF-1.4 fake'), mime: 'application/pdf', name: 'f.pdf' }, { maxChars: 1000 })
  assert.deepEqual(r, { kind: 'pdf', text: '# Title\n\nHello **doc**', truncated: false, pages: undefined, sheets: undefined })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].decl, DECL)
  assert.equal(calls[0].req.apiKey, 'k')
  assert.deepEqual(calls[0].req.query, { mode: 'text' })
  assert.equal(calls[0].req.files.length, 1)
  assert.equal(calls[0].req.files[0].name, 'f.pdf'); assert.equal(calls[0].req.files[0].mime, 'application/pdf')
  assert.equal(calls[0].req.files[0].bytes.toString(), '%PDF-1.4 fake')
})

test('extract: truncates at maxChars (bounded like fileText), normalises whitespace, empty text is an error', async () => {
  const extract = makeTinfoilExtractor({ decl: DECL, apiKey: 'k', call: async () => reply('a  \n\n\n\nb' + 'x'.repeat(5000)) })
  const r = await extract({ b64: b64('z'), name: 'a.txt' }, { maxChars: 600 })
  assert.equal(r.truncated, true); assert.equal(r.text.length, 600); assert.ok(r.text.startsWith('a\n\nb'))
  const empty = makeTinfoilExtractor({ decl: DECL, apiKey: 'k', call: async () => reply('   ') })
  await assert.rejects(empty({ b64: b64('z'), name: 'a.pdf' }), /no readable text/)
  await assert.rejects(extract({ b64: '', name: 'a.pdf' }), /empty file/)
})

test('extract: without a key, without a declaration, or on a refused/unattested endpoint the tool is UNAVAILABLE — never a local fallback', async () => {
  const noKey = makeTinfoilExtractor({ decl: DECL, apiKey: '', call: async () => { throw new Error('must not be called') } })
  await assert.rejects(noKey({ b64: b64('z'), name: 'a.pdf' }), (e) => e.code === 'tool_unavailable' && /unavailable in this Space/.test(e.message))
  const noDecl = makeTinfoilExtractor({ decl: null, apiKey: 'k', call: async () => { throw new Error('must not be called') } })
  await assert.rejects(noDecl({ b64: b64('z'), name: 'a.pdf' }), (e) => e.code === 'tool_unavailable')
  const un = new Error('tool_unattested: nope'); un.code = 'tool_unattested'
  const unatt = makeTinfoilExtractor({ decl: DECL, apiKey: 'k', call: async () => { throw un } })
  await assert.rejects(unatt({ b64: b64('z'), name: 'a.pdf' }), (e) => e.code === 'tool_unavailable' && /unavailable in this Space/.test(e.message))
  const http = makeTinfoilExtractor({ decl: DECL, apiKey: 'k', call: async () => ({ status: 415, headers: {}, body: Buffer.from('{"error":"unsupported"}') }) })
  await assert.rejects(http({ b64: b64('z'), name: 'a.xyz' }), /could not read|415/)
})

test('extract: a document larger than the endpoint accepts is refused up front (no bytes leave)', async () => {
  let called = false
  const extract = makeTinfoilExtractor({ decl: DECL, apiKey: 'k', call: async () => { called = true; return reply('x') }, maxBytes: 100 })
  await assert.rejects(extract({ b64: b64('y'.repeat(200)), name: 'big.pdf' }), /too large/)
  assert.equal(called, false)
})

// ── the timeout chain (2026-09-08) ───────────────────────────────────────────────────────────────────────────────
// A confidential turn that read a PDF never came back: the member watched "thinking" and neither the reply NOR their
// own message reached the ledger. The numbers could not work — the enclave's whole turn budget was 45s while this
// tool's default network timeout is 90s with one retry. The tool must therefore be BOUNDED BY ITS CALLER, and the
// enclave tier passes a value that fits (infra/enclave/node/enclaveTools.mjs).
test('the extractor passes the caller’s timeout down to the attested call', async () => {
  let seen = null
  const call = async (decl, opts) => { seen = opts; return { status: 200, body: Buffer.from(JSON.stringify({ document: { md_content: 'hi' } })) } }
  const decl = { host: 'h', path: '/p', repo: 'r' }
  await makeTinfoilExtractor({ decl, apiKey: 'k', call, timeoutMs: 70_000 })({ bytes: Buffer.from('x'.repeat(100)), name: 'a.pdf', mime: 'application/pdf' }, {})
  assert.equal(seen.timeoutMs, 70_000, 'an unbounded tool inside a bounded turn is a hang, not a slow answer')
})

test('with no timeout given, none is forced on the call (the Lambda tier keeps the default)', async () => {
  let seen = null
  const call = async (decl, opts) => { seen = opts; return { status: 200, body: Buffer.from(JSON.stringify({ document: { md_content: 'hi' } })) } }
  await makeTinfoilExtractor({ decl: { host: 'h', path: '/p', repo: 'r' }, apiKey: 'k', call })({ bytes: Buffer.from('x'.repeat(100)), name: 'a.pdf' }, {})
  assert.ok(!('timeoutMs' in seen), 'no caller budget ⇒ leave attestedTool’s own default alone')
})
