// attestedTool.test — the pinned channel a tool call rides on: TLS bound to the key the endpoint's attestation
// proved, fail-closed. In-process: a local HTTPS server with a throwaway self-signed cert (openssl), pinned by its
// real SPKI digest; a second cert for the same name shows the mismatch path.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate, createHash } from 'node:crypto'
import { spkiFingerprint, checkPinnedIdentity, multipart, pinnedRequest, callAttestedTool } from './attestedTool.mjs'

let dir, srv, port, cert, key, fp, otherFp
const mkCert = (name) => {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(dir, name + '.key'), '-out', join(dir, name + '.crt'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' })
  const c = readFileSync(join(dir, name + '.crt'))
  return { cert: c, key: readFileSync(join(dir, name + '.key')), fp: createHash('sha256').update(new X509Certificate(c).publicKey.export({ type: 'spki', format: 'der' })).digest('hex') }
}
before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'wbx-pin-'))
  ;({ cert, key, fp } = mkCert('a'))
  otherFp = mkCert('b').fp
  srv = https.createServer({ cert, key }, (req, res) => {
    const chunks = []
    req.on('data', (d) => chunks.push(d))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ method: req.method, url: req.url, auth: req.headers.authorization || null, ct: req.headers['content-type'] || null, len: body.length, hasFile: body.includes('hello file') }))
    })
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  port = srv.address().port
})
after(() => { srv.close(); rmSync(dir, { recursive: true, force: true }) })

test('spkiFingerprint / checkPinnedIdentity: sha256 over the SPKI DER (not the raw EC point); mismatch → tool_pin_mismatch', () => {
  const x = new X509Certificate(cert)
  assert.equal(spkiFingerprint({ raw: x.raw }), fp)
  assert.notEqual(fp, createHash('sha256').update(x.publicKey.export({ type: 'spki', format: 'der' }).subarray(-65)).digest('hex'))
  const check = checkPinnedIdentity(fp)
  assert.equal(check('localhost', { raw: x.raw, subject: { CN: 'localhost' }, subjectaltname: 'DNS:localhost' }), undefined)
  const err = checkPinnedIdentity(otherFp)('localhost', { raw: x.raw, subject: { CN: 'localhost' }, subjectaltname: 'DNS:localhost' })
  assert.equal(err && err.code, 'tool_pin_mismatch')
  const bad = check('other.example', { raw: x.raw, subject: { CN: 'localhost' }, subjectaltname: 'DNS:localhost' }) // key right, name wrong
  assert.ok(bad instanceof Error)
})

test('multipart: one part per file under the `files` field, filename + content type carried, deterministic layout', () => {
  const { body, contentType } = multipart([{ name: 'a.txt', mime: 'text/plain', bytes: Buffer.from('hello file') }])
  const b = contentType.match(/boundary=(\S+)/)[1]
  const s = body.toString()
  assert.match(contentType, /^multipart\/form-data; boundary=/)
  assert.ok(s.startsWith(`--${b}\r\nContent-Disposition: form-data; name="files"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nhello file\r\n--${b}--\r\n`))
  const q = multipart([{ name: 'we"ird\r\n.pdf', mime: 'application/pdf', bytes: Buffer.alloc(2) }]).body.toString()
  assert.doesNotMatch(q, /we"ird\r\n\.pdf/) // a filename cannot break out of its header
})

test('pinnedRequest: the request goes through when the server key matches the pin, and NOT when it does not', async () => {
  const opts = { host: 'localhost', port, path: '/v1/x?mode=text', headers: { authorization: 'Bearer t' }, body: Buffer.from('payload'), ca: [cert] }
  const ok = await pinnedRequest({ ...opts, fingerprint: fp })
  assert.equal(ok.status, 200)
  const j = JSON.parse(ok.body.toString())
  assert.equal(j.method, 'POST'); assert.equal(j.url, '/v1/x?mode=text'); assert.equal(j.auth, 'Bearer t'); assert.equal(j.len, 7)
  await assert.rejects(pinnedRequest({ ...opts, fingerprint: otherFp }), (e) => e.code === 'tool_pin_mismatch')
  await assert.rejects(pinnedRequest({ ...opts, fingerprint: 'nothex' }), (e) => e.code === 'tool_pin_mismatch')
})

test('pinnedRequest: a hung server trips the timeout (tool_timeout), never a hang', async () => {
  const hang = https.createServer({ cert, key }, () => { /* never answers */ })
  await new Promise((r) => hang.listen(0, '127.0.0.1', r))
  try {
    await assert.rejects(pinnedRequest({ host: 'localhost', port: hang.address().port, path: '/', body: Buffer.alloc(0), ca: [cert], fingerprint: fp, timeoutMs: 300 }), (e) => e.code === 'tool_timeout')
  } finally { hang.close() }
})

test('callAttestedTool: attest → pin → POST multipart; a pin mismatch re-attests ONCE then fails closed', async () => {
  const decl = { root: 'tinfoil', repo: 'o/r', host: 'localhost', path: '/v1/convert/file' }
  let attests = 0, forgot = 0
  const fps = [fp]
  const deps = { attest: async () => { attests++; return { fingerprint: fps.shift() || fp } }, forget: () => { forgot++ }, port, ca: [cert] }
  const r = await callAttestedTool(decl, { apiKey: 'k', query: { mode: 'text' }, files: [{ name: 'a.txt', mime: 'text/plain', bytes: Buffer.from('hello file') }] }, deps)
  assert.equal(r.status, 200)
  const j = JSON.parse(r.body.toString())
  assert.equal(j.url, '/v1/convert/file?mode=text'); assert.equal(j.auth, 'Bearer k'); assert.match(j.ct, /^multipart\/form-data/); assert.equal(j.hasFile, true)
  assert.equal(attests, 1)
  // enclave restarted with a new key: first attempt mismatches → forget + re-attest → second attempt succeeds
  fps.push(otherFp, fp); attests = 0
  const r2 = await callAttestedTool(decl, { apiKey: 'k', files: [] }, deps)
  assert.equal(r2.status, 200); assert.equal(attests, 2); assert.equal(forgot, 1)
  // still wrong after the retry → refused, not looped
  fps.push(otherFp, otherFp); attests = 0
  await assert.rejects(callAttestedTool(decl, { apiKey: 'k', files: [] }, deps), (e) => e.code === 'tool_pin_mismatch')
  assert.equal(attests, 2)
})

test('callAttestedTool: no attestation ⇒ no request (the endpoint is never contacted)', async () => {
  const decl = { root: 'tinfoil', repo: 'o/r', host: 'localhost', path: '/x' }
  const e = new Error('tool_unattested: x'); e.code = 'tool_unattested'
  await assert.rejects(callAttestedTool(decl, { apiKey: 'k', files: [] }, { attest: async () => { throw e }, port, ca: [cert] }), (err) => err.code === 'tool_unattested')
})

test('callAttestedTool: `json` posts an application/json body; without it the multipart default is byte-for-byte unchanged', async () => {
  // web_search calls Tinfoil's chat-completions endpoint, which wants JSON — read_file's multipart must stay untouched.
  const decl = { root: 'tinfoil', repo: 'o/r', host: 'localhost', path: '/v1/chat/completions' }
  const deps = { attest: async () => ({ fingerprint: fp }), forget: () => {}, port, ca: [cert] }
  const payload = { model: 'gpt-oss-120b', web_search_options: {} }
  const j = JSON.parse((await callAttestedTool(decl, { apiKey: 'k', json: payload }, deps)).body.toString())
  assert.equal(j.ct, 'application/json')
  assert.equal(j.auth, 'Bearer k')
  assert.equal(j.len, Buffer.byteLength(JSON.stringify(payload)), 'the exact JSON bytes, nothing wrapped around them')
  const m = JSON.parse((await callAttestedTool(decl, { apiKey: 'k', files: [{ name: 'a.txt', mime: 'text/plain', bytes: Buffer.from('hello file') }] }, deps)).body.toString())
  assert.match(m.ct, /^multipart\/form-data/)
  assert.equal(m.hasFile, true)
})
