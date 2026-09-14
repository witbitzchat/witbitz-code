// agent/attestedTool.mjs — call a tool endpoint OUTSIDE the enclave over a channel bound to its attestation.
//
// tinfoilAttest.mjs proves which TLS key the endpoint's enclave holds; this is the other half: the request only
// goes out on a TLS session whose leaf certificate carries EXACTLY that key (sha256 over the SubjectPublicKeyInfo
// DER — the digest the SEV-SNP report's report_data commits to), on top of the normal chain + hostname checks. So
// the bytes reach the attested enclave or nobody: a proxy, a CDN edge, a re-issued certificate, or another instance
// behind the same DNS name all fail the pin before the request body is written. A pin mismatch is also the signal
// that the enclave restarted with a fresh key → the caller re-attests ONCE and retries, then fails closed.
//
// Inside the Nitro enclave this is a plain https.request: the supervisor's DNS answers 127.0.0.1, its :443 listener
// splices by SNI to the parent, and the parent forwards only to hosts in the MEASURED egress allowlist — TLS still
// terminates HERE, so the pin is checked by this process, not by anything on the path.
import https from 'node:https'
import tls from 'node:tls'
import { X509Certificate, createHash, randomBytes } from 'node:crypto'
import { ensureToolAttested as tinfoilAttest, forgetToolAttestation as tinfoilForget } from './tinfoilAttest.mjs'
import { ensureToolAttested as nitroAttest, forgetToolAttestation as nitroForget } from './nitroToolAttest.mjs'

const HEX64 = /^[0-9a-f]{64}$/
const DEFAULT_TIMEOUT_MS = 90_000
const fail = (code, detail) => { const e = new Error(`${code}${detail ? `: ${detail}` : ''}`); e.code = code; return e }

/** sha256(SPKI DER) of a peer certificate as Node hands it to checkServerIdentity (`cert.raw` = DER). */
export function spkiFingerprint(cert) {
  return createHash('sha256').update(new X509Certificate(cert.raw).publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
}

/** A `checkServerIdentity` that requires the leaf's key to be `fingerprint` AND passes Node's own hostname check. */
export function checkPinnedIdentity(fingerprint) {
  const want = String(fingerprint || '').toLowerCase()
  return (host, cert) => {
    let got
    try { got = spkiFingerprint(cert) } catch (e) { return fail('tool_pin_mismatch', 'unreadable leaf certificate') }
    if (!HEX64.test(want) || got !== want) return fail('tool_pin_mismatch', `server key ${got.slice(0, 16)}… is not the attested key ${want.slice(0, 16)}…`)
    return tls.checkServerIdentity(host, cert)
  }
}

const headerSafe = (s) => String(s || 'file').replace(/[\r\n"\\]/g, '_').slice(0, 200)
/** multipart/form-data with one `files` part per { name, mime, bytes }. */
export function multipart(files) {
  const boundary = 'wbx' + randomBytes(16).toString('hex')
  const parts = []
  for (const f of files || []) {
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="files"; filename="${headerSafe(f.name)}"\r\nContent-Type: ${headerSafe(f.mime || 'application/octet-stream')}\r\n\r\n`), Buffer.from(f.bytes || []), Buffer.from('\r\n'))
  }
  parts.push(Buffer.from(`--${boundary}--\r\n`))
  return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` }
}

/** One HTTPS request pinned to `fingerprint`. Resolves { status, headers, body:Buffer }; rejects with .code
 *  tool_pin_mismatch / tool_timeout / tool_unreachable. `port`/`ca` exist for the in-process test server only. */
export function pinnedRequest({ host, path, method = 'POST', headers = {}, body, fingerprint, timeoutMs = DEFAULT_TIMEOUT_MS, port = 443, ca }) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.isBuffer(body) ? body : Buffer.from(body || '')
    const req = https.request({
      host, port, servername: host, path, method,
      headers: { ...headers, 'content-length': payload.length },
      checkServerIdentity: checkPinnedIdentity(fingerprint),
      ...(ca ? { ca } : {}),
      agent: false, // one connection per call: the pin is checked on every session, never inherited from a pool
    }, (res) => {
      const chunks = []
      res.on('data', (d) => chunks.push(d))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
      res.on('error', (e) => reject(fail('tool_unreachable', String(e && e.message))))
    })
    req.setTimeout(timeoutMs, () => req.destroy(fail('tool_timeout', `${host} did not answer within ${timeoutMs}ms`)))
    req.on('error', (e) => reject(e && e.code === 'tool_pin_mismatch' ? e : e && (e.code === 'tool_timeout') ? e : fail('tool_unreachable', String((e && e.message) || e).slice(0, 160))))
    req.end(payload)
  })
}

/** The attester the declaration's ROOT names: what proves the far key is an enclave's, before any byte leaves. */
const attesterFor = (decl) => decl && decl.root === 'nitro' ? { attest: nitroAttest, forget: nitroForget } : { attest: tinfoilAttest, forget: tinfoilForget }

/** Attest the declared endpoint, then POST `files` (multipart) to decl.path?query — with a Bearer key when the tool
 *  takes one (Tinfoil); the keyless nitro tools get no authorization header at all. One retry on a TLS pin mismatch
 *  (enclave restarted → forget the verdict, re-attest). Never contacts the endpoint unattested. A verdict may carry
 *  `ca` (the nitro enclave's attested self-signed leaf): that, and only that, is what Node validates the chain against. */
// `json` posts a JSON body instead of a multipart one (web_search's chat-completions call); `files` stays the
// default so every existing caller is byte-for-byte unchanged. Exactly one of the two is sent.
export async function callAttestedTool(decl, { apiKey, files = [], query = {}, json, timeoutMs } = {}, deps = {}) {
  const { attest = attesterFor(decl).attest, forget = attesterFor(decl).forget, port, ca } = deps
  const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v != null)).toString()
  const path = decl.path + (qs ? `?${qs}` : '')
  for (let attempt = 0; ; attempt++) {
    const att = await attest(decl)
    const { body, contentType } = json !== undefined
      ? { body: Buffer.from(JSON.stringify(json), 'utf8'), contentType: 'application/json' }
      : multipart(files)
    try {
      return await pinnedRequest({ host: decl.host, path, headers: { ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}), 'content-type': contentType, accept: 'application/json' }, body, fingerprint: att.fingerprint, timeoutMs, port, ca: att.ca || ca })
    } catch (e) {
      if (e && e.code === 'tool_pin_mismatch' && attempt === 0) { forget(decl); continue }
      throw e
    }
  }
}
