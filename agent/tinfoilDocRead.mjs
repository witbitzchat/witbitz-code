// agent/tinfoilDocRead.mjs — read_file's extractor on the ENCLAVE tier: the document leaves for Tinfoil's document
// enclave over the attested channel and comes back as text (P3 phase 2, docs/enclave-two-stage-launch.md).
//
// Same shape as agent/fileText.mjs's extractFileText (the Lambda tier keeps that in-process parser), so
// readFile.mjs cannot tell the two apart. Different trust story, stated plainly: the bytes go to an AMD SEV-SNP
// enclave whose code identity the turn verifies first (tinfoilAttest.mjs) and whose TLS key the request is pinned
// to (attestedTool.mjs); `mode=text` = the document's text layer, with pages that have none rendered by Tinfoil's
// VLM enclave behind the same router — never a non-confidential parser. What is NOT here on purpose: a fallback.
// No declaration, no key, no attestation, no route ⇒ the tool is unavailable in this Space — it never degrades to
// an unattested endpoint or an unmeasured parser. Endpoint contract (verified live 2026-09-07):
// POST /v1/convert/file?mode=text, multipart `files`, Bearer key → { document: { md_content }, status }.
import { callAttestedTool } from './attestedTool.mjs'

const DEFAULT_MAX = 60_000 // chars handed back by default — fileText's numbers, so a Space behaves the same on both tiers
const HARD_MAX = 200_000
const MAX_BYTES = 50 * 1024 * 1024 // the endpoint's per-file limit; the ledger caps a shared file far below this anyway
const MODE = 'text'
const fail = (code, msg) => { const e = new Error(msg); e.code = code; return e }

const extOf = (name) => (String(name || '').toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1] || ''
/** fileText's kind classification (mime, then extension) — without fileText's parsers on the import path. */
export function fileKind({ mime, name } = {}) {
  const m = String(mime || '').toLowerCase(), ext = extOf(name)
  const is = (needle, ...exts) => (needle && m.includes(needle)) || exts.includes(ext)
  if (is('pdf', 'pdf')) return 'pdf'
  if (is('wordprocessingml', 'docx')) return 'docx'
  if (is('spreadsheetml', 'xlsx') || is('ms-excel', 'xls')) return 'xlsx'
  if (is('csv', 'csv')) return 'csv'
  if (m.startsWith('text/') || is('', 'txt', 'md', 'markdown', 'text', 'log', 'json')) return 'text'
  return 'file'
}

/** Build the extractor: `(file, {maxChars}) → {text, kind, truncated, pages?, sheets?}` or throws. `decl` is the
 *  parsed TOOL_READ_FILE declaration from the measured policy; `apiKey` the KMS-released TINFOIL_API_KEY. */
// `timeoutMs` bounds the conversion call. It MUST be smaller than the caller's own turn budget, or the turn dies
// first and the member sees a hang instead of an answer: callAttestedTool's default is 90s, which was DOUBLE the
// enclave's whole 45s turn — so a read_file turn in a Confidential Space could not finish, whatever Tinfoil did.
export function makeTinfoilExtractor({ decl, apiKey, call = callAttestedTool, maxBytes = MAX_BYTES, timeoutMs } = {}) {
  return async function extract(file = {}, opts = {}) {
    if (!decl || !decl.host || !decl.path || !apiKey) throw fail('tool_unavailable', 'read_file is unavailable in this Space (no attested document reader is declared for this build)')
    const { b64, bytes, mime, name } = file
    const buf = bytes ? Buffer.from(bytes) : b64 ? Buffer.from(b64, 'base64') : null
    if (!buf || !buf.length) throw new Error('empty file')
    if (buf.length > maxBytes) throw new Error(`file too large to read (${Math.round(buf.length / 1048576)} MB)`)
    const maxChars = Math.min(HARD_MAX, Math.max(500, Number(opts.maxChars) || DEFAULT_MAX))
    let res
    try {
      res = await call(decl, { apiKey, query: { mode: MODE }, files: [{ name: name || 'file', mime: mime || 'application/octet-stream', bytes: buf }], ...(timeoutMs ? { timeoutMs } : {}) })
    } catch (e) {
      const code = e && e.code
      if (code === 'tool_unattested' || code === 'tool_measurement_unpinned' || code === 'tool_pin_mismatch') throw fail('tool_unavailable', `read_file is unavailable in this Space (${code})`)
      throw new Error(`could not read that file (${String((e && e.message) || e).slice(0, 120)})`)
    }
    if (!res || res.status !== 200) throw new Error(`could not read that file (document reader answered ${res && res.status})`)
    let doc
    try { doc = JSON.parse(res.body.toString('utf8')) } catch { throw new Error('could not read that file (malformed reader response)') }
    let text = String((doc && doc.document && doc.document.md_content) || '')
    text = text.replace(/\u0000/g, '').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim()
    if (!text) throw new Error('no readable text in that file')
    const truncated = text.length > maxChars
    return { text: truncated ? text.slice(0, maxChars) : text, kind: fileKind({ mime, name }), truncated, pages: undefined, sheets: undefined }
  }
}
