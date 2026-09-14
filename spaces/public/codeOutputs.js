// spaces/public/codeOutputs.js — the files a Code reply PRODUCED, previewed under it without asking.
//
// The owner, after an agent fixed a PDF and — asked to "upload it here" — answered that a PDF cannot be shown in the chat:
// "I think the user should automatically see a preview". Its answer had named the file's full path all along.
//
// A result is a file the reply WROTE or EDITED (its write/edit tools), or one its answer NAMES — never one it only read,
// never a path in your own prompt. Only kinds a phone can show preview (a PDF's first page, a picture, the first lines of
// a table or a text); office files, archives and media get a chip with Download; code gets nothing (its diff is in the
// steps). Only inside the session's folder — the connector serves nothing else (tools/code-outputs.mjs) — and never a
// name that looks like a secret. Pure: no DOM, no fs — the page and the JS connector import it; the Python connector
// holds to the same cases (spaces/test/codeOutputs.vectors.json).

/** The connector-owned route a page asks for a produced file on (never forwarded to OpenCode). */
export const OUTPUT_ROUTE = '/witbitz/output'
export const MAX_OUTPUTS = 6
export const MAX_PATH = 4096

const KINDS = {
  pdf: 'pdf',
  png: 'image', jpg: 'image', jpeg: 'image', gif: 'image', webp: 'image',
  csv: 'table', tsv: 'table',
  md: 'text', markdown: 'text', txt: 'text',
  docx: 'file', doc: 'file', xlsx: 'file', xls: 'file', pptx: 'file', ppt: 'file', odt: 'file', ods: 'file', odp: 'file',
  rtf: 'file', zip: 'file', epub: 'file', heic: 'file', svg: 'file', html: 'file', htm: 'file',
  mp3: 'file', wav: 'file', m4a: 'file', mp4: 'file', mov: 'file',
}
const MIME = {
  pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  csv: 'text/csv', tsv: 'text/tab-separated-values', md: 'text/markdown', markdown: 'text/markdown', txt: 'text/plain',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', doc: 'application/msword',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', xls: 'application/vnd.ms-excel',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ppt: 'application/vnd.ms-powerpoint',
  odt: 'application/vnd.oasis.opendocument.text', ods: 'application/vnd.oasis.opendocument.spreadsheet',
  odp: 'application/vnd.oasis.opendocument.presentation', rtf: 'application/rtf', zip: 'application/zip',
  epub: 'application/epub+zip', heic: 'image/heic', svg: 'image/svg+xml', html: 'text/html', htm: 'text/html',
  mp3: 'audio/mpeg', wav: 'audio/wav', m4a: 'audio/mp4', mp4: 'video/mp4', mov: 'video/quicktime',
}

/** The extension of a file whose name does not start with a dot (`.pdf` alone is a dot-file, not a PDF). */
const extOf = (path) => { const m = /(?:^|\/)[^/.][^/]*\.([A-Za-z0-9]+)$/.exec(String(path || '')); return m ? m[1].toLowerCase() : '' }

/** 'pdf' | 'image' | 'table' | 'text' | 'file' — or null: not something to show. */
export const outputKind = (path) => KINDS[extOf(path)] || null
export const outputMime = (path) => MIME[extOf(path)] || 'application/octet-stream'

// The same rule Auto mode uses for a name that looks like a secret (tools/code-auto.mjs sensitivePath — the Python
// connector uses auto.py's): a .git/.ssh/.aws/… folder on the way, a .env, a private key, "secret"/"credential".
const SENSITIVE_BASE = /^(\.env(\..+)?|\.npmrc|\.netrc|\.pypirc|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?)$/
const SAFE_ENV = /^\.env\.(example|sample|template|dist)$/
/** `rel`: the path below the session folder, starting with "/". */
export function sensitivePath(rel) {
  const parts = String(rel || '').split('/')
  const base = parts[parts.length - 1] || ''
  if (parts.some((p) => ['.git', '.ssh', '.aws', '.gnupg', '.kube', '.docker'].includes(p))) return true
  if (SENSITIVE_BASE.test(base) && !SAFE_ENV.test(base)) return true
  if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(base)) return true
  return /secret|credential/i.test(base)
}

/** A path a page may ask for: absolute, at most 4096 characters, one line, no NUL. */
export const validOutputPath = (p) => typeof p === 'string' && p.startsWith('/') && p.length <= MAX_PATH && !/[\0\r\n]/.test(p)

/** posix normalize of an absolute path; null when it is not absolute. */
function normalize(p) {
  if (!String(p).startsWith('/')) return null
  const out = []
  for (const seg of String(p).split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') { out.pop(); continue }
    out.push(seg)
  }
  return '/' + out.join('/')
}

const EXT_ALT = Object.keys(KINDS).join('|')
const BARE = new RegExp(`(?:^|[\\s(\\[<"'«])((?:\\.{1,2}\\/|\\/)?[^\\s\`'"()<>\\[\\]«»]+\\.(?:${EXT_ALT}))(?=$|[\\s)\\]>"'».,;:!?])`, 'giu')

const escapeRe = (x) => x.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
/** Candidate paths an answer names: whole `code spans`; then, outside them, paths under the session's folder written out
 *  in full — matched from the folder itself, because a folder name with a space ("תיקייה 1") would otherwise be cut at the
 *  space into a wrong relative path; then bare tokens in what is left. */
function namedIn(text, dir) {
  const s = String(text || '')
  const out = []
  for (const m of s.matchAll(/`([^`\n]{1,4096})`/g)) out.push({ raw: m[1].trim(), spaced: true })
  let rest = s.replace(/`[^`\n]*`/g, ' ')
  const underDir = new RegExp(`${escapeRe(dir)}\\/[^\\n\`<>"]*?\\.(?:${EXT_ALT})(?=$|[\\s)\\]>"'».,;:!?])`, 'giu')
  rest = rest.replace(underDir, (m) => { out.push({ raw: m, spaced: false }); return ' ' })
  for (const m of rest.matchAll(BARE)) out.push({ raw: m[1], spaced: false })
  return out
}

/**
 * The results of one reply: `messages` is the run of assistant messages after a prompt (user messages are skipped).
 * → [{path, kind, source: 'wrote'|'named'}] — files written first, each once, at most MAX_OUTPUTS.
 */
export function replyOutputs(messages, { directory = '' } = {}) {
  const dir = normalize(directory)
  if (!dir || dir === '/') return []
  const seen = new Set()
  const out = []
  const take = (raw, source, { spaced = false } = {}) => {
    if (out.length >= MAX_OUTPUTS || typeof raw !== 'string' || !raw || raw.includes('://') || raw.startsWith('~')) return
    if (!raw.startsWith('/') && spaced && /\s/.test(raw)) return // a command in backticks, not a relative path
    const abs = normalize(raw.startsWith('/') ? raw : `${dir}/${raw}`)
    if (!abs || !validOutputPath(abs) || !abs.startsWith(dir + '/') || seen.has(abs)) return
    const kind = outputKind(abs)
    if (!kind || sensitivePath(abs.slice(dir.length))) return
    seen.add(abs)
    out.push({ path: abs, kind, source })
  }
  const assistant = (Array.isArray(messages) ? messages : []).filter((m) => m && m.info && m.info.role === 'assistant')
  const parts = assistant.flatMap((m) => (Array.isArray(m.parts) ? m.parts : []))
  for (const p of parts) {
    if (p && p.type === 'tool' && (p.tool === 'write' || p.tool === 'edit') && p.state && p.state.status === 'completed') {
      take(p.state.input && p.state.input.filePath, 'wrote')
    }
  }
  for (const p of parts) {
    if (p && p.type === 'text' && !p.synthetic) for (const c of namedIn(p.text, dir)) take(c.raw, 'named', c)
  }
  return out
}
