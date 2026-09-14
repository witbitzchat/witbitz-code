// spaces/public/codeAttachments.js — attachments in the Code section, the Claude Code way (docs/code-attachments.md).
//
// The connector saves every file a message carries on the computer and puts a NOTE in the message in its place; the agent
// opens the file (or its Tinfoil text copy) with its read tool when it needs it. This module is the note's one definition:
// the connector writes it, the page reads it back into chips, and the Python twin matches it through the tests.
//
// Measured on opencode 1.18.30 (2026-09-13): OpenCode refuses an Excel or Word file part for every model ("'file part media
// type …spreadsheetml.sheet' functionality not supported"); a staged text copy named in a synthetic line was read by Kimi K3
// unprompted, while DeepSeek V4 Flash first reached for the shell on the original — so the note says WHICH file to open.
// Pure: no DOM, no fs — the same module runs in the page and in Node.

const NOTE_HEAD = 'The user attached files. They are saved on this computer — open them with the read tool.'
const MAX_NAME = 100

/** A name that is safe as the last part of a path: no folders, no dot-file, only plain characters, at most 100 long. */
export function safeName(name) {
  let s = String(name || '').split(/[\\/]/).pop().trim()
  s = s.replace(/[^A-Za-z0-9._ ()-]+/g, '_').replace(/_+/g, '_').replace(/^\./, '_')
  if (!s.replace(/[._ ]/g, '')) s = 'file' // nothing readable left (an empty or all-foreign name)
  if (s.length > MAX_NAME) {
    const ext = (s.match(/\.[A-Za-z0-9]{1,10}$/) || [''])[0]
    s = s.slice(0, MAX_NAME - ext.length) + ext
  }
  return s
}

/** On disk: the first 8 hex of the content's SHA-256, then the safe name — the same bytes land on the same file. */
export const stagedFileName = (hashHex, name) => `${String(hashHex).slice(0, 8)}-${safeName(name)}`

const extOf = (name) => (String(name || '').toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1] || ''
const TEXT_EXT = new Set(['txt', 'md', 'markdown', 'csv', 'tsv', 'json', 'log', 'xml', 'yaml', 'yml', 'html', 'htm', 'js', 'mjs', 'ts', 'py', 'sh', 'sql', 'ini', 'toml'])

/** A document the read tool cannot show a model (PDF, Word, Excel, slides…) gets a text copy; images and text do not. */
export function needsTextCopy(mime, name) {
  const m = String(mime || '').toLowerCase()
  if (m.startsWith('image/') || m.startsWith('text/') || m === 'application/json') return false
  return !TEXT_EXT.has(extOf(name))
}

export function formatSize(bytes) {
  const n = Number(bytes) || 0
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1023.95) return `${(n / 1024).toFixed(1)} KB` // never "1024.0 KB"
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

const SHOWN_MAX = 200 // a file name is prompt text the model reads — keep it a name, not a paragraph (review finding)
const shown = (name) => String(name || 'file').replace(/[\r\n]+/g, ' ').replace(/ — /g, ' - ').slice(0, SHOWN_MAX)

/**
 * The note that replaces the files in the message. `entries`: {name, size, path, copy?, inline?, noCopy?} — `copy` is the
 * text copy's path, `inline` means the file also rides the message (an image a model can see), `noCopy` why there is none.
 */
export function attachmentNote(entries) {
  const lines = [NOTE_HEAD]
  for (const e of entries) {
    lines.push(`• ${shown(e.name)} — ${formatSize(e.size)} — ${e.path}`)
    if (e.copy) lines.push(`  Its text — open THIS with the read tool, not the original: ${e.copy}`)
    else if (e.inline) lines.push('  Shown to you with this message.')
    else if (e.noCopy) lines.push(`  No text copy (${e.noCopy}) — open it with the read tool if you can; otherwise ask the user before converting it.`)
  }
  return lines.join('\n')
}

/** The note back → [{name, size, session, file, copy, inline}], or null when the text is not a note. */
export function parseAttachmentNote(text) {
  const lines = String(text || '').split('\n')
  if (lines[0] !== NOTE_HEAD) return null
  const out = []
  for (const line of lines.slice(1)) {
    const m = /^• (.+?) — (\d+(?:\.\d)? (?:B|KB|MB)) — (\/.+)$/.exec(line)
    if (m) {
      const parts = m[3].split('/')
      out.push({ name: m[1], size: m[2], session: parts[parts.length - 2] || '', file: parts[parts.length - 1] || '', copy: '', inline: false })
      continue
    }
    const last = out[out.length - 1]
    if (!last) continue
    const c = /^ {2}Its text — .*: (\/.+)$/.exec(line)
    if (c) last.copy = c[1].split('/').pop()
    else if (/^ {2}Shown to you with this message\.$/.test(line)) last.inline = true
  }
  return out.length ? out : null
}

/** A page's request for a staged file names a session and a staged file name — never a path. */
export function validAttachmentRef(session, file) {
  return /^[A-Za-z0-9_-]{1,128}$/.test(String(session || '')) &&
    /^[0-9a-f]{8}-(?!\.)[A-Za-z0-9._ ()-]{1,110}$/.test(String(file || '')) && !String(file).includes('..')
}

const MIME = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', heic: 'image/heic',
  md: 'text/markdown', txt: 'text/plain', csv: 'text/csv', json: 'application/json',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', xls: 'application/vnd.ms-excel',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', doc: 'application/msword',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation' }
export const mimeForFile = (file) => MIME[extOf(file)] || 'application/octet-stream'

/** The connector-owned route a page asks for a staged file on (never forwarded to OpenCode). */
export const ATTACHMENT_ROUTE = '/witbitz/attachment'
