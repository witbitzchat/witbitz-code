// tools/code-attachments.mjs — the connector saves the files a Code message carries, the Claude Code way
// (docs/code-attachments.md). Claude Code saves every attachment to disk and hands the agent a path; here the connector
// does that before OpenCode sees the message, because OpenCode refuses an Excel or Word file part for every model and
// TrustedRouter answers 502 for a PDF (both measured, opencode 1.18.30, 2026-09-13).
//
//   POST /session/:id/message  →  each data: file part saved under <root>/<session>/<sha8>-<name> (folder 700, file 600)
//                              →  a document (PDF, Word, Excel…) also gets <file>.md, made by Tinfoil's attested reader
//                              →  the part is replaced by a synthetic NOTE naming the files (codeAttachments.js);
//                                 an image also stays in the message, for a model that can see it
//
// The agent then opens the text copy with its read tool; the session carries a rule allowing reads in ITS folder (and only
// there), so that asks nothing. The page gets a saved file back through the connector's own route (serveAttachment).
// Bounded (security review): a file, a session and the whole folder have caps; nothing is written or read through a link;
// a different file under an existing name is refused, never swapped in.
import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, existsSync, readFileSync, statSync, lstatSync, readdirSync, rmSync, chmodSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve, sep } from 'node:path'
import { stagedFileName, attachmentNote, needsTextCopy, validAttachmentRef, mimeForFile } from '../spaces/public/codeAttachments.js'

export const ATTACH_ROOT = process.env.WITBITZ_CODE_ATTACHMENTS || join(homedir(), '.witbitz', 'code', 'attachments')
export const MAX_FILE_BYTES = 25 * 1024 * 1024
export const MAX_SESSION_BYTES = 200 * 1024 * 1024
export const MAX_ROOT_BYTES = 2 * 1024 * 1024 * 1024 // every session together — a secret-holder cannot fill the disk by inventing sessions
export const MAX_SERVE_BYTES = 20 * 1024 * 1024 // base64 in one relay message stays under its 32 MiB reassembly cap
const SESSION_RE = /^[A-Za-z0-9_-]{1,128}$/

/** Reads in THIS session's attachments folder are allowed, nothing else. Measured (opencode 1.18.30): the rule removes the
 *  ask for that folder, while a same-prefix sibling (<session>-evil/), another session's folder and the root still ask. */
export const attachmentRule = (root, sessionID) => ({ permission: 'external_directory', pattern: `${root}/${sessionID}/*`, action: 'allow' })

const refuse = (status, message) => ({ error: { status, message } })
const parseDataUrl = (url) => {
  const m = /^data:([^;,]*)(?:;[^,]*?)?;base64,(.*)$/s.exec(String(url || ''))
  return m ? { mime: m[1] || 'application/octet-stream', b64: m[2] } : null
}
const folderBytes = (dir) => { try { return readdirSync(dir).reduce((n, f) => n + lstatSync(join(dir, f)).size, 0) } catch { return 0 } }
const rootBytes = (root) => { try { return readdirSync(root).reduce((n, s) => n + folderBytes(join(root, s)), 0) } catch { return 0 } }
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const isLink = (p) => { try { return lstatSync(p).isSymbolicLink() } catch { return false } }

/**
 * Save the files in one turn's body and return `{body, entries}` with the note in their place — or `null` when there is
 * nothing to save, or `{error: {status, message}}` to refuse the turn. `readText({kind, mime, b64, name})` → text is the
 * Tinfoil reader (null when this computer has no key). Never changes the body it was given.
 */
export async function stageMessageBody(body, { sessionID, root = ATTACH_ROOT, readText = null, maxFileBytes = MAX_FILE_BYTES, maxSessionBytes = MAX_SESSION_BYTES, maxRootBytes = MAX_ROOT_BYTES } = {}) {
  const parts = Array.isArray(body && body.parts) ? body.parts : []
  const files = parts.map((p, i) => ({ p, i, d: p && p.type === 'file' ? parseDataUrl(p.url) : null })).filter((x) => x.d)
  if (!files.length) return null
  if (!SESSION_RE.test(String(sessionID || ''))) return refuse(400, 'not a session id')
  const dir = join(root, sessionID)
  if (isLink(root) || isLink(dir)) return refuse(400, 'the attachments folder is a link — refusing to write through it')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const entries = []
  const drop = new Set()
  let used = folderBytes(dir)
  let all = rootBytes(root)
  for (const { p, i, d } of files) {
    const bytes = Buffer.from(d.b64, 'base64')
    const name = String(p.filename || 'file')
    if (bytes.length > maxFileBytes) return refuse(413, `${name} is over ${Math.round(maxFileBytes / 1048576)} MB — too large to attach`)
    const hash = sha256(bytes)
    const file = stagedFileName(hash, name)
    const path = join(dir, file)
    if (existsSync(path) || isLink(path)) {
      // Same name = same first 8 hex of the hash: it is this file again — unless 32 bits collided (or a link sits there).
      if (isLink(path) || sha256(readFileSync(path)) !== hash) return refuse(409, `a different file saved as ${file} is already in this session — rename it and attach it again`)
    } else {
      if (used + bytes.length > maxSessionBytes) return refuse(413, `this session's attachments are over ${Math.round(maxSessionBytes / 1048576)} MB — start a new session to attach more`)
      if (all + bytes.length > maxRootBytes) return refuse(413, `saved attachments on this computer are over ${Math.round(maxRootBytes / 1073741824)} GB — delete old sessions to attach more`)
      try { writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' }) } catch (e) {
        if (!(e && e.code === 'EEXIST') || sha256(readFileSync(path)) !== hash) return refuse(409, `a different file saved as ${file} is already in this session — rename it and attach it again`)
      }
      used += bytes.length
      all += bytes.length
    }
    const mime = String(p.mime || d.mime || '').toLowerCase()
    const entry = { name, size: bytes.length, path }
    if (mime.startsWith('image/')) entry.inline = true
    else drop.add(i)
    if (needsTextCopy(mime, name)) {
      const copy = `${path}.md`
      if (existsSync(copy)) entry.copy = copy
      else if (!readText) entry.noCopy = 'no Tinfoil key on this computer'
      else {
        try {
          const text = String(await readText({ kind: 'file', mime, b64: d.b64, name }) || '').trim()
          if (!text) throw new Error('no readable text in it')
          writeFileSync(copy, text + '\n', { mode: 0o600, flag: 'wx' })
          entry.copy = copy
        } catch (e) { entry.noCopy = `Tinfoil could not read it: ${String((e && e.message) || e).slice(0, 160)}` }
      }
    }
    entries.push(entry)
  }
  const kept = parts.filter((_, i) => !drop.has(i))
  return { body: { ...body, parts: [...kept, { type: 'text', text: attachmentNote(entries), synthetic: true }] }, entries }
}

/** One staged file (or its text copy) for the page: `{st, b}` in the connector's reply shape. */
export function serveAttachment({ root = ATTACH_ROOT, session, file, maxBytes = MAX_SERVE_BYTES }) {
  if (!validAttachmentRef(session, file)) return { st: 400, b: JSON.stringify({ error: 'not an attachment' }) }
  const path = resolve(root, session, file)
  if (!existsSync(path)) return { st: 404, b: JSON.stringify({ error: 'that attachment is no longer on this computer' }) }
  // By REAL path: a link anywhere under the folder (the session folder, or the file) must not lead the read elsewhere.
  let real = ''
  try { real = realpathSync(path) } catch { return { st: 404, b: JSON.stringify({ error: 'that attachment is no longer on this computer' }) } }
  if (real !== join(realpathSync(root), session, file) || !real.startsWith(realpathSync(root) + sep)) return { st: 400, b: JSON.stringify({ error: 'not an attachment' }) }
  const size = statSync(path).size
  if (size > maxBytes) return { st: 413, b: JSON.stringify({ error: `the file is over ${Math.round(maxBytes / 1048576)} MB — too large to send to the phone` }) }
  return { st: 200, b: JSON.stringify({ name: file.slice(9), mime: mimeForFile(file), size, b64: readFileSync(path).toString('base64') }) }
}

/** A session was deleted: its files go with it. */
export function removeSessionAttachments(root = ATTACH_ROOT, sessionID) {
  if (!SESSION_RE.test(String(sessionID || ''))) return
  rmSync(join(root, sessionID), { recursive: true, force: true })
}

/** At start-up: session folders nothing was saved into for `days` are removed. Returns how many. */
export function pruneAttachments(root = ATTACH_ROOT, { days = 30, now = Date.now() } = {}) {
  let names
  try { names = readdirSync(root) } catch { return 0 }
  let n = 0
  for (const s of names) {
    if (!SESSION_RE.test(s)) continue
    try { if (statSync(join(root, s)).mtimeMs < now - days * 86_400_000) { rmSync(join(root, s), { recursive: true, force: true }); n++ } } catch { /* raced away */ }
  }
  return n
}
