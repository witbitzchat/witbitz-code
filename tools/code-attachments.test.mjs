// code-attachments.mjs — the connector saves the files a Code message carries and swaps in a note (docs/code-attachments.md).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, statSync, existsSync, readdirSync, utimesSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { stageMessageBody, serveAttachment, removeSessionAttachments, pruneAttachments, attachmentRule } from './code-attachments.mjs'
import { parseAttachmentNote } from '../spaces/public/codeAttachments.js'

const XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
const dataUrl = (mime, text) => `data:${mime};base64,${Buffer.from(text).toString('base64')}`
const root = () => mkdtempSync(join(tmpdir(), 'wb-att-'))
const turn = (parts) => ({ model: { providerID: 'trustedrouter', modelID: 'deepseek/deepseek-v4-flash' }, agent: 'build', parts })

test('a message with no files is left alone', async () => {
  assert.equal(await stageMessageBody(turn([{ type: 'text', text: 'hi' }]), { sessionID: 'ses_a', root: root() }), null)
  assert.equal(await stageMessageBody(turn([{ type: 'file', mime: 'image/png', url: 'file:///x.png' }]), { sessionID: 'ses_a', root: root() }), null, 'a file:// part is not bytes to save')
})

test('an Excel file is saved (owner-only), replaced by a note, and gets a Tinfoil text copy', async () => {
  const dir = root()
  const asked = []
  const readText = async (item) => { asked.push(item); return '| Quarter | Revenue |\n| Q3 | ZUCCHINI-771 |' }
  const out = await stageMessageBody(turn([{ type: 'text', text: 'What was Q3?' }, { type: 'file', mime: XLSX, filename: 'budget.xlsx', url: dataUrl(XLSX, 'PK-fake-xlsx') }]), { sessionID: 'ses_a', root: dir, readText })
  assert.equal(out.body.parts.length, 2)
  assert.deepEqual(out.body.parts[0], { type: 'text', text: 'What was Q3?' })
  assert.equal(out.body.parts[1].synthetic, true)
  assert.equal(out.body.model.modelID, 'deepseek/deepseek-v4-flash', 'the rest of the turn is untouched')
  const [e] = parseAttachmentNote(out.body.parts[1].text)
  assert.equal(e.session, 'ses_a'); assert.match(e.file, /^[0-9a-f]{8}-budget\.xlsx$/); assert.equal(e.copy, `${e.file}.md`)
  const saved = join(dir, 'ses_a', e.file)
  assert.equal(readFileSync(saved, 'utf8'), 'PK-fake-xlsx')
  assert.equal(statSync(saved).mode & 0o777, 0o600)
  assert.equal(statSync(join(dir, 'ses_a')).mode & 0o777, 0o700)
  assert.match(readFileSync(`${saved}.md`, 'utf8'), /ZUCCHINI-771/)
  assert.equal(asked.length, 1); assert.equal(asked[0].kind, 'file'); assert.equal(asked[0].name, 'budget.xlsx')
  // the same file again (OpenCode re-sends nothing, but a person may attach it twice): no second Tinfoil call
  await stageMessageBody(turn([{ type: 'file', mime: XLSX, filename: 'budget.xlsx', url: dataUrl(XLSX, 'PK-fake-xlsx') }]), { sessionID: 'ses_a', root: dir, readText })
  assert.equal(asked.length, 1, 'the text copy is made once per file')
})

test('an image stays in the message (a model may see it) and is saved too; text files need no copy', async () => {
  const dir = root()
  const out = await stageMessageBody(turn([{ type: 'file', mime: 'image/png', filename: 'shot.png', url: dataUrl('image/png', 'PNGDATA') }, { type: 'file', mime: 'text/csv', filename: 'rows.csv', url: dataUrl('text/csv', 'a,b\n1,2') }]), { sessionID: 'ses_b', root: dir, readText: async () => { throw new Error('must not be called') } })
  assert.equal(out.body.parts[0].type, 'file', 'the image rides on')
  const notes = parseAttachmentNote(out.body.parts[out.body.parts.length - 1].text)
  assert.deepEqual(notes.map((n) => [n.name, n.inline, n.copy]), [['shot.png', true, ''], ['rows.csv', false, '']])
  assert.equal(out.body.parts.filter((p) => p.type === 'file').length, 1, 'the CSV is read from disk, not sent')
})

test('no Tinfoil key, or Tinfoil fails: the note says so — the turn still goes', async () => {
  const noKey = await stageMessageBody(turn([{ type: 'file', mime: 'application/pdf', filename: 'scan.pdf', url: dataUrl('application/pdf', '%PDF-1') }]), { sessionID: 'ses_c', root: root(), readText: null })
  assert.match(noKey.body.parts[0].text, /No text copy \(no Tinfoil key on this computer\)/)
  const broken = await stageMessageBody(turn([{ type: 'file', mime: 'application/pdf', filename: 'scan.pdf', url: dataUrl('application/pdf', '%PDF-2') }]), { sessionID: 'ses_c', root: root(), readText: async () => { throw new Error('document reader answered 500') } })
  assert.match(broken.body.parts[0].text, /No text copy \(Tinfoil could not read it: document reader answered 500\)/)
})

test('caps: a file over the limit, or a session over its quota, refuses the turn with a reason', async () => {
  const big = await stageMessageBody(turn([{ type: 'file', mime: XLSX, filename: 'huge.xlsx', url: dataUrl(XLSX, 'x'.repeat(2000)) }]), { sessionID: 'ses_d', root: root(), maxFileBytes: 1000 })
  assert.equal(big.error.status, 413); assert.match(big.error.message, /huge\.xlsx is over/)
  const dir = root()
  await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'a.txt', url: dataUrl('text/plain', 'y'.repeat(900)) }]), { sessionID: 'ses_e', root: dir, maxSessionBytes: 1500 })
  const over = await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'b.txt', url: dataUrl('text/plain', 'z'.repeat(900)) }]), { sessionID: 'ses_e', root: dir, maxSessionBytes: 1500 })
  assert.equal(over.error.status, 413); assert.match(over.error.message, /this session's attachments/)
  assert.equal((await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'c.txt', url: dataUrl('text/plain', 'q') }]), { sessionID: '../evil', root: dir })).error.status, 400)
})

test('a staged file is served back by name — only from its session folder', async () => {
  const dir = root()
  const out = await stageMessageBody(turn([{ type: 'file', mime: 'application/pdf', filename: 'scan.pdf', url: dataUrl('application/pdf', '%PDF-serve') }]), { sessionID: 'ses_f', root: dir, readText: async () => 'the text' })
  const [e] = parseAttachmentNote(out.body.parts[0].text)
  const got = serveAttachment({ root: dir, session: 'ses_f', file: e.file })
  assert.equal(got.st, 200)
  assert.deepEqual({ ...JSON.parse(got.b), b64: undefined }, { name: 'scan.pdf', mime: 'application/pdf', size: 10, b64: undefined })
  assert.equal(Buffer.from(JSON.parse(got.b).b64, 'base64').toString(), '%PDF-serve')
  assert.equal(JSON.parse(serveAttachment({ root: dir, session: 'ses_f', file: e.copy }).b).mime, 'text/markdown')
  assert.equal(serveAttachment({ root: dir, session: 'ses_f', file: '../../etc/passwd' }).st, 400)
  assert.equal(serveAttachment({ root: dir, session: 'ses_f', file: '00000000-nothing.pdf' }).st, 404)
  assert.equal(serveAttachment({ root: dir, session: 'ses_f', file: e.file, maxBytes: 4 }).st, 413)
})

test('a deleted session takes its files along; folders untouched for 30 days are pruned', () => {
  const dir = root()
  for (const s of ['ses_old', 'ses_new', 'ses_gone']) { mkdirSync(join(dir, s)); writeFileSync(join(dir, s, '00000000-a.txt'), 'a') }
  removeSessionAttachments(dir, 'ses_gone')
  assert.equal(existsSync(join(dir, 'ses_gone')), false)
  removeSessionAttachments(dir, '../ses_new') // not a session id: nothing happens
  const old = (Date.now() - 31 * 86_400_000) / 1000
  utimesSync(join(dir, 'ses_old'), old, old)
  assert.equal(pruneAttachments(dir, { days: 30 }), 1)
  assert.deepEqual(readdirSync(dir), ['ses_new'])
  assert.equal(pruneAttachments(join(dir, 'missing')), 0, 'no folder yet is not an error')
})

test('the permission rule lets the agent read ITS session\'s folder — only that one', () => {
  assert.deepEqual(attachmentRule('/home/u/.witbitz/code/attachments', 'ses_a'), { permission: 'external_directory', pattern: '/home/u/.witbitz/code/attachments/ses_a/*', action: 'allow' })
})

// ── the security review's findings (2026-09-13) ─────────────────────────────────────────────────────────────────────
test('REVIEW: nothing is written or served through a link — a session folder or a file that points elsewhere is refused', async () => {
  const dir = root()
  const outside = mkdtempSync(join(tmpdir(), 'wb-outside-'))
  writeFileSync(join(outside, 'secret.txt'), 'NOT-YOURS')
  symlinkSync(outside, join(dir, 'ses_link'))
  const staged = await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'a.txt', url: dataUrl('text/plain', 'x') }]), { sessionID: 'ses_link', root: dir })
  assert.equal(staged.error.status, 400)
  assert.equal(existsSync(join(outside, readdirSync(outside).find((f) => f !== 'secret.txt') || 'none')), false, 'nothing landed outside')
  writeFileSync(join(outside, '00000000-secret.txt'), 'NOT-YOURS')
  assert.equal(serveAttachment({ root: dir, session: 'ses_link', file: '00000000-secret.txt' }).st, 400, 'a linked session folder')
  mkdirSync(join(dir, 'ses_real'))
  symlinkSync(join(outside, 'secret.txt'), join(dir, 'ses_real', '11111111-secret.txt'))
  assert.equal(serveAttachment({ root: dir, session: 'ses_real', file: '11111111-secret.txt' }).st, 400, 'a linked file')
})

test('REVIEW: a different file under a name already saved is refused, never swapped in; the whole folder has a cap', async () => {
  const dir = root()
  const first = await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'a.txt', url: dataUrl('text/plain', 'one') }]), { sessionID: 'ses_x', root: dir })
  const [e] = parseAttachmentNote(first.body.parts[0].text)
  writeFileSync(join(dir, 'ses_x', e.file), 'swapped') // what a 32-bit collision would look like
  const again = await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'a.txt', url: dataUrl('text/plain', 'one') }]), { sessionID: 'ses_x', root: dir })
  assert.equal(again.error.status, 409)
  mkdirSync(join(dir, 'ses_big')); writeFileSync(join(dir, 'ses_big', '00000000-b.bin'), 'z'.repeat(1500))
  const full = await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'c.txt', url: dataUrl('text/plain', 'y'.repeat(600)) }]), { sessionID: 'ses_y', root: dir, maxRootBytes: 2000 })
  assert.equal(full.error.status, 413); assert.match(full.error.message, /on this computer are over/)
})

test('REVIEW: the name the model reads is capped', async () => {
  const out = await stageMessageBody(turn([{ type: 'file', mime: 'text/plain', filename: 'n'.repeat(5000) + '.txt', url: dataUrl('text/plain', 'x') }]), { sessionID: 'ses_n', root: root() })
  assert.ok(out.body.parts[0].text.split('\n')[1].length < 400)
})
