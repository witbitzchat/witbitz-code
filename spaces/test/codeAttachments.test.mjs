// codeAttachments.js — the note the connector puts in a message in place of a file (docs/code-attachments.md), shared by the
// connector (writes it) and the page (turns it into chips). Measured on opencode 1.18.30 (2026-09-13): OpenCode refuses an
// Excel or Word file part for every model; a staged file's Tinfoil text copy, named in a synthetic line, was read by Kimi K3
// unprompted, while DeepSeek V4 Flash first reached for the shell on the ORIGINAL — so the note says which file to open.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { safeName, stagedFileName, attachmentNote, parseAttachmentNote, validAttachmentRef, mimeForFile, formatSize, needsTextCopy } from '../public/codeAttachments.js'

test('a file name is made safe: no folders, no dot-files, no odd characters, a sane length', () => {
  assert.equal(safeName('budget.xlsx'), 'budget.xlsx')
  assert.equal(safeName('../../etc/passwd'), 'passwd')
  assert.equal(safeName('C:\\Users\\me\\Q3 plan (final).docx'), 'Q3 plan (final).docx')
  assert.equal(safeName('.env'), '_env')
  assert.equal(safeName('רבעון.xlsx'), '_.xlsx')
  assert.equal(safeName(''), 'file')
  assert.equal(safeName('x'.repeat(300) + '.pdf').length, 100)
  assert.ok(safeName('x'.repeat(300) + '.pdf').endsWith('.pdf'), 'the extension survives the cut')
})

test('the staged name is the content hash then the safe name', () => {
  assert.equal(stagedFileName('3f9a1c2e77aa', 'budget.xlsx'), '3f9a1c2e-budget.xlsx')
})

test('which files get a text copy: documents yes; images and text no', () => {
  for (const [mime, name] of [['application/pdf', 'a.pdf'], ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'b.xlsx'], ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'c.docx'], ['application/octet-stream', 'deck.pptx']]) assert.equal(needsTextCopy(mime, name), true, name)
  for (const [mime, name] of [['image/png', 'a.png'], ['text/plain', 'b.txt'], ['text/csv', 'c.csv'], ['application/json', 'd.json'], ['text/markdown', 'e.md']]) assert.equal(needsTextCopy(mime, name), false, name)
})

const ROOT = '/home/u/.witbitz/code/attachments'
const ENTRIES = [
  { name: 'budget.xlsx', size: 6512, path: `${ROOT}/ses_abc/3f9a1c2e-budget.xlsx`, copy: `${ROOT}/ses_abc/3f9a1c2e-budget.xlsx.md` },
  { name: 'photo.png', size: 2_400_000, path: `${ROOT}/ses_abc/0a1b2c3d-photo.png`, inline: true },
  { name: 'scan.pdf', size: 90_000, path: `${ROOT}/ses_abc/deadbeef-scan.pdf`, noCopy: 'no Tinfoil key on this computer' },
]

test('the note tells the model where each file is and WHICH file to open', () => {
  const note = attachmentNote(ENTRIES)
  assert.match(note, /^The user attached files/)
  assert.match(note, /budget\.xlsx — 6\.4 KB — \/home\/u\/\.witbitz\/code\/attachments\/ses_abc\/3f9a1c2e-budget\.xlsx/)
  assert.match(note, /Its text — open THIS with the read tool, not the original: \/home\/u\/.+budget\.xlsx\.md/)
  assert.match(note, /photo\.png — 2\.3 MB — .+\n {2}Shown to you with this message\./)
  assert.match(note, /scan\.pdf — 87\.9 KB — .+\n {2}No text copy \(no Tinfoil key on this computer\)/)
})

test('the page reads the note back — and anything else is not a note', () => {
  assert.deepEqual(parseAttachmentNote(attachmentNote(ENTRIES)), [
    { name: 'budget.xlsx', size: '6.4 KB', session: 'ses_abc', file: '3f9a1c2e-budget.xlsx', copy: '3f9a1c2e-budget.xlsx.md', inline: false },
    { name: 'photo.png', size: '2.3 MB', session: 'ses_abc', file: '0a1b2c3d-photo.png', copy: '', inline: true },
    { name: 'scan.pdf', size: '87.9 KB', session: 'ses_abc', file: 'deadbeef-scan.pdf', copy: '', inline: false },
  ])
  assert.equal(parseAttachmentNote('What is in the pdf'), null)
  assert.equal(parseAttachmentNote('The user attached files, but this is just prose.'), null)
})

test('a request for a staged file names a session and a staged file — never a path', () => {
  assert.equal(validAttachmentRef('ses_abc', '3f9a1c2e-budget.xlsx'), true)
  assert.equal(validAttachmentRef('ses_abc', '3f9a1c2e-budget.xlsx.md'), true)
  for (const [s, f] of [['ses_abc', '../x'], ['ses_abc', '3f9a1c2e-a/b'], ['../ses', '3f9a1c2e-a'], ['ses_abc', 'budget.xlsx'], ['ses_abc', '3f9a1c2e-.hidden'], ['', '3f9a1c2e-a'], ['ses.abc', '3f9a1c2e-a']]) {
    assert.equal(validAttachmentRef(s, f), false, `${s} ${f}`)
  }
})

test('sizes read like a person wrote them; a served file gets a type from its name', () => {
  assert.deepEqual([formatSize(900), formatSize(6512), formatSize(2_400_000)], ['900 B', '6.4 KB', '2.3 MB'])
  assert.equal(mimeForFile('3f9a1c2e-scan.pdf'), 'application/pdf')
  assert.equal(mimeForFile('3f9a1c2e-budget.xlsx.md'), 'text/markdown')
  assert.equal(mimeForFile('3f9a1c2e-photo.JPG'), 'image/jpeg')
  assert.equal(mimeForFile('3f9a1c2e-thing.bin'), 'application/octet-stream')
})

// The Python connector (packages/witbitz-code-py attachments.py) is held to the same file.
test('the shared vectors still describe this module', async () => {
  const { readFileSync } = await import('node:fs')
  const m = await import('../public/codeAttachments.js')
  const v = JSON.parse(readFileSync(new URL('./codeAttachments.vectors.json', import.meta.url), 'utf8'))
  for (const [n, want] of v.safeName) assert.equal(m.safeName(n), want, n)
  for (const [h, n, want] of v.stagedFileName) assert.equal(m.stagedFileName(h, n), want)
  for (const [n, want] of v.formatSize) assert.equal(m.formatSize(n), want, String(n))
  assert.equal(m.attachmentNote(v.note.entries), v.note.text)
  assert.deepEqual(m.parseAttachmentNote(v.note.text), v.note.parsed)
  for (const t of v.notNotes) assert.equal(m.parseAttachmentNote(t), null)
  for (const [s, f, want] of v.validRef) assert.equal(m.validAttachmentRef(s, f), want, `${s} ${f}`)
  for (const [mime, n, want] of v.needsTextCopy) assert.equal(m.needsTextCopy(mime, n), want, n)
  for (const [f, want] of v.mimeForFile) assert.equal(m.mimeForFile(f), want, f)
  assert.equal(m.ATTACHMENT_ROUTE, v.route)
})
