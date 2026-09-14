// codeOutputs.js — the files a reply PRODUCED, previewed under it without asking (the owner: "I think the user should
// automatically see a preview"). The case that started it: an agent fixed a PDF, and asked to "upload it here" said a PDF
// cannot be shown in the chat — while its answer named the file's full path, in Hebrew, with spaces, in backticks.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { outputKind, replyOutputs, sensitivePath, validOutputPath, outputMime, MAX_OUTPUTS } from '../public/codeOutputs.js'

const V = JSON.parse(readFileSync(new URL('./codeOutputs.vectors.json', import.meta.url), 'utf8'))
const DIR = '/home/u/case 1'
const text = (t) => ({ type: 'text', text: t })
const tool = (name, filePath, status = 'completed') => ({ type: 'tool', tool: name, state: { status, input: { filePath } } })
const reply = (...parts) => [{ info: { role: 'assistant' }, parts }]

test('kinds (shared with the connectors): documents and pictures preview, office files and archives are chips, code is none', () => {
  for (const [path, kind] of V.kinds) assert.equal(outputKind(path), kind, path)
})

test('sensitive names never get a card, and the connectors refuse them (shared vectors)', () => {
  for (const [rel, yes] of V.sensitive) assert.equal(sensitivePath(rel), yes, rel)
})

test('a path the page may ask for: absolute, bounded, one line', () => {
  for (const [p, ok] of V.paths) assert.equal(validOutputPath(p), ok, JSON.stringify(p))
  assert.equal(validOutputPath('/' + 'a'.repeat(4096)), false, 'over 4096 characters')
})

test('the measured case: a Hebrew path with spaces in backticks, in the answer — one PDF card', () => {
  const msgs = reply(text('הקובץ עודכן:\n`/home/u/תיקייה 1/דוח מסכם - גרסה 2.pdf`\n\nשיניתי את הכותרות.'))
  assert.deepEqual(replyOutputs(msgs, { directory: '/home/u/תיקייה 1' }), [{ path: '/home/u/תיקייה 1/דוח מסכם - גרסה 2.pdf', kind: 'pdf', source: 'named' }])
})

test('a path written WITHOUT backticks in a folder whose name has a space is found whole — not cut at the space', () => {
  const msgs = reply(text('Wrote /home/u/תיקייה 1/out/report.pdf and out/summary.md, plus /home/u/תיקייה 1/דוח מסכם.pdf.'))
  assert.deepEqual(replyOutputs(msgs, { directory: '/home/u/תיקייה 1' }).map((o) => o.path), [
    '/home/u/תיקייה 1/out/report.pdf', '/home/u/תיקייה 1/דוח מסכם.pdf', '/home/u/תיקייה 1/out/summary.md',
  ])
})

test('the measured miss: a file named in the ANSWER with a space in backticks is found; names in the narration between steps are not', () => {
  // The owner's "something went wrong": the answer said the report was written to `דוח מסכם.pdf` (made with cp — no
  // write tool), and the cards showed min.html and min.pdf — a test in /tmp the narration mentioned — "not on the computer".
  const dir = '/home/u/תיקייה 2'
  const msgs = reply(
    tool('bash', ''),
    text('Without the @font-face, it\'s 1 page and no blank. The min.html has no @font-face — let me check the min.pdf text.'),
    tool('bash', ''),
    text('Done. The report is written to the PDF.\n\nנכתב לקובץ `דוח מסכם.pdf` בתיקייה.'),
  )
  assert.deepEqual(replyOutputs(msgs, { directory: dir }), [{ path: `${dir}/דוח מסכם.pdf`, kind: 'pdf', source: 'named' }])
  const commands = reply(text('Run `soffice --convert-to pdf a.pdf`, `cd out && ls b.pdf`, `cat x.csv | head`, `OUT=c.pdf make` or `rm *.png`.'))
  assert.deepEqual(replyOutputs(commands, { directory: dir }), [], 'a command in backticks is still not a file')
})

test('files the turn wrote or edited come first; a named relative path resolves in the session folder; each file once', () => {
  const msgs = reply(
    tool('write', `${DIR}/out/report.pdf`),
    tool('edit', `${DIR}/src/app.ts`), // code: no card
    tool('read', `${DIR}/in/source.pdf`), // only read: not a result
    tool('write', `${DIR}/draft.md`, 'error'), // failed: nothing was written
    text('Wrote `out/report.pdf` and a chart at out/chart.png. Also see ./notes/summary.md, and the data: out/q3.csv.'),
  )
  assert.deepEqual(replyOutputs(msgs, { directory: DIR }), [
    { path: `${DIR}/out/report.pdf`, kind: 'pdf', source: 'wrote' },
    { path: `${DIR}/out/chart.png`, kind: 'image', source: 'named' },
    { path: `${DIR}/notes/summary.md`, kind: 'text', source: 'named' },
    { path: `${DIR}/out/q3.csv`, kind: 'table', source: 'named' },
  ])
})

test('never a card: code, home-relative or climbing paths, secrets, URLs, the user\'s own prompt; and a handful at most', () => {
  const msgs = [
    { info: { role: 'user' }, parts: [text('look at /home/u/case 1/brief.pdf')] },
    ...reply(text('See `~/Downloads/x.pdf`, `../elsewhere/y.pdf`, `/home/u/case 1/.env`, `backup/credentials.pdf`, https://example.com/z.pdf, `src/index.ts`.')),
  ]
  assert.deepEqual(replyOutputs(msgs, { directory: DIR }), [])
  const many = reply(text(Array.from({ length: 12 }, (_, i) => `\`out/page-${i}.png\``).join(' ')))
  assert.equal(replyOutputs(many, { directory: DIR }).length, MAX_OUTPUTS)
})

test('only inside the session folder — the connector serves nothing else, so a card there would only ever fail', () => {
  const msgs = reply(text('`out/a.pdf` and `/tmp/b.pdf` and `/home/u/case 10/c.pdf`'))
  assert.deepEqual(replyOutputs(msgs, { directory: DIR }), [{ path: `${DIR}/out/a.pdf`, kind: 'pdf', source: 'named' }], 'a look-alike sibling folder is outside too')
  assert.deepEqual(replyOutputs(msgs, { directory: '' }), [], 'no folder known: no cards')
})

test('mime for a kind the page draws', () => {
  assert.equal(outputMime('/a/b.PDF'), 'application/pdf')
  assert.equal(outputMime('/a/b.jpeg'), 'image/jpeg')
  assert.equal(outputMime('/a/b.tsv'), 'text/tab-separated-values')
  assert.equal(outputMime('/a/b.docx'), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
})
