// tools/code-outputs.mjs — the connector serves a file a reply produced, for the page's preview (spaces/public/codeOutputs.js).
// Only a regular file of a kind the page shows, inside the SESSION's folder by real path, never a secret-looking name,
// never over the relay's size. Real folders and links here — the checks are about what the disk actually holds.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, readFileSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { serveOutput } from './code-outputs.mjs'

function tree() {
  const root = mkdtempSync(join(tmpdir(), 'wb-out-'))
  const dir = join(root, 'תיקייה 1'), outside = join(root, 'elsewhere')
  mkdirSync(join(dir, 'out'), { recursive: true }); mkdirSync(outside); mkdirSync(join(dir, '.git'))
  writeFileSync(join(dir, 'out', 'דוח - 14.pdf'), '%PDF-1.4 test')
  writeFileSync(join(dir, 'out', 'chart.png'), 'PNG')
  writeFileSync(join(dir, 'app.ts'), 'code')
  writeFileSync(join(dir, '.env'), 'KEY=1')
  writeFileSync(join(dir, '.git', 'x.pdf'), 'x')
  writeFileSync(join(dir, 'my-credentials.pdf'), 'x')
  writeFileSync(join(outside, 'secret.pdf'), 'outside')
  writeFileSync(join(outside, 'report.pdf'), 'outside')
  symlinkSync(join(outside, 'report.pdf'), join(dir, 'out', 'link-out.pdf'))
  symlinkSync(outside, join(dir, 'out', 'folder-out'))
  symlinkSync(join(dir, '.env'), join(dir, 'out', 'env.pdf'))
  symlinkSync(join(dir, 'out', 'chart.png'), join(dir, 'out', 'alias.png'))
  return { root, dir, outside }
}
const body = (r) => JSON.parse(r.b)

test('a PDF the reply wrote, in a Hebrew folder with spaces: its bytes, name, kind, size and when it last changed', () => {
  const { dir } = tree()
  const p = join(dir, 'out', 'דוח - 14.pdf')
  utimesSync(p, 1789000000, 1789000000)
  const r = serveOutput({ directory: dir, path: p })
  assert.equal(r.st, 200)
  const b = body(r)
  assert.deepEqual({ name: b.name, kind: b.kind, mime: b.mime, size: b.size, mtime: b.mtime }, { name: 'דוח - 14.pdf', kind: 'pdf', mime: 'application/pdf', size: 13, mtime: 1789000000000 })
  assert.equal(Buffer.from(b.b64, 'base64').toString(), '%PDF-1.4 test')
})

test('stat=true answers the same without the bytes — so the page can decide before pulling a big file over the relay', () => {
  const { dir } = tree()
  const r = serveOutput({ directory: dir, path: join(dir, 'out', 'chart.png'), stat: true })
  assert.equal(r.st, 200)
  assert.equal('b64' in body(r), false)
  assert.equal(body(r).size, 3)
})

test('refused: outside the folder, through a link out, a link to a secret, a secret-looking name, .git, code, a folder', () => {
  const { dir, outside } = tree()
  const cases = [
    [join(outside, 'secret.pdf'), 403],
    [join(dir, 'out', 'link-out.pdf'), 403],
    [join(dir, 'out', 'folder-out', 'report.pdf'), 403],
    [join(dir, 'out', 'env.pdf'), 403],
    [join(dir, 'my-credentials.pdf'), 403],
    [join(dir, '.git', 'x.pdf'), 403],
    [join(dir, 'app.ts'), 400],
    [join(dir, 'out') + '/', 400],
    [`${dir}/out/../../elsewhere/secret.pdf`, 403],
    [`${dir}10/x.pdf`, 403], // a look-alike sibling — refused by name, before the disk is even asked (no probing outside)
  ]
  for (const [path, st] of cases) {
    const r = serveOutput({ directory: dir, path })
    assert.equal(r.st, st, `${path} → ${r.st} ${r.b}`)
    assert.equal('b64' in body(r), false)
  }
})

test('a link INSIDE the folder to a file inside it is fine — it is the same file', () => {
  const { dir } = tree()
  assert.equal(serveOutput({ directory: dir, path: join(dir, 'out', 'alias.png') }).st, 200)
})

test('bad input: not absolute, a newline, no folder, a folder that is gone; missing file → 404', () => {
  const { dir, root } = tree()
  assert.equal(serveOutput({ directory: dir, path: 'out/chart.png' }).st, 400)
  assert.equal(serveOutput({ directory: dir, path: `${dir}/out/a\nb.png` }).st, 400)
  assert.equal(serveOutput({ directory: '', path: `${dir}/out/chart.png` }).st, 400)
  assert.equal(serveOutput({ directory: join(root, 'gone'), path: join(root, 'gone', 'a.png') }).st, 404)
  assert.equal(serveOutput({ directory: dir, path: join(dir, 'out', 'missing.pdf') }).st, 404)
})

test('over the relay\'s size: stat still answers (the card says so); the bytes are refused with 413', () => {
  const { dir } = tree()
  const p = join(dir, 'out', 'big.pdf')
  writeFileSync(p, Buffer.alloc(2048))
  assert.equal(serveOutput({ directory: dir, path: p, stat: true, maxBytes: 1024 }).st, 200)
  const r = serveOutput({ directory: dir, path: p, maxBytes: 1024 })
  assert.equal(r.st, 413)
  assert.match(body(r).error, /too large/)
  assert.equal(readFileSync(p).length, 2048)
})
