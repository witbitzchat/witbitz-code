// The CLI QR must reuse the app's encoder and round-trip: what we draw must decode back to the exact link. We can't run
// a camera in node, so assert the module matrix is stable and the SVG/ANSI cover the whole matrix with a quiet zone.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { qrModules } from '../spaces/public/qrRender.js'
import { qrAnsi, qrSvg } from './rc-qr.mjs'

const LINK = 'https://witbitz-spaces.pages.dev/space?room=sp-rc-abc123#mk=deadbeefdeadbeefdeadbeefdeadbeef?gate=email'

test('qrModules encodes the link (non-trivial matrix)', () => {
  const { size, isDark } = qrModules(LINK)
  assert.ok(size >= 21, 'a real QR is at least version 1 (21 modules)')
  let dark = 0
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (isDark(r, c)) dark++
  assert.ok(dark > size, 'the matrix has substantial dark content')
})

test('qrSvg draws one rect per dark module plus a white ground', () => {
  const { size, isDark } = qrModules(LINK)
  let dark = 0
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (isDark(r, c)) dark++
  const svg = qrSvg(LINK)
  assert.equal((svg.match(/<rect/g) || []).length, dark + 1, 'one rect per dark module + the background')
  assert.match(svg, /viewBox="0 0 \d+ \d+"/)
  assert.match(svg, /fill="#fff"/)
})

test('qrAnsi (large) renders every row with a quiet zone and resets colour', () => {
  const { size } = qrModules(LINK)
  const ansi = qrAnsi(LINK, { compact: false })
  const lines = ansi.split('\n')
  assert.equal(lines.length, size + 8, 'size + 4 quiet rows top and bottom')
  assert.match(ansi, /\x1b\[40m/); assert.match(ansi, /\x1b\[47m/); assert.match(ansi, /\x1b\[0m/)
})

/** Read a compact QR back the way a terminal draws it: each ▀ is the top module (foreground) over the bottom (background). */
function modulesOfCompact(ansi) {
  const rows = []
  for (const line of ansi.split('\n')) {
    const cells = [...line.matchAll(/\x1b\[(30|97);(40|107)m▀/g)]
    rows.push(cells.map((m) => m[1] === '30'), cells.map((m) => m[2] === '40'))
  }
  return rows
}

test('the compact terminal QR is a quarter of the size and holds exactly the matrix, quiet zone included', () => {
  const { size, isDark } = qrModules(LINK)
  const dim = size + 8
  const ansi = qrAnsi(LINK, { compact: true })
  assert.equal(ansi.split('\n').length, Math.ceil(dim / 2), 'two module rows per line')
  const grid = modulesOfCompact(ansi)
  assert.equal(grid[0].length, dim, 'one character per module across')
  for (let r = 0; r < dim; r++) for (let c = 0; c < dim; c++) {
    const want = r >= 4 && c >= 4 && r < 4 + size && c < 4 + size && isDark(r - 4, c - 4)
    assert.equal(grid[r][c], want, `module ${r},${c}`)
  }
  assert.ok(ansi.split('\n').every((l) => l.endsWith('\x1b[0m')), 'every line resets colour')
})

test('drawn the way a terminal draws it, the compact QR decodes back to the exact link (jsQR, the app\'s own scanner)', async () => {
  // vendor/jsQR.js is a UMD script and spaces/ is "type": "module" — evaluate it with a CommonJS module object
  const { readFileSync } = await import('node:fs')
  const mod = { exports: {} }
  new Function('module', 'exports', readFileSync(new URL('../spaces/public/vendor/jsQR.js', import.meta.url), 'utf8'))(mod, mod.exports)
  const jsQR = mod.exports.default || mod.exports
  for (const link of [LINK, 'wbzlink1:0123456789abcdef0123456789abcdef.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEf']) {
    const grid = modulesOfCompact(qrAnsi(link, { compact: true }))
    const CW = 8, CH = 16 // a terminal cell: twice as tall as wide
    const w = grid[0].length * CW, h = Math.ceil(grid.length / 2) * CH
    const px = new Uint8ClampedArray(w * h * 4)
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
      const row = Math.floor(y / CH) * 2 + (y % CH < CH / 2 ? 0 : 1)
      const v = grid[row] && grid[row][Math.floor(x / CW)] ? 0 : 255
      const i = (y * w + x) * 4; px[i] = px[i + 1] = px[i + 2] = v; px[i + 3] = 255
    }
    const got = jsQR(px, w, h)
    assert.ok(got, 'it scans')
    assert.equal(got.data, link)
  }
})
