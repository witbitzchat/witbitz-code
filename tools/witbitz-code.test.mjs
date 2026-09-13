// The single-file witbitz-code download (tools/build-witbitz-code.sh → spaces/public/downloads/witbitz-code.mjs).
// The committed file must be exactly what the sources build to — it ships under the signed build certificate, so a stale
// copy would certify old code — and it must run with nothing but Node.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const ROOT = new URL('..', import.meta.url).pathname
const SHIPPED = join(ROOT, 'spaces/public/downloads/witbitz-code.mjs')

test('the shipped witbitz-code.mjs is exactly what the current sources build to', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wbc-'))
  try {
    const out = join(dir, 'witbitz-code.mjs')
    execFileSync('bash', [join(ROOT, 'tools/build-witbitz-code.sh'), out], { cwd: ROOT, stdio: 'pipe' })
    assert.ok(readFileSync(out).equals(readFileSync(SHIPPED)), 'stale download — run: bash tools/build-witbitz-code.sh')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('it runs standalone: help, version, and status with no pairing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wbc-run-'))
  try {
    const env = { ...process.env, WITBITZ_CODE_PAIRINGS: join(dir, 'none.json'), HOME: dir }
    const run = (...a) => execFileSync(process.execPath, [SHIPPED, ...a], { cwd: dir, env, encoding: 'utf8' })
    assert.match(run('--help'), /pair \[--name/)
    assert.match(run('version'), /^\d+\.\d+\.\d+/)
    assert.match(run('status'), /not paired/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('serve --port serves only the pairings pointed at that OpenCode (two instances never answer the same channel)', async () => {
  process.env.WITBITZ_CODE_IMPORT = '1'
  const { pairingsForPort } = await import('./witbitz-code.mjs')
  const P = [{ name: 'mine', opencodeUrl: 'http://127.0.0.1:4096' }, { name: 'friend', opencodeUrl: 'http://127.0.0.1:4097' }, { name: 'default' }]
  assert.deepEqual(pairingsForPort(P, 4096).map((p) => p.name), ['mine', 'default'])
  assert.deepEqual(pairingsForPort(P, 4097).map((p) => p.name), ['friend'])
  assert.deepEqual(pairingsForPort(P, 5000), [])
})
