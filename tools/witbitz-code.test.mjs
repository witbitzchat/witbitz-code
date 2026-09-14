// The single-file witbitz-code download (tools/build-witbitz-code.sh → spaces/public/downloads/witbitz-code.mjs).
// The committed file must be exactly what the sources build to — it ships under the signed build certificate, so a stale
// copy would certify old code — and it must run with nothing but Node.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, chmodSync, mkdirSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const ROOT = new URL('..', import.meta.url).pathname
const SHIPPED = join(ROOT, 'spaces/public/downloads/witbitz-code.mjs')
/** The environment for running the shipped file — without the import switch the in-process test below sets. */
const runEnv = (extra = {}) => { const e = { ...process.env, ...extra }; delete e.WITBITZ_CODE_IMPORT; return e }

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
    assert.match(run('--help'), /setup \[--port <n>\][\s\S]*START HERE/)
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

test('setup asks questions, so it refuses to run without a terminal instead of hanging', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wbc-setup-'))
  try {
    const r = spawnSync(process.execPath, [SHIPPED, 'setup'], { cwd: dir, env: runEnv({ HOME: dir }), input: '', encoding: 'utf8' })
    assert.equal(r.status, 2)
    assert.match(r.stderr, /run it in a terminal/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('serve never hands the Tinfoil key to OpenCode (every shell the agent runs would inherit it), and routes TrustedRouter through the proxy', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wbc-env-'))
  try {
    // a fake `opencode` that records the environment it was started with, then exits (serve stops with it)
    const bin = join(dir, 'bin')
    mkdirSync(bin)
    const dump = join(dir, 'env.json')
    writeFileSync(join(bin, 'opencode'), `#!${process.execPath}\nrequire('fs').writeFileSync(${JSON.stringify(dump)}, JSON.stringify(process.env))\n`)
    chmodSync(join(bin, 'opencode'), 0o755)
    const port = 20000 + Math.floor(Math.random() * 20000)
    const pairings = join(dir, 'pairings.json')
    writeFileSync(pairings, JSON.stringify({ v: 1, pairings: [{ account: 't@example.invalid', idx: { room: 'r', mk: 'm' }, computerId: 'c', secret: randomBytes(32).toString('base64url'), name: 'test', relay: 'wss://127.0.0.1:1/none', opencodeUrl: `http://127.0.0.1:${port}` }] }))
    const env = runEnv({ HOME: dir, PATH: `${bin}:${process.env.PATH}`, WITBITZ_CODE_PAIRINGS: pairings, OPENCODE_ENV_FILE: join(dir, 'none.env'), TINFOIL_API_KEY: 'tk_tinfoil_must_not_reach_opencode', TRUSTEDROUTER_API_KEY: 'tk_tr_test_key' })
    spawnSync(process.execPath, [SHIPPED, 'serve', '--port', String(port)], { cwd: dir, env, encoding: 'utf8', timeout: 30_000 })
    const seen = JSON.parse(readFileSync(dump, 'utf8'))
    assert.equal(seen.TINFOIL_API_KEY, undefined)
    const config = JSON.parse(seen.OPENCODE_CONFIG_CONTENT)
    assert.equal(config.provider.trustedrouter.options.baseURL, `http://127.0.0.1:${port + 100}/v1`)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
