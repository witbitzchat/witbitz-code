// spaces/public/code.sh — the one line the Code guide gives: `curl -fsSL https://app.witbitz.chat/code.sh | bash` (the
// owner: the curl -o download "is really complicated for a non technical user"). It must never use a file that does not
// match the app's asset manifest, and must say what to do when Node.js is missing. Run detached (no terminal), so the
// script's hand-off to `setup` falls back to printing the command instead of waiting on a keyboard.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, existsSync, readdirSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'

const BASH = execFileSync('bash', ['-c', 'command -v bash'], { encoding: 'utf8' }).trim() // absolute: one test empties PATH
const SCRIPT = new URL('../spaces/public/code.sh', import.meta.url).pathname
const FILE = '#!/usr/bin/env node\nconsole.log("witbitz-code stand-in", process.argv.slice(2).join(" "))\n'
const sha = (s) => createHash('sha256').update(s).digest('hex')

async function app({ manifestHash = sha(FILE), file = FILE } = {}) {
  const srv = createServer((req, res) => {
    if (req.url === '/downloads/witbitz-code.mjs') return res.end(file)
    if (req.url === '/assets-manifest.json') return res.end(JSON.stringify({ files: { 'downloads/witbitz-code.mjs': manifestHash } }))
    res.statusCode = 404; res.end()
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close() }
}

function run(env, args = []) {
  return new Promise((resolve) => {
    const child = spawn(BASH, [SCRIPT, ...args], { env: { ...process.env, ...env }, detached: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { out += c })
    child.on('close', (code) => resolve({ code, out }))
  })
}

test('it downloads, checks the file against the manifest, saves it, and names the next command', async (t) => {
  const a = await app(); t.after(a.close)
  const dest = join(mkdtempSync(join(tmpdir(), 'wbc-inst-')), 'witbitz-code.mjs')
  const r = await run({ WITBITZ_APP: a.url, WITBITZ_CODE_FILE: dest })
  assert.equal(r.code, 0, r.out)
  assert.equal(readFileSync(dest, 'utf8'), FILE)
  assert.equal(statSync(dest).mode & 0o777, 0o644)
  assert.match(r.out, /✓ Downloaded witbitz-code and checked it against the app's manifest \(sha256 [0-9a-f]{16}…\)/)
  assert.match(r.out, new RegExp(`Now run:  node "${dest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}" setup`))
  assert.deepEqual(readdirSync(dirname(dest)), ['witbitz-code.mjs'], 'no temporary download is left behind')
})

test('a file that does not match the manifest is never used — nothing is saved, and it says to retry', async (t) => {
  const a = await app({ manifestHash: sha('something else') }); t.after(a.close)
  const dir = mkdtempSync(join(tmpdir(), 'wbc-inst-'))
  const dest = join(dir, 'witbitz-code.mjs')
  const r = await run({ WITBITZ_APP: a.url, WITBITZ_CODE_FILE: dest })
  assert.equal(r.code, 1)
  assert.match(r.out, /does not match the app's manifest, so it was not used/)
  assert.equal(existsSync(dest), false)
  assert.deepEqual(readdirSync(dir), [], 'the partial download is removed')
})

test('an older file already in place is kept when the new one fails the check', async (t) => {
  const good = await app(); t.after(good.close)
  const dest = join(mkdtempSync(join(tmpdir(), 'wbc-inst-')), 'witbitz-code.mjs')
  assert.equal((await run({ WITBITZ_APP: good.url, WITBITZ_CODE_FILE: dest })).code, 0)
  const bad = await app({ file: 'tampered', manifestHash: sha(FILE) }); t.after(bad.close)
  assert.equal((await run({ WITBITZ_APP: bad.url, WITBITZ_CODE_FILE: dest })).code, 1)
  assert.equal(readFileSync(dest, 'utf8'), FILE)
})

test('no manifest entry (or no manifest) is a failed check, not a pass', async (t) => {
  const a = await app({ manifestHash: '' }); t.after(a.close)
  const dest = join(mkdtempSync(join(tmpdir(), 'wbc-inst-')), 'witbitz-code.mjs')
  const r = await run({ WITBITZ_APP: a.url, WITBITZ_CODE_FILE: dest })
  assert.equal(r.code, 1)
  assert.equal(existsSync(dest), false)
})

test('without Node.js it says where to get it, before downloading anything', async () => {
  const dest = join(mkdtempSync(join(tmpdir(), 'wbc-inst-')), 'witbitz-code.mjs')
  const r = await run({ PATH: '/nonexistent', WITBITZ_APP: 'http://127.0.0.1:9', WITBITZ_CODE_FILE: dest })
  assert.equal(r.code, 1)
  assert.match(r.out, /needs Node\.js 22 or newer, and this computer does not have Node\.js/)
  assert.match(r.out, /https:\/\/nodejs\.org/)
  assert.equal(existsSync(dest), false)
})

test('`bash -s uninstall` hands over to uninstall instead of setup; other words still go to setup', async (t) => {
  const a = await app(); t.after(a.close)
  const dest = join(mkdtempSync(join(tmpdir(), 'wbc-inst-')), 'witbitz-code.mjs')
  const r = await run({ WITBITZ_APP: a.url, WITBITZ_CODE_FILE: dest }, ['uninstall'])
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /Now run:  node ".*witbitz-code\.mjs" uninstall$/m)
  const other = await run({ WITBITZ_APP: a.url, WITBITZ_CODE_FILE: dest }, ['--port', '4097'])
  assert.match(other.out, /Now run:  node ".*witbitz-code\.mjs" setup$/m)
})
