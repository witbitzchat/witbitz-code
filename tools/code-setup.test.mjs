// code-setup.mjs — `witbitz-code setup`: one command from a fresh download to a working Code section (the owner: "Can we
// make it easier"). The key checks follow the providers' measured answers (2026-09-14): TrustedRouter GET /v1/key is 401
// for a bad key; Tinfoil checks the model before the key, then 401 "Incorrect API key provided.".
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  KEY_PAGES, validKeyShape, checkTrustedRouterKey, checkTinfoilKey, withAuthKey, systemdUnit, launchdPlist, serviceName,
  launchdLabel, stableScript, serviceManager, runSetup, readLine,
} from './code-setup.mjs'
import { EventEmitter } from 'node:events'

const tmp = () => mkdtempSync(join(tmpdir(), 'wbc-setup-'))
const res = (status, body = {}) => ({ status, ok: status >= 200 && status < 300, json: async () => body })

test('a pasted key must look like a key — nothing that could break the file it is saved in', () => {
  assert.equal(validKeyShape('tk_abcdefgh12345678'), true)
  for (const bad of ['', 'short', 'has space inside', 'line\nbreak', 'x'.repeat(513), 'ключ-ключ-ключ']) assert.equal(validKeyShape(bad), false, JSON.stringify(bad))
})

test('TrustedRouter: 401 means rejected, 200 accepted, anything else is "could not tell"', async () => {
  const seen = []
  const f = (status) => async (url, init) => { seen.push({ url, auth: init.headers.authorization }); return res(status) }
  assert.deepEqual(await checkTrustedRouterKey('tk_good_key_123', { fetchImpl: f(200) }), { ok: true })
  assert.equal((await checkTrustedRouterKey('tk_bad_key_1234', { fetchImpl: f(401) })).ok, false)
  assert.equal((await checkTrustedRouterKey('tk_x_key_123456', { fetchImpl: f(503) })).ok, null)
  assert.equal((await checkTrustedRouterKey('tk_x_key_123456', { fetchImpl: async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }) } })).ok, null)
  assert.equal(seen[0].url, 'https://api.trustedrouter.com/v1/key')
  assert.equal(seen[0].auth, 'Bearer tk_good_key_123')
})

test('Tinfoil: an existing model and an empty conversation — 401 rejected, 400 accepted (nothing generated), 404 unknown', async () => {
  const calls = []
  const f = (status) => async (url, init = {}) => {
    calls.push({ url, body: init.body && JSON.parse(init.body) })
    if (url.endsWith('/models')) return res(200, { data: [{ id: 'old-model', deprecated: true }, { id: 'gemma4-31b' }] })
    return res(status)
  }
  assert.deepEqual(await checkTinfoilKey('tk_tinfoil_key_1', { fetchImpl: f(400) }), { ok: true })
  assert.deepEqual(calls[1].body, { model: 'gemma4-31b', messages: [], max_tokens: 1 }, 'the first model that is not deprecated')
  assert.equal((await checkTinfoilKey('tk_tinfoil_key_1', { fetchImpl: f(401) })).ok, false)
  assert.equal((await checkTinfoilKey('tk_tinfoil_key_1', { fetchImpl: f(404) })).ok, null)
})

test("OpenCode's credentials keep every other provider, and a file that is not JSON is never overwritten", () => {
  const merged = JSON.parse(withAuthKey(JSON.stringify({ anthropic: { type: 'oauth', refresh: 'r' } }), 'trustedrouter', 'tk_k_12345678'))
  assert.deepEqual(merged, { anthropic: { type: 'oauth', refresh: 'r' }, trustedrouter: { type: 'api', key: 'tk_k_12345678' } })
  assert.deepEqual(JSON.parse(withAuthKey('', 'trustedrouter', 'tk_k_12345678')), { trustedrouter: { type: 'api', key: 'tk_k_12345678' } })
  assert.throws(() => withAuthKey('{not json', 'trustedrouter', 'k'))
  assert.throws(() => withAuthKey('[1]', 'trustedrouter', 'k'))
})

test('the systemd unit quotes paths so a space, %, $ or quote cannot change the command', () => {
  const u = systemdUnit({ node: '/opt/my node/bin/node', script: '/home/u/100%/$HOME/"x".mjs', port: 4096, path: '/usr/bin:/opt/a b' })
  assert.match(u, /^ExecStart="\/opt\/my node\/bin\/node" "\/home\/u\/100%%\/\$\$HOME\/\\"x\\".mjs" serve --port 4096$/m)
  assert.match(u, /^Environment="PATH=\/usr\/bin:\/opt\/a b"$/m)
  assert.match(u, /^Restart=always$/m)
  assert.match(u, /^WantedBy=default.target$/m)
  assert.throws(() => systemdUnit({ node: 'n', script: 's', port: 'x; rm -rf ~', path: '' }))
  // a newline would start a new line of the unit — another directive — so it is refused, never escaped
  assert.throws(() => systemdUnit({ node: '/usr/bin/node', script: '/s.mjs', port: 4096, path: '/usr/bin\nExecStartPre=/bin/sh -c evil' }), /control character/)
  assert.throws(() => launchdPlist({ node: '/usr/bin/node', script: '/s\u0000.mjs', port: 4096, path: '/usr/bin', home: '/Users/a' }), /control character/)
  const svc = serviceManager({ platform: 'linux', home: tmp(), env: {}, run: () => ({ status: 0, stdout: '', stderr: '' }) })
  assert.deepEqual(svc.install({ node: '/usr/bin/node', script: '/nope.mjs', port: 4096, path: 'a\nb' }), { ok: false, why: 'a path contains a control character' }, 'reported, not thrown, and nothing written')
  assert.equal(serviceName(4096), 'witbitz-code')
  assert.equal(serviceName(4097), 'witbitz-code-4097', 'a second OpenCode gets its own service')
  assert.equal(launchdLabel(4097), 'chat.witbitz.code.4097')
})

test('the launchd agent escapes XML and logs to ~/Library/Logs', () => {
  const p = launchdPlist({ node: '/usr/local/bin/node', script: '/Users/a&b/<x>.mjs', port: 4096, path: '/usr/bin', home: '/Users/a&b' })
  assert.match(p, /<string>\/Users\/a&amp;b\/&lt;x&gt;.mjs<\/string>/)
  assert.match(p, /<key>Label<\/key><string>chat.witbitz.code<\/string>/)
  assert.match(p, /<key>StandardOutPath<\/key><string>\/Users\/a&amp;b\/Library\/Logs\/witbitz-code.log<\/string>/)
  assert.doesNotMatch(p, /<x>/)
})

test('Linux: install copies the download to a stable place, writes the unit and enables it; uninstall removes it', () => {
  const home = tmp()
  writeFileSync(join(home, 'dl.mjs'), '// v2')
  const calls = []
  const run = (cmd, args) => { calls.push([cmd, ...args].join(' ')); return { status: 0, stdout: args[1] === 'is-active' ? 'active\n' : '', stderr: '' } }
  const svc = serviceManager({ platform: 'linux', home, env: {}, run })
  assert.equal(svc.status(4096), 'not installed')
  assert.equal(svc.outdated(join(home, 'dl.mjs')), true, 'no copy yet')
  const r = svc.install({ node: '/usr/bin/node', script: join(home, 'dl.mjs'), port: 4096, path: '/usr/bin' })
  assert.deepEqual(r, { ok: true })
  const unit = readFileSync(join(home, '.config/systemd/user/witbitz-code.service'), 'utf8')
  assert.ok(unit.includes(`"${stableScript(home)}"`), 'the service runs the stable copy, not the download')
  assert.equal(readFileSync(stableScript(home), 'utf8'), '// v2')
  assert.equal(statSync(join(home, '.witbitz')).mode & 0o077, 0, 'the folder beside the pairings stays private')
  assert.deepEqual(calls, ['systemctl --user daemon-reload', 'systemctl --user enable witbitz-code', 'systemctl --user restart witbitz-code'])
  assert.equal(svc.status(4096), 'active')
  assert.equal(svc.outdated(join(home, 'dl.mjs')), false, 'same bytes')
  writeFileSync(join(home, 'dl.mjs'), '// v3')
  assert.equal(svc.outdated(join(home, 'dl.mjs')), true, 'a newer download')
  calls.length = 0
  assert.deepEqual(svc.uninstall(4096), { ok: true })
  assert.equal(existsSync(join(home, '.config/systemd/user/witbitz-code.service')), false)
  assert.deepEqual(calls.slice(0, 1), ['systemctl --user disable --now witbitz-code'])
  assert.deepEqual(svc.uninstall(4096), { ok: true, noop: true })
})

test('Linux without a systemd user session (WSL by default) says so instead of failing later', () => {
  const svc = serviceManager({ platform: 'linux', home: tmp(), env: {}, run: () => ({ status: 1, stdout: '', stderr: 'Failed to connect to bus' }) })
  assert.equal(svc.available(), false)
  assert.match(svc.unavailableWhy, /wsl\.conf/)
  assert.equal(serviceManager({ platform: 'win32', home: tmp() }).available(), false)
})

test('macOS: bootstrap into the login session; a failure is reported', () => {
  const home = tmp()
  writeFileSync(join(home, 'dl.mjs'), '//')
  const calls = []
  const svc = serviceManager({ platform: 'darwin', home, uid: 501, run: (cmd, args) => { calls.push([cmd, ...args].join(' ')); return { status: args[0] === 'bootstrap' ? 5 : 0, stdout: '', stderr: 'Bootstrap failed: 5: Input/output error' } } })
  const r = svc.install({ node: '/usr/local/bin/node', script: join(home, 'dl.mjs'), port: 4096, path: '/usr/bin' })
  assert.equal(r.ok, false)
  assert.match(r.why, /Bootstrap failed/)
  assert.ok(existsSync(join(home, 'Library/LaunchAgents/chat.witbitz.code.plist')))
  assert.deepEqual(calls, ['launchctl bootout gui/501/chat.witbitz.code', `launchctl bootstrap gui/501 ${join(home, 'Library/LaunchAgents/chat.witbitz.code.plist')}`])
})

// ── the walk-through, with fakes ───────────────────────────────────────────────────────────────────────────────────────

function fakeSetup(over = {}) {
  const said = []
  const answers = [...(over.answers || [])]
  const secrets = [...(over.secrets || [])]
  const state = { opencode: false, pairings: [], tr: false, tinfoil: '', listening: false, service: 'not installed', installs: [], restarts: 0, served: false, npm: 0, ...over.state }
  const d = {
    io: { say: (m) => said.push(m), ask: async (q) => { said.push(q); return answers.shift() ?? '' }, secret: async (q) => { said.push(q); return secrets.shift() ?? '' } },
    port: 4096,
    findOpenCode: () => (state.opencode ? '/usr/bin/opencode' : ''),
    installOpenCode: () => { state.npm++; state.opencode = over.npmWorks !== false; return state.opencode },
    pairings: () => state.pairings,
    pair: async () => { if (over.pairWorks !== false) state.pairings = [{ name: 'laptop', account: 'a@example.com' }] },
    hasTrustedRouter: () => state.tr,
    saveTrustedRouterKey: (k) => { state.trKey = k; state.tr = true },
    checkTrustedRouter: async (k) => (over.trCheck ? over.trCheck(k) : { ok: true }),
    tinfoilKey: () => state.tinfoil,
    saveTinfoilKey: (k) => { state.tinfoil = k },
    checkTinfoil: async () => ({ ok: true }),
    isListening: async () => { const v = typeof state.listening === 'function' ? state.listening() : state.listening; return v },
    service: {
      kind: 'systemd', available: () => over.serviceAvailable !== false, unavailableWhy: 'no systemd user session',
      status: () => state.service, outdated: () => !!over.outdated,
      install: (a) => { state.installs.push(a); state.service = 'active'; return { ok: true } },
      restart: () => { state.restarts++; return true },
      logsHint: () => 'journalctl --user -u witbitz-code -f', extraHint: 'It starts when you log in.',
    },
    serviceArgs: { node: '/usr/bin/node', script: '/dl/witbitz-code.mjs', path: '/usr/bin' },
    bundled: over.bundled !== false,
    serveHere: async () => { state.served = true },
  }
  return { d, said, state, text: () => said.join('\n') }
}

test('a brand-new computer: installs OpenCode, pairs, retries a rejected key, skips Tinfoil, starts in the background', async () => {
  let tries = 0
  const f = fakeSetup({ answers: ['', ''], secrets: ['tk_wrong_key_0001', 'tk_right_key_0002', ''], trCheck: async () => (++tries === 1 ? { ok: false, why: 'TrustedRouter rejected this key' } : { ok: true }) })
  const r = await runSetup(f.d)
  assert.deepEqual({ ...r }, { opencode: true, paired: true, trustedrouter: true, tinfoil: false, running: 'service' })
  assert.equal(f.state.npm, 1)
  assert.equal(f.state.trKey, 'tk_right_key_0002', 'the rejected key is never saved')
  assert.equal(f.state.installs.length, 1)
  assert.equal(f.state.served, false)
  const t = f.text()
  assert.ok(t.includes(KEY_PAGES.trustedrouter) && t.includes(KEY_PAGES.tinfoil), 'links straight to both key pages')
  assert.match(t, /✖ TrustedRouter rejected this key/)
  assert.match(t, /Skipped — add it later with: node witbitz-code.mjs tinfoil-key/)
  assert.match(t, /Open Spaces → ☰ → Code/)
  assert.ok(!t.includes('tk_right_key_0002') && !t.includes('tk_wrong_key_0001'), 'no key is ever printed')
})

test('running it again on a finished computer asks nothing and restarts nothing', async () => {
  const f = fakeSetup({ state: { opencode: true, pairings: [{ name: 'laptop', account: 'a@example.com' }], tr: true, tinfoil: 'tk_saved', service: 'active', listening: true } })
  const r = await runSetup(f.d)
  assert.equal(r.running, 'service')
  assert.equal(f.said.filter((m) => /\[Y\/n\]|Paste|Press Enter/.test(m)).length, 0)
  assert.equal(f.state.restarts, 0)
  assert.equal(f.state.installs.length, 0)
  assert.match(f.text(), /✓ Already running in the background/)
})

test('a newly added TrustedRouter key restarts the running service; a newer download updates it', async () => {
  const added = fakeSetup({ secrets: ['tk_new_key_00001'], state: { opencode: true, pairings: [{ name: 'l' }], tinfoil: 'tk', service: 'active' } })
  await runSetup(added.d)
  assert.equal(added.state.restarts, 1)
  const newer = fakeSetup({ outdated: true, state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk', service: 'active' } })
  await runSetup(newer.d)
  assert.equal(newer.state.installs.length, 1)
  assert.match(newer.text(), /Updated the background service to this version/)
})

test('an OpenCode the person started themselves is named, and setup waits for it to close', async () => {
  let checks = 0
  const f = fakeSetup({ answers: ['', ''], state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk', listening: () => ++checks < 2 } })
  await runSetup(f.d)
  assert.match(f.text(), /Something is already running on 127\.0\.0\.1:4096/)
  assert.match(f.text(), /its TrustedRouter calls are not protected/)
  assert.equal(f.state.installs.length, 1)
  const stop = fakeSetup({ answers: ['s'], state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk', listening: true } })
  const r = await runSetup(stop.d)
  assert.equal(r.stopped, 'busy')
  assert.equal(stop.state.installs.length, 0)
})

test('no background start (WSL without systemd, or "n"): it runs in this window instead', async () => {
  const f = fakeSetup({ serviceAvailable: false, state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk' } })
  const r = await runSetup(f.d)
  assert.equal(r.running, 'here')
  assert.equal(f.state.served, true)
  assert.match(f.text(), /Background start is not available: no systemd user session/)
  const no = fakeSetup({ answers: ['n'], state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk' } })
  assert.equal((await runSetup(no.d)).running, 'here')
  assert.equal(no.state.installs.length, 0)
})

test('it stops with clear next steps when OpenCode cannot be installed or pairing does not finish', async () => {
  const oc = fakeSetup({ answers: [''], npmWorks: false })
  assert.equal((await runSetup(oc.d)).stopped, 'opencode')
  assert.match(oc.text(), /curl -fsSL https:\/\/opencode\.ai\/install \| bash/)
  const pair = fakeSetup({ pairWorks: false, state: { opencode: true } })
  assert.equal((await runSetup(pair.d)).stopped, 'pair')
  assert.match(pair.text(), /Pairing did not finish/)
})

test('three rejected keys: skipped, nothing saved', async () => {
  const f = fakeSetup({ secrets: ['tk_bad_000000001', 'tk_bad_000000002', 'tk_bad_000000003'], serviceAvailable: false, trCheck: async () => ({ ok: false, why: 'TrustedRouter rejected this key' }), state: { opencode: true, pairings: [{ name: 'l' }], tinfoil: 'tk' } })
  const r = await runSetup(f.d)
  assert.equal(r.trustedrouter, false)
  assert.equal(f.state.trKey, undefined)
  assert.match(f.text(), /Skipped after three tries/)
})

// ── the key prompt, on a fake terminal ─────────────────────────────────────────────────────────────────────────────────

function fakeTTY() {
  const input = Object.assign(new EventEmitter(), { isTTY: true, raw: [], setRawMode(v) { this.raw.push(v) }, resume() {}, pause() {}, setEncoding() {} })
  const output = { text: '', write(s) { this.text += s } }
  return { input, output }
}

test('a hidden key is never echoed; a paste that ends in a newline submits, and backspace edits', async () => {
  const { input, output } = fakeTTY()
  const got = readLine('Key: ', { hidden: true, input, output })
  input.emit('data', 'tk_secret_value_1x')
  input.emit('data', '\u007f')
  input.emit('data', '2\r')
  assert.equal(await got, 'tk_secret_value_12')
  assert.equal(output.text, 'Key: \n', 'only the prompt and the newline — not a character of the key')
  assert.deepEqual(input.raw, [true, false], 'raw mode is switched back off')
  assert.equal(input.listenerCount('data'), 0)
})

test('a visible answer echoes as typed; control characters are ignored; a chunk with Enter in the middle stops there', async () => {
  const { input, output } = fakeTTY()
  const got = readLine('[Y/n] ', { input, output })
  input.emit('data', 'n\u001b\ro-more')
  assert.equal(await got, 'n')
  assert.equal(output.text, '[Y/n] n\n')
})
