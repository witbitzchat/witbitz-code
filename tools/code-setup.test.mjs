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
  launchdLabel, stableScript, serviceManager, runSetup, readLine, pairingPort, withPairingPort, withoutEnvKeys, withoutAuthKey,
  runUninstall, openCodeInstall, openCodeRemovalHint, withoutOpenCodePath, shellStartupFiles,
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
    port: over.port || 4096,
    portExplicit: !!over.portExplicit,
    findOpenCode: () => (state.opencode ? '/usr/bin/opencode' : ''),
    openCodeInstallPlans: () => over.plans ?? [{ kind: 'npm', label: 'with npm ("npm install -g opencode-ai")' }],
    installOpenCode: (kind) => { state.npm++; (state.tried ||= []).push(kind); state.opencode = (over.works ?? { npm: over.npmWorks !== false, installer: true })[kind]; return state.opencode },
    allPairings: () => state.pairings,
    portOf: pairingPort,
    pair: async (port) => {
      state.pairedFor = port
      if (over.pairWorks === false) return
      const url = over.pairKeepsPort ? state.pairings[0].opencodeUrl : `http://127.0.0.1:${port}`
      state.pairings = [...state.pairings.filter((p) => p.account !== 'a@example.com'), { name: 'laptop', account: 'a@example.com', opencodeUrl: url }]
    },
    movePairing: (p, to) => { state.pairings = state.pairings.map((x) => (x === p ? { ...x, opencodeUrl: `http://127.0.0.1:${to}` } : x)); state.moved = to },
    hasTrustedRouter: () => state.tr,
    saveTrustedRouterKey: (k) => { state.trKey = k; state.tr = true },
    checkTrustedRouter: async (k) => (over.trCheck ? over.trCheck(k) : { ok: true }),
    tinfoilKey: () => state.tinfoil,
    saveTinfoilKey: (k) => { state.tinfoil = k },
    checkTinfoil: async () => ({ ok: true }),
    isListening: async (port) => { state.checkedPort = port; return typeof state.listening === 'function' ? state.listening(port) : state.listening },
    portOwners: async () => (typeof over.owners === 'function' ? over.owners() : over.owners ?? []),
    stopProcess: async (pid) => { (state.stopped ||= []).push(pid); return true },
    freePort: async (from) => over.free ?? from,
    wsl: over.wsl ?? true,
    service: {
      kind: 'systemd', available: () => over.serviceAvailable !== false, unavailableWhy: 'no systemd user session',
      status: () => state.service, outdated: () => !!over.outdated,
      install: (a) => { state.installs.push(a); state.service = 'active'; return { ok: true } },
      restart: () => { state.restarts++; return true },
      installedPorts: () => [],
      logsHint: () => 'journalctl --user -u witbitz-code -f', extraHint: 'It starts when you log in.',
    },
    serviceArgs: { node: '/usr/bin/node', script: '/dl/witbitz-code.mjs', path: '/usr/bin' },
    bundled: over.bundled !== false,
    serveHere: async (port) => { state.served = port },
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

test('an OpenCode of the person\'s own on the port: setup names it and offers to stop it, then carries on', async () => {
  const SERVE = { pid: 777, cmd: 'opencode serve --port 4096' }
  const f = fakeSetup({ answers: ['', ''], owners: () => (f.state.stopped ? [] : [SERVE]), state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk', listening: () => !f.state.stopped } })
  await runSetup(f.d)
  assert.match(f.text(), /Already running on 127\.0\.0\.1:4096: opencode serve --port 4096 \(process 777\)/)
  assert.match(f.text(), /its TrustedRouter calls are not protected/)
  assert.match(f.text(), /Stop it now\? \[Y\/n\] — or type s to stop here/)
  assert.deepEqual(f.state.stopped, [777])
  assert.equal(f.state.installs.length, 1)
  assert.equal(f.state.installs[0].port, 4096)
  const stop = fakeSetup({ answers: ['s'], owners: [SERVE], state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk', listening: true } })
  const r = await runSetup(stop.d)
  assert.equal(r.stopped, 'busy')
  assert.equal(stop.state.installs.length, 0)
  assert.equal(stop.state.stopped, undefined)
})

test('no background start (WSL without systemd, or "n"): it runs in this window instead', async () => {
  const f = fakeSetup({ serviceAvailable: false, state: { opencode: true, pairings: [{ name: 'l' }], tr: true, tinfoil: 'tk' } })
  const r = await runSetup(f.d)
  assert.equal(r.running, 'here')
  assert.equal(f.state.served, 4096)
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

test('a key shows one * per character — never the key; a paste that ends in a newline submits, and backspace edits', async () => {
  const { input, output } = fakeTTY()
  const got = readLine('Key: ', { hidden: true, input, output })
  input.emit('data', 'tk_secret_value_1x')
  input.emit('data', '\u007f')
  input.emit('data', '2\r')
  assert.equal(await got, 'tk_secret_value_12')
  // the owner: "show at least that something was pasted like with *****"
  assert.equal(output.text, 'Key: ' + '*'.repeat(18) + '\b \b' + '*' + '\n', 'stars as it is pasted, one erased by backspace')
  assert.ok(!/[a-z0-9_]/.test(output.text.slice('Key: '.length)), 'not a character of the key')
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

// ── the owner's test: setup on another port, for a computer already paired for 4096 ─────────────────────────────────────

const PAIRED_4096 = { name: 'test-box', account: 'a@example.com', idx: { room: 'r1' }, computerId: 'c1', opencodeUrl: 'http://127.0.0.1:4096' }

test('setup --port 4097 on a computer paired for 4096: offers to move it — no second scan, and it runs on 4097', async () => {
  const f = fakeSetup({ port: 4097, portExplicit: true, answers: ['', ''], state: { opencode: true, pairings: [PAIRED_4096], tr: true, tinfoil: 'tk' } })
  const r = await runSetup(f.d)
  assert.equal(r.paired, true)
  assert.equal(f.state.moved, 4097)
  assert.equal(f.state.pairedFor, undefined, 'no QR')
  assert.match(f.text(), /"test-box" → a@example\.com is set up for OpenCode on port 4096\. Use port 4097 instead\?/)
  assert.match(f.text(), /✓ Paired: "test-box" → a@example\.com \(OpenCode on port 4097\)/)
  assert.equal(f.state.checkedPort, 4097)
  assert.equal(f.state.installs[0].port, 4097)
})

test('the same, answering no: the scan pairs for 4097 (an OpenCode asked for moves the account) and setup finds it', async () => {
  const f = fakeSetup({ port: 4097, portExplicit: true, answers: ['n', ''], state: { opencode: true, pairings: [PAIRED_4096], tr: true, tinfoil: 'tk' } })
  const r = await runSetup(f.d)
  assert.equal(f.state.pairedFor, 4097)
  assert.equal(r.paired, true)
  assert.doesNotMatch(f.text(), /Pairing did not finish/)
})

test('if a scan still leaves the pairing on another port, setup says which port — not "did not finish"', async () => {
  const f = fakeSetup({ port: 4097, portExplicit: true, pairKeepsPort: true, answers: ['n'], state: { opencode: true, pairings: [PAIRED_4096], tr: true, tinfoil: 'tk' } })
  const r = await runSetup(f.d)
  assert.equal(r.stopped, 'pair')
  assert.match(f.text(), /paired, but for OpenCode on another port \("laptop": 4096\)\. Run setup again with that port: node witbitz-code\.mjs setup --port 4096/)
  assert.doesNotMatch(f.text(), /Pairing did not finish/)
})

test('plain setup on a computer paired for 4097 uses 4097 — no QR, and the service and checks follow it', async () => {
  const f = fakeSetup({ answers: [''], state: { opencode: true, pairings: [{ ...PAIRED_4096, opencodeUrl: 'http://127.0.0.1:4097' }], tr: true, tinfoil: 'tk' } })
  await runSetup(f.d)
  assert.equal(f.state.pairedFor, undefined)
  assert.match(f.text(), /paired for OpenCode on port 4097 — using that port/)
  assert.equal(f.state.installs[0].port, 4097)
  const two = fakeSetup({ state: { opencode: true, pairings: [{ ...PAIRED_4096, opencodeUrl: 'http://127.0.0.1:4097' }, { ...PAIRED_4096, idx: { room: 'r2' }, opencodeUrl: 'http://127.0.0.1:4098' }], tr: true, tinfoil: 'tk' } })
  assert.equal((await runSetup(two.d)).stopped, 'ports')
  assert.match(two.text(), /ports 4097, 4098\. Run setup for the one you mean/)
})

test("the owner's test: 4096 is taken by a program that is not theirs (another WSL distro) — setup moves to a free port and continues", async () => {
  const f = fakeSetup({ answers: ['', ''], free: 4098, state: { opencode: true, pairings: [PAIRED_4096], tr: true, tinfoil: 'tk', listening: (p) => p === 4096 } })
  const r = await runSetup(f.d)
  assert.equal(r.stopped, undefined)
  assert.match(f.text(), /Port 4096 is taken by a program that is not yours — on WSL, another Linux distro on this computer shares its ports/)
  assert.match(f.text(), /Use port 4098 instead\? \[Y\/n\]/)
  assert.equal(f.state.moved, 4098, 'the pairing moves — no new scan')
  assert.equal(f.state.installs[0].port, 4098)
  assert.equal(f.state.stopped, undefined, 'nothing of anyone else is stopped')
  const no = fakeSetup({ answers: ['n'], free: 4098, wsl: false, state: { opencode: true, pairings: [PAIRED_4096], tr: true, tinfoil: 'tk', listening: (p) => p === 4096 } })
  const noText = () => no.text()
  assert.equal((await runSetup(no.d)).stopped, 'busy')
  assert.match(no.text(), /To use another port later: node witbitz-code\.mjs setup --port 4098/)
  assert.doesNotMatch(noText(), /WSL/, 'the WSL reason only on WSL')
})

test('a pairing is moved by account room and computer, pointed at 127.0.0.1; ports read like the connector reads them', () => {
  const doc = { v: 1, pairings: [PAIRED_4096, { ...PAIRED_4096, idx: { room: 'r2' }, account: 'b@example.com' }] }
  const moved = withPairingPort(doc, PAIRED_4096, 4097)
  assert.deepEqual(moved.pairings.map((p) => p.opencodeUrl), ['http://127.0.0.1:4097', 'http://127.0.0.1:4096'])
  assert.throws(() => withPairingPort(doc, PAIRED_4096, 70000))
  assert.equal(pairingPort({}), 4096)
  assert.equal(pairingPort({ opencodeUrl: 'http://127.0.0.1:4097/' }), 4097)
  assert.equal(pairingPort({ opencodeUrl: 'https://h' }), 443)
  assert.equal(pairingPort({ opencodeUrl: 'not a url' }), 0)
})

// ── uninstall ───────────────────────────────────────────────────────────────────────────────────────────────────────────

function fakeUninstall(over = {}) {
  const said = []
  const answers = [...(over.answers || [])]
  const state = { ports: over.ports ?? [4096], pairings: over.pairings ?? [PAIRED_4096], removedServices: [], unpaired: [], keysDeleted: false, removed: [], sessionsDeleted: false, stopped: [] }
  const d = {
    io: { say: (m) => said.push(m), ask: async (q) => { said.push(q); return answers.shift() ?? '' } },
    yes: !!over.yes,
    removeKeys: !!over.removeKeys,
    removeNotes: !!over.removeNotes,
    removeSessions: !!over.removeSessions,
    notes: () => over.notes ?? { root: '/home/u/.local/share/witbitz-notes', folders: 0, pluginFiles: [] },
    sessions: () => over.sessions ?? { dir: '/home/u/.local/share/opencode', exists: false },
    deleteSessions: () => { state.sessionsDeleted = true },
    openCodeProcesses: async () => over.procs ?? [],
    openCode: () => over.oc ?? { kind: 'none', path: '', hint: '' },
    removeOpenCode: !!over.removeOpenCode,
    removeOpenCodeProgram: async (info) => { state.ocRemoved = info.kind; return over.ocRemoval ?? { ok: true, said: [] } },
    stopProcess: async (pid) => { state.stopped.push(pid); return true },
    service: { installedPorts: () => state.ports, uninstall: (p) => { state.removedServices.push(p); return { ok: true } } },
    allPairings: () => state.pairings,
    unpair: async (p) => { if (over.offline) return { ok: false, why: 'network error' }; state.unpaired.push(p.account); return { ok: true } },
    codeDir: '/home/u/.witbitz/code',
    script: '/home/u/witbitz-code.mjs',
    hasKeys: () => over.keys ?? ['Tinfoil key', "TrustedRouter key (in OpenCode's credentials)"],
    deleteKeys: () => { state.keysDeleted = true },
    removePath: (p) => state.removed.push(p),
  }
  return { d, state, text: () => said.join('\n') }
}

test('uninstall says what it will remove and what it keeps, and changes nothing without a yes', async () => {
  const f = fakeUninstall({ answers: [''] })
  assert.deepEqual(await runUninstall(f.d), { done: false })
  const t = f.text()
  assert.match(t, /stop the background service and stop it starting with the computer/)
  assert.match(t, /remove this computer from a@example\.com — your devices stop showing it/)
  assert.match(t, /delete \/home\/u\/\.witbitz\/code/)
  assert.match(t, /It keeps OpenCode and your projects — and, unless you say so next, your keys, notes and sessions/)
  assert.match(t, /Nothing changed/)
  assert.deepEqual([f.state.removedServices, f.state.unpaired, f.state.removed], [[], [], []])
})

test('uninstall, yes: service, account, files and the download go; keys only when asked', async () => {
  const f = fakeUninstall({ ports: [4096, 4097], answers: ['y', ''] })
  const r = await runUninstall(f.d)
  assert.deepEqual(r, { done: true, left: 0 })
  assert.deepEqual(f.state.removedServices, [4096, 4097])
  assert.deepEqual(f.state.unpaired, ['a@example.com'])
  assert.deepEqual(f.state.removed, ['/home/u/.witbitz/code', '/home/u/witbitz-code.mjs'])
  assert.equal(f.state.keysDeleted, false, 'Enter keeps the keys')
  assert.match(f.text(), /witbitz-code is removed\.$/m)
  const keys = fakeUninstall({ answers: ['y', 'y'] })
  await runUninstall(keys.d)
  assert.equal(keys.state.keysDeleted, true)
})

test('uninstall --yes asks nothing and keeps the keys unless --remove-keys', async () => {
  const f = fakeUninstall({ yes: true })
  await runUninstall(f.d)
  assert.equal(f.state.keysDeleted, false)
  assert.equal(f.text().includes('[y/N]'), false)
  const k = fakeUninstall({ yes: true, removeKeys: true })
  await runUninstall(k.d)
  assert.equal(k.state.keysDeleted, true)
})

test('offline: the account could not be told — uninstall carries on and says how to remove it from the phone', async () => {
  const gone = fakeUninstall({ yes: true })
  gone.d.unpair = async () => ({ ok: true, noop: true })
  await runUninstall(gone.d)
  assert.match(gone.text(), /✓ Removed "test-box" from a@example\.com \(it was not listed\)/)
  const f = fakeUninstall({ yes: true, offline: true })
  const r = await runUninstall(f.d)
  assert.deepEqual(r, { done: true, left: 1 })
  assert.match(f.text(), /✖ Could not remove "test-box" from a@example\.com \(network error\)/)
  assert.match(f.text(), /Your phone may still list "test-box": open Code → Settings → Remove there/)
  assert.deepEqual(f.state.removed, ['/home/u/.witbitz/code', '/home/u/witbitz-code.mjs'])
})

test('removing keys keeps every other line and provider', () => {
  assert.equal(withoutEnvKeys('OPENCODE_SERVER_PASSWORD=p\nTINFOIL_API_KEY=tk\nexport TINFOIL_API_KEY="x"\nOTHER=1\n', ['TINFOIL_API_KEY']), 'OPENCODE_SERVER_PASSWORD=p\nOTHER=1\n')
  assert.equal(withoutEnvKeys('TINFOIL_API_KEY=tk\n', ['TINFOIL_API_KEY']), '')
  assert.deepEqual(JSON.parse(withoutAuthKey(JSON.stringify({ trustedrouter: { type: 'api', key: 'k' }, anthropic: { type: 'oauth' } }), 'trustedrouter')), { anthropic: { type: 'oauth' } })
  assert.throws(() => withoutAuthKey('[]', 'trustedrouter'))
})

test('the installed services are found by their file names, on both systems', () => {
  const home = tmp()
  const run = () => ({ status: 0, stdout: '', stderr: '' })
  const linux = serviceManager({ platform: 'linux', home, env: {}, run })
  writeFileSync(join(home, 'dl.mjs'), '//')
  linux.install({ node: '/usr/bin/node', script: join(home, 'dl.mjs'), port: 4096, path: '/usr/bin' })
  linux.install({ node: '/usr/bin/node', script: join(home, 'dl.mjs'), port: 4097, path: '/usr/bin' })
  writeFileSync(join(home, '.config/systemd/user/unrelated.service'), '')
  assert.deepEqual(linux.installedPorts(), [4096, 4097])
  const mac = serviceManager({ platform: 'darwin', home, uid: 501, run })
  mac.install({ node: '/usr/local/bin/node', script: join(home, 'dl.mjs'), port: 4098, path: '/usr/bin' })
  assert.deepEqual(mac.installedPorts(), [4098])
})

const NOTES = { root: '/home/u/.local/share/witbitz-notes', folders: 3, pluginFiles: ['/home/u/.config/opencode/plugins/witbitz-notes.js', '/home/u/.config/opencode/commands/notes-init.md'] }
const SESSIONS = { dir: '/home/u/.local/share/opencode', exists: true }

test('the notes plugin always goes (it would write new notes); notes and sessions only when asked — Enter keeps both', async () => {
  const f = fakeUninstall({ keys: [], notes: NOTES, sessions: SESSIONS, answers: ['y', '', ''] })
  await runUninstall(f.d)
  const t = f.text()
  assert.match(t, /remove the project-notes plugin from OpenCode \(2 files\)/)
  assert.match(t, /Also delete your project notes — 3 project folders in \/home\/u\/\.local\/share\/witbitz-notes\? \[y\/N\]/)
  assert.match(t, /Also delete ALL OpenCode sessions on this computer — every conversation, from Code and from the OpenCode app/)
  assert.ok(f.state.removed.includes(NOTES.pluginFiles[0]) && f.state.removed.includes(NOTES.pluginFiles[1]))
  assert.ok(!f.state.removed.includes(NOTES.root), 'Enter keeps the notes')
  assert.equal(f.state.sessionsDeleted, false, 'Enter keeps the sessions')
})

test('saying yes deletes the notes and the sessions — but never under a running OpenCode', async () => {
  const f = fakeUninstall({ keys: [], notes: NOTES, sessions: SESSIONS, answers: ['y', 'y', 'y'] })
  await runUninstall(f.d)
  assert.ok(f.state.removed.includes(NOTES.root))
  assert.equal(f.state.sessionsDeleted, true)
  assert.match(f.text(), /✓ Deleted the OpenCode sessions in \/home\/u\/\.local\/share\/opencode \(provider logins kept\)/)
  // still in use: it names the process and offers to stop it — services first, and only a process with the data folder
  // open counts (the owner's test waited on an OpenCode on 4096 from ANOTHER WSL distro, which nobody could close)
  const SERVE = { pid: 4242, cmd: 'opencode serve --port 4096 --hostname 127.0.0.1' }
  let checks = 0
  const stops = fakeUninstall({ keys: [], sessions: SESSIONS, answers: ['y', 'y', ''] })
  stops.d.openCodeProcesses = async () => (++checks === 1 || !stops.state.stopped.length ? [SERVE] : [])
  stops.d.service.uninstall = (p) => { stops.state.removedServices.push(p); assert.equal(checks, 0, 'services stop before the check'); return { ok: true } }
  await runUninstall(stops.d)
  assert.match(stops.text(), /OpenCode is still using the sessions: opencode serve --port 4096 --hostname 127\.0\.0\.1 \(process 4242\)/)
  assert.match(stops.text(), /Stop it now\? \[Y\/n\] — or type k to keep the sessions/)
  assert.deepEqual(stops.state.stopped, [4242])
  assert.equal(stops.state.sessionsDeleted, true)
  assert.ok(stops.state.removed.includes('/home/u/witbitz-code.mjs'))
  const keep = fakeUninstall({ keys: [], sessions: SESSIONS, procs: [SERVE], answers: ['y', 'y', 'k'] })
  await runUninstall(keep.d)
  assert.equal(keep.state.sessionsDeleted, false)
  assert.deepEqual(keep.state.stopped, [])
  const self = fakeUninstall({ keys: [], sessions: SESSIONS, answers: ['y', 'y', 'n', ''] })
  let n = 0
  self.d.openCodeProcesses = async () => (++n === 1 ? [SERVE] : [])
  await runUninstall(self.d)
  assert.match(self.text(), /Close it yourself, then press Enter/)
  assert.deepEqual(self.state.stopped, [], '"n": it does not stop anything itself')
  assert.equal(self.state.sessionsDeleted, true)
  const scripted = fakeUninstall({ yes: true, removeSessions: true, sessions: SESSIONS, procs: [SERVE] })
  await runUninstall(scripted.d)
  assert.equal(scripted.state.sessionsDeleted, false, '--yes never stops a process: it keeps them and says so')
  assert.deepEqual(scripted.state.stopped, [])
  assert.match(scripted.text(), /✖ Keeping the OpenCode sessions/)
})

test('--yes deletes neither notes nor sessions unless their flags say so; nothing to ask about → no question', async () => {
  const f = fakeUninstall({ yes: true, notes: NOTES, sessions: SESSIONS })
  await runUninstall(f.d)
  assert.equal(f.state.sessionsDeleted, false)
  assert.ok(!f.state.removed.includes(NOTES.root))
  const all = fakeUninstall({ yes: true, removeNotes: true, removeSessions: true, notes: NOTES, sessions: SESSIONS })
  await runUninstall(all.d)
  assert.equal(all.state.sessionsDeleted, true)
  assert.ok(all.state.removed.includes(NOTES.root))
  const none = fakeUninstall({ keys: [], answers: ['y'] })
  await runUninstall(none.d)
  assert.equal(none.text().match(/\[y\/N\]/g).length, 1, 'only "Continue?" — no notes, no sessions, no keys here')
})

// ── OpenCode itself ─────────────────────────────────────────────────────────────────────────────────────────────────────

test("how OpenCode was installed is read from where `opencode` resolves — the owner's test box: OpenCode's installer", () => {
  const home = '/home/witbitzchat'
  assert.deepEqual(openCodeInstall({ path: '/home/witbitzchat/.opencode/bin/opencode', home }), { kind: 'installer', path: '/home/witbitzchat/.opencode/bin/opencode', dir: '/home/witbitzchat/.opencode', binDir: '/home/witbitzchat/.opencode/bin' })
  assert.equal(openCodeInstall({ path: '/home/u/.nvm/versions/node/v24.3.0/bin/opencode', real: '/home/u/.nvm/versions/node/v24.3.0/lib/node_modules/opencode-ai/bin/opencode', home: '/home/u' }).kind, 'npm')
  assert.equal(openCodeInstall({ path: '/opt/homebrew/bin/opencode', real: '/opt/homebrew/Cellar/opencode/1.18.30/bin/opencode', home: '/Users/u' }).kind, 'brew')
  assert.equal(openCodeInstall({ path: '/usr/local/bin/opencode', home: '/home/u' }).kind, 'other')
  assert.equal(openCodeInstall({ path: '', home: '/home/u' }).kind, 'none')
  // the owner ran `npm uninstall -g opencode-ai` as told and npm said "up to date": the hint must fit the install
  assert.match(openCodeRemovalHint({ kind: 'installer' }), /^rm -rf ~\/\.opencode/)
  assert.equal(openCodeRemovalHint({ kind: 'npm' }, { npmNeedsSudo: true }), 'sudo npm uninstall -g opencode-ai')
  assert.equal(openCodeRemovalHint({ kind: 'brew' }), 'brew uninstall opencode')
})

test("OpenCode's PATH lines come out of a startup file exactly as its installer wrote them; everything else stays", () => {
  const bin = '/home/witbitzchat/.opencode/bin'
  const before = 'alias ll="ls -l"\nexport PATH=$HOME/go/bin:$PATH\n\n# opencode\nexport PATH=/home/witbitzchat/.opencode/bin:$PATH\n'
  assert.deepEqual(withoutOpenCodePath(before, bin), { text: 'alias ll="ls -l"\nexport PATH=$HOME/go/bin:$PATH\n', changed: true })
  assert.deepEqual(withoutOpenCodePath('# opencode\nfish_add_path /home/witbitzchat/.opencode/bin', bin), { text: '', changed: true })
  assert.equal(withoutOpenCodePath('# my notes on opencode\nexport PATH=/opt/opencode/bin:$PATH\n', bin).changed, false, 'another folder is not ours')
  assert.equal(withoutOpenCodePath('echo hi\nexport PATH=$HOME/.opencode/bin:$PATH\n', bin).text, 'echo hi\n')
  assert.ok(shellStartupFiles('/home/u').includes('/home/u/.bashrc') && shellStartupFiles('/home/u').includes('/home/u/.config/fish/config.fish'))
})

test('uninstall asks about OpenCode itself, naming how it was installed; the closing hint fits the install', async () => {
  const OC = { kind: 'installer', path: '/home/u/.opencode/bin/opencode', dir: '/home/u/.opencode', binDir: '/home/u/.opencode/bin', hint: 'rm -rf ~/.opencode — and delete the "# opencode" PATH line' }
  const keep = fakeUninstall({ keys: [], oc: OC, answers: ['y', ''] })
  await runUninstall(keep.d)
  assert.match(keep.text(), /Also remove OpenCode itself \(installed from OpenCode's installer, in ~\/\.opencode\)\? \[y\/N\]/)
  assert.equal(keep.state.ocRemoved, undefined)
  assert.match(keep.text(), /OpenCode is still installed — to remove it too: rm -rf ~\/\.opencode/)
  assert.doesNotMatch(keep.text(), /npm uninstall/)
  const gone = fakeUninstall({ keys: [], oc: OC, answers: ['y', 'y'], ocRemoval: { ok: true, said: ['✓ Removed OpenCode\'s PATH line from /home/u/.bashrc'] } })
  await runUninstall(gone.d)
  assert.equal(gone.state.ocRemoved, 'installer')
  assert.match(gone.text(), /✓ Removed OpenCode's PATH line from \/home\/u\/\.bashrc/)
  assert.match(gone.text(), /witbitz-code and OpenCode are removed\. Open a new terminal window/)
  const sudo = fakeUninstall({ keys: [], oc: { kind: 'npm', path: '/usr/bin/opencode', hint: 'sudo npm uninstall -g opencode-ai' }, answers: ['y', 'y'], ocRemoval: { ok: false, why: "npm's global folder needs sudo here", said: [] } })
  await runUninstall(sudo.d)
  assert.match(sudo.text(), /✖ Could not remove OpenCode \(npm's global folder needs sudo here\) — to do it yourself: sudo npm uninstall -g opencode-ai/)
  const other = fakeUninstall({ keys: [], oc: { kind: 'other', path: '/usr/local/bin/opencode', hint: 'it is at /usr/local/bin/opencode — remove it the way it was installed' }, answers: ['y'] })
  await runUninstall(other.d)
  assert.doesNotMatch(other.text(), /Also remove OpenCode itself/, 'an install it cannot recognise is only described')
  const scripted = fakeUninstall({ yes: true, oc: OC })
  await runUninstall(scripted.d)
  assert.equal(scripted.state.ocRemoved, undefined, '--yes keeps OpenCode unless --remove-opencode')
  const flagged = fakeUninstall({ yes: true, removeOpenCode: true, oc: OC })
  await runUninstall(flagged.d)
  assert.equal(flagged.state.ocRemoved, 'installer')
})

const PLAN_NPM = { kind: 'npm', label: 'with npm ("npm install -g opencode-ai")' }
const PLAN_INSTALLER = { kind: 'installer', label: "with OpenCode's installer (\"curl -fsSL https://opencode.ai/install | bash\" — into ~/.opencode, no sudo; it adds OpenCode to your PATH)" }

test("npm that needs sudo is never offered: the owner's test box gets OpenCode's installer", async () => {
  const f = fakeSetup({ plans: [PLAN_INSTALLER], answers: [''], state: { pairings: [PAIRED_4096], tr: true, tinfoil: 'tk' }, serviceAvailable: false })
  const r = await runSetup(f.d)
  assert.equal(r.opencode, true)
  assert.deepEqual(f.state.tried, ['installer'])
  assert.match(f.text(), /Install it now with OpenCode's installer \("curl -fsSL https:\/\/opencode\.ai\/install \| bash" — into ~\/\.opencode, no sudo/)
  assert.doesNotMatch(f.text(), /npm install -g opencode-ai"\? \[Y\/n\]/)
})

test('when npm fails anyway, the installer is offered next; when everything fails it names the no-sudo way first', async () => {
  const f = fakeSetup({ plans: [PLAN_NPM, PLAN_INSTALLER], works: { npm: false, installer: true }, answers: ['', ''], state: { pairings: [PAIRED_4096], tr: true, tinfoil: 'tk' }, serviceAvailable: false })
  const r = await runSetup(f.d)
  assert.equal(r.opencode, true)
  assert.deepEqual(f.state.tried, ['npm', 'installer'])
  assert.match(f.text(), /✖ That did not install OpenCode\./)
  const none = fakeSetup({ plans: [PLAN_NPM, PLAN_INSTALLER], works: { npm: false, installer: false }, answers: ['', ''] })
  assert.equal((await runSetup(none.d)).stopped, 'opencode')
  assert.match(none.text(), /Install it, then run setup again:\n +curl -fsSL https:\/\/opencode\.ai\/install \| bash +\(no sudo/)
  const declined = fakeSetup({ plans: [PLAN_NPM, PLAN_INSTALLER], answers: ['n'] })
  await runSetup(declined.d)
  assert.equal(declined.state.tried, undefined, '"n" installs nothing and offers nothing else')
})
