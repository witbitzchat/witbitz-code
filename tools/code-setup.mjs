// witbitz-code setup — from a fresh download to a working Code section in one command (the owner: "Can we make it
// easier"). It walks OpenCode → pairing → TrustedRouter → Tinfoil → keeping it running, and skips whatever is already done.
//
// Measured 2026-09-14 (before writing this):
//   • TrustedRouter: GET https://api.trustedrouter.com/v1/key answers 401 "Invalid API key" for a bad or missing key.
//     Keys are created at trustedrouter.com/console/api-keys (sign in with Google or GitHub).
//   • Tinfoil: POST inference.tinfoil.sh/v1/chat/completions checks the MODEL before the key (an unknown model is 404 with
//     any key), then the key: a real model with a bad key is 401 "Incorrect API key provided." — so the check sends an
//     existing model and an empty conversation, which a valid key gets refused for without generating anything.
//     Keys are created at dash.tinfoil.sh?tab=api-keys.
//   • OpenCode 1.18.30 reads {"trustedrouter":{"type":"api","key":…}} from $XDG_DATA_HOME/opencode/auth.json — the same
//     file `opencode auth login` writes (checked with `opencode auth list` in an empty home). The key goes THERE, never
//     into OpenCode's environment, where every shell command the agent runs could print it.
//   • This computer's WSL has no systemd user manager (`systemctl --user` is offline) — so "no background start here" is a
//     real case: setup then runs serve in the window.
// Nothing here prints a key. Keys are written 0600 through writeSecret (temp file + rename).
import { spawnSync } from 'node:child_process'
import { readFileSync, existsSync, mkdirSync, copyFileSync, writeFileSync, rmSync, chmodSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname, resolve } from 'node:path'

export const KEY_PAGES = { trustedrouter: 'https://trustedrouter.com/console/api-keys', tinfoil: 'https://dash.tinfoil.sh?tab=api-keys' }
const TR_KEY_URL = 'https://api.trustedrouter.com/v1/key'
const TINFOIL_API = 'https://inference.tinfoil.sh/v1'
const TINFOIL_FALLBACK_MODEL = 'gpt-oss-120b'

/** An API key as pasted: printable ASCII, no spaces — anything else would break the env file or auth.json it is saved in. */
export const validKeyShape = (key) => typeof key === 'string' && /^[\x21-\x7e]{8,512}$/.test(key)

// ── key checks: { ok: true } accepted · { ok: false } rejected · { ok: null, why } could not tell (saved anyway) ────────

export async function checkTrustedRouterKey(key, { fetchImpl = fetch, timeoutMs = 10_000 } = {}) {
  try {
    const r = await fetchImpl(TR_KEY_URL, { headers: { authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(timeoutMs) })
    if (r.status === 401 || r.status === 403) return { ok: false, why: 'TrustedRouter rejected this key' }
    if (r.ok) return { ok: true }
    return { ok: null, why: `TrustedRouter answered HTTP ${r.status}` }
  } catch (e) { return { ok: null, why: `could not reach TrustedRouter (${(e && (e.code || e.name)) || e})` } }
}

export async function checkTinfoilKey(key, { fetchImpl = fetch, timeoutMs = 15_000 } = {}) {
  try {
    let model = TINFOIL_FALLBACK_MODEL
    try {
      const list = await fetchImpl(`${TINFOIL_API}/models`, { signal: AbortSignal.timeout(timeoutMs) })
      const data = list.ok ? ((await list.json()) || {}).data : null
      const live = Array.isArray(data) ? data.find((m) => m && typeof m.id === 'string' && !m.deprecated) : null
      if (live) model = live.id
    } catch { /* the fallback model */ }
    const r = await fetchImpl(`${TINFOIL_API}/chat/completions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({ model, messages: [], max_tokens: 1 }),
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (r.status === 401 || r.status === 403) return { ok: false, why: 'Tinfoil rejected this key' }
    if (r.ok || r.status === 400 || r.status === 422) return { ok: true }
    return { ok: null, why: `Tinfoil answered HTTP ${r.status}` }
  } catch (e) { return { ok: null, why: `could not reach Tinfoil (${(e && (e.code || e.name)) || e})` } }
}

// ── OpenCode's credentials file ────────────────────────────────────────────────────────────────────────────────────────

export const authPath = (env = process.env) => join(env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'opencode', 'auth.json')

/** auth.json text with `provider` set to an API key; every other provider kept. Throws on a file that is not a JSON object
 *  — setup then tells the person to use `opencode auth login` rather than overwrite credentials it cannot read. */
export function withAuthKey(text, provider, key) {
  let doc = {}
  if (text && String(text).trim()) {
    doc = JSON.parse(text)
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('auth.json is not a JSON object')
  }
  return JSON.stringify({ ...doc, [provider]: { type: 'api', key } }, null, 2) + '\n'
}

// ── pairings and ports ──────────────────────────────────────────────────────────────────────────────────────────────────

/** The OpenCode port a pairing points at (the connector's rule: tools/opencode-connector.mjs pairingsForPort). 0 = unusable. */
export function pairingPort(p) {
  try { const u = new URL((p && p.opencodeUrl) || 'http://127.0.0.1:4096'); return Number(u.port || (u.protocol === 'https:' ? 443 : 80)) } catch { return 0 }
}

/** The pairings file with one pairing (same account room and computer) pointed at another local OpenCode port. Pure. */
export function withPairingPort(doc, pairing, port) {
  if (!validPort(port)) throw new Error(`bad port ${port}`)
  const list = doc && Array.isArray(doc.pairings) ? doc.pairings : []
  const same = (x) => x && x.idx && pairing.idx && x.idx.room === pairing.idx.room && x.computerId === pairing.computerId
  return { ...doc, pairings: list.map((x) => (same(x) ? { ...x, opencodeUrl: `http://127.0.0.1:${port}` } : x)) }
}

// ── keeping it running: a systemd user unit (Linux) or a launchd agent (macOS) ──────────────────────────────────────────

const validPort = (port) => Number.isInteger(port) && port > 0 && port < 65536
/** One service per OpenCode port, so a second OpenCode (another person's, docs: "More than one account") gets its own. */
export const serviceName = (port) => (port === 4096 ? 'witbitz-code' : `witbitz-code-${port}`)
export const launchdLabel = (port) => (port === 4096 ? 'chat.witbitz.code' : `chat.witbitz.code.${port}`)
/** Where the service runs witbitz-code from — a copy that survives the download being moved or deleted. */
export const stableScript = (home = homedir()) => join(home, '.witbitz', 'code', 'witbitz-code.mjs')

/** A path or PATH written into a unit or plist: a control character (a newline above all) would start a new line of the
 *  file — another directive — so it is refused rather than escaped. */
const plain = (s) => { const v = String(s); if (/[\x00-\x1f\x7f]/.test(v)) throw new Error('a path contains a control character'); return v }
/** systemd quoting: a double-quoted word with \ and " escaped, % doubled (specifiers) and $ doubled (variables). */
const sdWord = (s) => `"${plain(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`

export function systemdUnit({ node, script, port, path }) {
  if (!validPort(port)) throw new Error(`bad port ${port}`)
  return [
    '[Unit]',
    "Description=witbitz-code — the Spaces Code section's connection to OpenCode on this computer",
    'After=network-online.target',
    '',
    '[Service]',
    `ExecStart=${sdWord(node)} ${sdWord(script)} serve --port ${port}`,
    `Environment=${sdWord(`PATH=${path}`)}`,
    'WorkingDirectory=%h',
    'Restart=always',
    'RestartSec=10',
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].join('\n')
}

const xml = (s) => plain(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

export function launchdPlist({ node, script, port, path, home }) {
  if (!validPort(port)) throw new Error(`bad port ${port}`)
  const log = join(home, 'Library', 'Logs', `${serviceName(port)}.log`)
  const args = [node, script, 'serve', '--port', String(port)].map((a) => `<string>${xml(a)}</string>`).join('')
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${xml(launchdLabel(port))}</string>
  <key>ProgramArguments</key><array>${args}</array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>${xml(path)}</string></dict>
  <key>WorkingDirectory</key><string>${xml(home)}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
</dict>
</plist>
`
}

/** Ports of the witbitz-code services installed in a folder (the unnamed one is 4096). */
function portsFrom(dir, re) {
  try { return readdirSync(dir).map((f) => f.match(re)).filter(Boolean).map((m) => (m[1] ? Number(m[1]) : 4096)).filter(validPort).sort((a, b) => a - b) } catch { return [] }
}

const runCmd = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8' })
  return { status: r.error ? -1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '' }
}

/** The service manager for this platform. Every outside effect is injectable (tests run it against a temp home). */
export function serviceManager({ platform = process.platform, home = homedir(), env = process.env, run = runCmd, uid = process.getuid ? process.getuid() : 0 } = {}) {
  const put = (file, text) => { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, text, { mode: 0o644 }) }
  const stage = (script) => {
    const dest = stableScript(home)
    if (resolve(script) !== resolve(dest)) { mkdirSync(dirname(dest), { recursive: true, mode: 0o700 }); copyFileSync(script, dest); chmodSync(dest, 0o644) }
    return dest
  }
  /** The script differs from the copy the service runs (or there is no copy yet). */
  const outdated = (script) => {
    const dest = stableScript(home)
    try { return resolve(script) !== resolve(dest) && !readFileSync(script).equals(readFileSync(dest)) } catch { return true }
  }
  if (platform === 'linux') {
    const dir = join(env.XDG_CONFIG_HOME || join(home, '.config'), 'systemd', 'user')
    const unitFile = (port) => join(dir, `${serviceName(port)}.service`)
    const sc = (...a) => run('systemctl', ['--user', ...a])
    return {
      kind: 'systemd',
      outdated,
      available: () => sc('show-environment').status === 0,
      unavailableWhy: 'there is no systemd user session here (on WSL, turn systemd on in /etc/wsl.conf: [boot] systemd=true)',
      status: (port) => (existsSync(unitFile(port)) ? (sc('is-active', serviceName(port)).stdout.trim() || 'inactive') : 'not installed'),
      install({ node, script, port, path }) {
        let unit
        try { unit = systemdUnit({ node, script: stableScript(home), port, path }) } catch (e) { return { ok: false, why: e.message } }
        stage(script)
        put(unitFile(port), unit)
        const steps = [sc('daemon-reload'), sc('enable', serviceName(port)), sc('restart', serviceName(port))]
        const bad = steps.find((s) => s.status !== 0)
        return bad ? { ok: false, why: (bad.stderr || bad.stdout).trim() || 'systemctl failed' } : { ok: true }
      },
      restart: (port) => sc('restart', serviceName(port)).status === 0,
      uninstall(port) {
        if (!existsSync(unitFile(port))) return { ok: true, noop: true }
        sc('disable', '--now', serviceName(port))
        rmSync(unitFile(port), { force: true })
        sc('daemon-reload')
        return { ok: true }
      },
      installedPorts: () => portsFrom(dir, /^witbitz-code(?:-(\d+))?\.service$/),
      logsHint: (port) => `journalctl --user -u ${serviceName(port)} -f`,
      extraHint: 'It starts when you log in. To keep it running while you are logged out: loginctl enable-linger $USER',
    }
  }
  if (platform === 'darwin') {
    const plist = (port) => join(home, 'Library', 'LaunchAgents', `${launchdLabel(port)}.plist`)
    const target = (port) => `gui/${uid}/${launchdLabel(port)}`
    return {
      kind: 'launchd',
      outdated,
      available: () => true,
      unavailableWhy: '',
      status: (port) => {
        if (!existsSync(plist(port))) return 'not installed'
        const r = run('launchctl', ['print', target(port)])
        return r.status === 0 && /state = running/.test(r.stdout) ? 'active' : 'inactive'
      },
      install({ node, script, port, path }) {
        let text
        try { text = launchdPlist({ node, script: stableScript(home), port, path, home }) } catch (e) { return { ok: false, why: e.message } }
        stage(script)
        put(plist(port), text)
        run('launchctl', ['bootout', target(port)]) // not loaded yet is fine
        const r = run('launchctl', ['bootstrap', `gui/${uid}`, plist(port)])
        return r.status === 0 ? { ok: true } : { ok: false, why: (r.stderr || r.stdout).trim() || 'launchctl bootstrap failed' }
      },
      restart: (port) => run('launchctl', ['kickstart', '-k', target(port)]).status === 0,
      uninstall(port) {
        if (!existsSync(plist(port))) return { ok: true, noop: true }
        run('launchctl', ['bootout', target(port)])
        rmSync(plist(port), { force: true })
        return { ok: true }
      },
      installedPorts: () => portsFrom(join(home, 'Library', 'LaunchAgents'), /^chat\.witbitz\.code(?:\.(\d+))?\.plist$/),
      logsHint: (port) => `tail -f ~/Library/Logs/${serviceName(port)}.log`,
      extraHint: 'It starts when you log in.',
    }
  }
  return {
    kind: 'none',
    outdated: () => false,
    available: () => false,
    unavailableWhy: `background start is not supported on ${platform} (use WSL on Windows)`,
    status: () => 'not installed',
    install: () => ({ ok: false, why: 'unsupported platform' }),
    restart: () => false,
    uninstall: () => ({ ok: true, noop: true }),
    installedPorts: () => [],
    logsHint: () => '',
    extraHint: '',
  }
}

// ── the terminal ────────────────────────────────────────────────────────────────────────────────────────────────────────

/** Read one line from a terminal in raw mode — characters echoed, or one "*" each for a key (the owner: "can pasting the
 *  keys show at least that something was pasted like with *****" — a silent prompt looked like the paste had failed). A pasted chunk is taken character
 *  by character, so a paste that ends in a newline submits instead of saving the newline into the key. */
export function readLine(prompt, { hidden = false, input = process.stdin, output = process.stderr } = {}) {
  return new Promise((done) => {
    output.write(prompt)
    if (!input.isTTY) {
      let s = ''
      input.setEncoding('utf8')
      input.on('data', (c) => { s += c })
      input.on('end', () => done(s.split(/\r?\n/)[0].trim()))
      return
    }
    let s = ''
    input.setRawMode(true); input.resume(); input.setEncoding('utf8')
    const finish = () => { input.setRawMode(false); input.pause(); input.off('data', onData); output.write('\n'); done(s.trim()) }
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\u0003') { input.setRawMode(false); output.write('\n'); process.exit(130) }
        if (ch === '\r' || ch === '\n' || ch === '\u0004') return finish()
        if (ch === '\u007f' || ch === '\b') { if (s) { s = s.slice(0, -1); output.write('\b \b') } continue }
        if (ch < ' ') continue
        s += ch
        output.write(hidden ? '*' : ch)
      }
    }
    input.on('data', onData)
  })
}

// ── the walk-through ────────────────────────────────────────────────────────────────────────────────────────────────────

const yes = (answer) => !/^n/i.test(String(answer || '').trim())

/** Ask for a key until it is accepted, skipped (empty) or three tries were rejected. Returns the key to save, or ''. */
async function askKey({ io, label, check }) {
  for (let tries = 0; tries < 3; tries++) {
    const key = await io.secret(`   Paste your ${label} API key (it shows as *****; Enter to skip): `)
    if (!key) return ''
    if (!validKeyShape(key)) { io.say('   ✖ That does not look like an API key (no spaces, 8–512 characters). Try again.'); continue }
    io.say('   Checking the key…')
    const v = await check(key)
    if (v.ok === false) { io.say(`   ✖ ${v.why}. Copy it again from the key page and paste it here.`); continue }
    if (v.ok === null) io.say(`   ⚠ Saved without checking — ${v.why}.`)
    return key
  }
  io.say(`   Skipped after three tries.`)
  return ''
}

/**
 * The whole setup. `d` holds every outside effect, so the flow is tested end to end with fakes:
 *   io { say, ask, secret } · port · portExplicit (--port given) · findOpenCode() → path|''
 *   openCodeInstallPlans() → [{ kind: 'npm'|'installer', label }] (what works here, best first) · installOpenCode(kind) → boolean
 *   allPairings() → [] · portOf(pairing) → number · pair(port) · movePairing(pairing, port) · hasTrustedRouter()
 *   saveTrustedRouterKey(key) · tinfoilKey() · saveTinfoilKey(key) · checkTrustedRouter(key) · checkTinfoil(key)
 *   isListening(port) · portOwners(port) → [{ pid, cmd }] (this user's processes listening there) · stopProcess(pid)
 *   freePort(from) → port (it and port+100, the confidential-model proxy, both free) · service (serviceManager())
 *   serviceArgs { node, script, path } · bundled · serveHere(port) · wsl (running under Windows' WSL)
 */
export async function runSetup(d) {
  const { io } = d
  let port = d.port
  const result = { opencode: false, paired: false, trustedrouter: false, tinfoil: false, running: '' }
  io.say(`witbitz-code setup — five steps; anything already done is skipped.\n`)

  // 1 — OpenCode
  io.say('1. OpenCode, the coding agent')
  let oc = d.findOpenCode()
  if (!oc) {
    io.say('   OpenCode is not installed.')
    // Only what works without sudo (the owner's test box: npm is the system one in /usr/lib, so `npm install -g` failed
    // with EACCES) — npm where its global folder is writable, else OpenCode's own installer into ~/.opencode. A way that
    // fails offers the next one.
    for (const plan of d.openCodeInstallPlans()) {
      if (!yes(await io.ask(`   Install it now ${plan.label}? [Y/n] `))) break
      if (d.installOpenCode(plan.kind)) oc = d.findOpenCode()
      if (oc) break
      io.say('   ✖ That did not install OpenCode.')
    }
    if (!oc) {
      io.say('   ✖ OpenCode is still not installed. Install it, then run setup again:')
      io.say('       curl -fsSL https://opencode.ai/install | bash      (no sudo — then open a new terminal)')
      io.say('       npm install -g opencode-ai                         (if your npm can install without sudo)')
      return { ...result, stopped: 'opencode' }
    }
  }
  io.say(`   ✓ OpenCode is installed`)
  result.opencode = true

  // 2 — pairing
  io.say('\n2. This computer and your Witbitz account')
  // A pairing belongs to one OpenCode port. Already paired for another port: without --port, use that one; with --port and a
  // single pairing, offer to move it (the port lives only in this computer's pairings file — no scan). Before this, setup
  // showed the QR again, the scan "refreshed" the pairing on its old port, and setup said pairing did not finish.
  const on = (list, p) => list.filter((x) => d.portOf(x) === p)
  const named = (list) => list.map((p) => `"${p.name}" → ${p.account || 'your account'}`).join(', ')
  let all = d.allPairings()
  if (all.length && !on(all, port).length) {
    const ports = [...new Set(all.map((p) => d.portOf(p)))]
    if (!d.portExplicit && ports.length === 1) {
      port = ports[0]
      io.say(`   This computer is paired for OpenCode on port ${port} — using that port.`)
    } else if (!d.portExplicit) {
      io.say(`   This computer is paired for OpenCode on ports ${ports.join(', ')}. Run setup for the one you mean: node witbitz-code.mjs setup --port <port>`)
      return { ...result, stopped: 'ports' }
    } else if (all.length === 1) {
      const p = all[0]
      if (yes(await io.ask(`   ${named([p])} is set up for OpenCode on port ${d.portOf(p)}. Use port ${port} instead? [Y/n] `))) {
        d.movePairing(p, port)
        all = d.allPairings()
      }
    }
  }
  let mine = on(all, port)
  if (!mine.length) {
    io.say('   On your phone, open Spaces → Settings → Back up & recovery → Add a device, and scan the code below.\n')
    await d.pair(port)
    all = d.allPairings()
    mine = on(all, port)
    if (!mine.length) {
      io.say(all.length
        ? `   ✖ This computer is paired, but for OpenCode on another port (${all.map((p) => `"${p.name}": ${d.portOf(p)}`).join(', ')}). Run setup again with that port: node witbitz-code.mjs setup --port ${d.portOf(all[0])}`
        : '   ✖ Pairing did not finish. Run setup again to retry.')
      return { ...result, stopped: 'pair' }
    }
  }
  io.say(`   ✓ Paired: ${named(mine)}${port !== 4096 ? ` (OpenCode on port ${port})` : ''}`)
  result.paired = true

  // 3 — TrustedRouter
  io.say('\n3. TrustedRouter — the AI models, including the confidential ones (you pay TrustedRouter directly)')
  let trAdded = false
  if (d.hasTrustedRouter()) io.say('   ✓ TrustedRouter is connected')
  else {
    io.say(`   Create a key at ${KEY_PAGES.trustedrouter} (sign in with Google or GitHub, add credit).`)
    const key = await askKey({ io, label: 'TrustedRouter', check: d.checkTrustedRouter })
    if (key) {
      try { d.saveTrustedRouterKey(key); trAdded = true; io.say("   ✓ Saved in OpenCode's credentials (only you can read it)") }
      catch (e) { io.say(`   ✖ Could not save it (${e.message}). Run "opencode auth login" and choose TrustedRouter instead.`) }
    } else io.say('   Skipped — Code uses whatever providers OpenCode already has. Confidential models need TrustedRouter.')
  }
  result.trustedrouter = d.hasTrustedRouter()

  // 4 — Tinfoil
  io.say('\n4. Tinfoil — optional: lets confidential models read images, and makes readable copies of PDF, Word and Excel files')
  if (d.tinfoilKey()) io.say('   ✓ Tinfoil key saved')
  else {
    io.say(`   Create a key at ${KEY_PAGES.tinfoil} (you pay Tinfoil directly).`)
    const key = await askKey({ io, label: 'Tinfoil', check: d.checkTinfoil })
    if (key) { d.saveTinfoilKey(key); io.say('   ✓ Saved (only you can read it)') }
    else io.say('   Skipped — add it later with: node witbitz-code.mjs tinfoil-key')
  }
  result.tinfoil = !!d.tinfoilKey()

  // 5 — keep it running
  io.say('\n5. Keep it running')
  const svc = d.service
  const installed = svc.status(port)
  if (installed === 'active') {
    // Re-running setup from a newer download updates the copy the service runs (install restarts it); otherwise a running
    // service is restarted only when OpenCode must pick up a TrustedRouter key it did not have — a restart ends live turns.
    if (d.bundled && svc.outdated(d.serviceArgs.script)) {
      const r = svc.install({ ...d.serviceArgs, port })
      io.say(r.ok ? '   ✓ Updated the background service to this version and restarted it' : `   ✖ Could not update the background service (${r.why})`)
    } else if (trAdded) { svc.restart(port); io.say('   ✓ Restarted the background service so OpenCode picks up TrustedRouter') }
    else io.say('   ✓ Already running in the background')
    result.running = 'service'
  } else {
    // Who holds the port decides what to offer (the owner's test: 4096 was an OpenCode in ANOTHER WSL distro — distros share
    // ports — so "close it" was impossible). This person's own process: offer to stop it. Anything else: move to a free port.
    while (await d.isListening(port)) {
      const mine = await d.portOwners(port)
      if (mine.length) {
        io.say(`   Already running on 127.0.0.1:${port}: ${mine.map((p) => `${(p.cmd || 'a program').slice(0, 70)} (process ${p.pid})`).join('; ')}.`)
        io.say('   witbitz-code has to start OpenCode itself — started any other way, its TrustedRouter calls are not protected.')
        const a = await io.ask(`   Stop ${mine.length > 1 ? 'them' : 'it'} now? [Y/n] — or type s to stop here: `)
        if (/^s/i.test(a)) { io.say('   Stopped. Run setup again when you are ready.'); return { ...result, stopped: 'busy' } }
        if (/^n/i.test(a)) {
          if (/^s/i.test(await io.ask('   Close it yourself, then press Enter — or type s to stop here: '))) { io.say('   Stopped. Run setup again when you are ready.'); return { ...result, stopped: 'busy' } }
          continue
        }
        for (const p of mine) io.say((await d.stopProcess(p.pid)) ? `   ✓ Stopped process ${p.pid}` : `   ✖ Could not stop process ${p.pid}`)
        continue
      }
      const free = await d.freePort(port + 1)
      io.say(`   Port ${port} is taken by a program that is not yours${d.wsl ? ' — on WSL, another Linux distro on this computer shares its ports' : ''}.`)
      if (!yes(await io.ask(`   Use port ${free} instead? [Y/n] `))) { io.say(`   Stopped. To use another port later: node witbitz-code.mjs setup --port ${free}`); return { ...result, stopped: 'busy' } }
      for (const p of on(d.allPairings(), port)) d.movePairing(p, free)
      port = free
      io.say(`   ✓ This computer now uses OpenCode on port ${port} (no new scan needed)`)
    }
    if (svc.available() && d.bundled) {
      if (yes(await io.ask('   Start witbitz-code now and every time you log in? [Y/n] '))) {
        const r = svc.install({ ...d.serviceArgs, port })
        if (r.ok) {
          io.say(`   ✓ Running in the background. Logs: ${svc.logsHint(port)}`)
          if (svc.extraHint) io.say(`     ${svc.extraHint}`)
          io.say('     Stop it with: node witbitz-code.mjs service uninstall · remove everything: node witbitz-code.mjs uninstall')
          result.running = 'service'
        } else io.say(`   ✖ Could not start it in the background (${r.why}).`)
      }
    } else if (!d.bundled) io.say('   (Background start is for the downloaded witbitz-code.mjs; from the repository use tools/opencode-serve.sh.)')
    else io.say(`   Background start is not available: ${svc.unavailableWhy}.`)
  }

  if (result.running === 'service') { io.say('\nDone. Open Spaces → ☰ → Code on your phone.'); return result }
  io.say('\nDone. Starting witbitz-code in this window — keep it open (Ctrl-C stops it). Open Spaces → ☰ → Code on your phone.\n')
  result.running = 'here'
  await d.serveHere(port)
  return result
}

// ── OpenCode itself: how it was installed, and how to remove it ──────────────────────────────────────────────────────────

/** The shell startup files OpenCode's installer (opencode.ai/install) may have added its PATH line to. */
export const shellStartupFiles = (home, env = {}) => {
  const xdg = env.XDG_CONFIG_HOME || join(home, '.config')
  const zdot = env.ZDOTDIR || home
  return [...new Set([join(home, '.bashrc'), join(home, '.bash_profile'), join(home, '.profile'), join(xdg, 'bash', '.bashrc'), join(xdg, 'bash', '.bash_profile'),
    join(zdot, '.zshrc'), join(zdot, '.zshenv'), join(xdg, 'zsh', '.zshrc'), join(xdg, 'zsh', '.zshenv'), join(home, '.ashrc'), join(xdg, 'fish', 'config.fish')])]
}

/** A startup file without the lines OpenCode's installer appended: "\n# opencode\n" then `export PATH=<dir>:$PATH` (or
 *  `fish_add_path <dir>`), read from opencode.ai/install (add_to_path). Only those exact lines go; the comment and the
 *  blank line before it only when they sit right above the PATH line. Pure. → { text, changed } */
export function withoutOpenCodePath(text, binDir) {
  const lines = String(text || '').split('\n')
  const dirs = [binDir, '$HOME/.opencode/bin', '~/.opencode/bin']
  const isPath = (l) => dirs.some((dir) => l.trim() === `export PATH=${dir}:$PATH` || l.trim() === `fish_add_path ${dir}`)
  const out = []
  let changed = false
  for (const l of lines) {
    if (!isPath(l)) { out.push(l); continue }
    changed = true
    if (out.length && out[out.length - 1].trim() === '# opencode') {
      out.pop()
      if (out.length && out[out.length - 1].trim() === '') out.pop()
    }
  }
  return { text: out.join('\n'), changed }
}

/** How OpenCode got here, from where `opencode` resolves. → { kind: 'installer'|'npm'|'brew'|'other'|'none', path, dir? } */
export function openCodeInstall({ path, real = path, home }) {
  if (!path) return { kind: 'none', path: '' }
  const own = join(home, '.opencode')
  if (path.startsWith(own + '/') || String(real).startsWith(own + '/')) return { kind: 'installer', path, dir: own, binDir: join(own, 'bin') }
  if (/\/node_modules\/opencode-ai\//.test(real)) return { kind: 'npm', path }
  if (/\/Cellar\/opencode\//.test(real) || /^\/(opt\/homebrew|home\/linuxbrew\/\.linuxbrew)\//.test(path)) return { kind: 'brew', path }
  return { kind: 'other', path }
}

/** The command a person would run to remove it — shown when they keep OpenCode, or when removing it needs sudo. */
export function openCodeRemovalHint(info, { npmNeedsSudo = false } = {}) {
  if (info.kind === 'installer') return `rm -rf ~/.opencode — and delete the "# opencode" PATH line from your shell's startup file (~/.bashrc or ~/.zshrc)`
  if (info.kind === 'npm') return `${npmNeedsSudo ? 'sudo ' : ''}npm uninstall -g opencode-ai`
  if (info.kind === 'brew') return 'brew uninstall opencode'
  if (info.kind === 'other') return `it is at ${info.path} — remove it the way it was installed`
  return ''
}

// ── uninstall ───────────────────────────────────────────────────────────────────────────────────────────────────────────

/** An env file's text without the given keys; every other line kept verbatim. Pure. */
export function withoutEnvKeys(text, keys) {
  const drop = new RegExp(`^\\s*(?:export\\s+)?(?:${keys.join('|')})=`)
  const kept = String(text || '').split(/\r?\n/).filter((l) => !drop.test(l))
  while (kept.length && kept[kept.length - 1] === '') kept.pop()
  return kept.length ? kept.join('\n') + '\n' : ''
}

/** auth.json text without one provider; every other provider kept. Throws on a file that is not a JSON object. */
export function withoutAuthKey(text, provider) {
  const doc = text && String(text).trim() ? JSON.parse(text) : {}
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('auth.json is not a JSON object')
  const { [provider]: _gone, ...rest } = doc
  return JSON.stringify(rest, null, 2) + '\n'
}

/**
 * `witbitz-code uninstall` (the owner: "we should also have an uninstall option"). Removes what witbitz-code put on this
 * computer; asks before the things that are the person's own — saved keys, project notes, OpenCode's sessions (Enter keeps
 * each). `d`:
 *   io { say, ask } · yes (--yes: no confirmation) · removeKeys / removeNotes / removeSessions (--remove-… flags)
 *   service (serviceManager()) · allPairings() · unpair(pairing) → { ok, why } · codeDir · script (the downloaded file, or
 *   '' from the repository) · hasKeys() → names[] · deleteKeys() · removePath(path)
 *   notes() → { root, folders, pluginFiles[] } · sessions() → { dir, exists } · deleteSessions()
 *   openCodeProcesses() → [{ pid, cmd }] (processes with OpenCode's data folder open) · stopProcess(pid) → Promise<boolean>
 *   openCode() → openCodeInstall() + { hint } · removeOpenCodeProgram(info) → Promise<{ ok, why?, said[] }> · removeOpenCode (--remove-opencode)
 */
export async function runUninstall(d) {
  const { io, service: svc } = d
  const ports = svc.installedPorts()
  const pairings = d.allPairings()
  const keys = d.hasKeys()
  const notes = d.notes()
  const sessions = d.sessions()
  io.say('witbitz-code uninstall — removes witbitz-code from this computer.\n')
  io.say('This will:')
  if (ports.length) io.say(`  • stop the background service${ports.length > 1 ? 's' : ''} and stop ${ports.length > 1 ? 'them' : 'it'} starting with the computer`)
  if (pairings.length) io.say(`  • remove this computer from ${[...new Set(pairings.map((p) => p.account || 'your account'))].join(', ')} — your devices stop showing it`)
  io.say(`  • delete ${d.codeDir} (the pairing secrets, files you attached in Code, the Auto-mode log)`)
  if (notes.pluginFiles.length) io.say(`  • remove the project-notes plugin from OpenCode (${notes.pluginFiles.length} file${notes.pluginFiles.length > 1 ? 's' : ''}), so no new notes are written`)
  if (d.script) io.say(`  • delete ${d.script}`)
  io.say('It keeps OpenCode and your projects — and, unless you say so next, your keys, notes and sessions.\n')
  if (!d.yes && !/^y/i.test(await io.ask('Continue? [y/N] '))) { io.say('Nothing changed.'); return { done: false } }

  const ask = async (flag, show, q) => (flag ? true : show && !d.yes ? /^y/i.test(await io.ask(q)) : false)
  const trNote = keys.some((k) => /TrustedRouter/.test(k)) ? ' OpenCode would then no longer reach TrustedRouter.' : ''
  const removeKeys = keys.length ? await ask(d.removeKeys, true, `Also remove your saved ${keys.join(' and ')}?${trNote} [y/N] `) : false
  const removeNotes = notes.folders ? await ask(d.removeNotes, true, `Also delete your project notes — ${notes.folders} project folder${notes.folders > 1 ? 's' : ''} in ${notes.root}? [y/N] `) : false
  let removeSessions = sessions.exists ? await ask(d.removeSessions, true, `Also delete ALL OpenCode sessions on this computer — every conversation, from Code and from the OpenCode app (${sessions.dir}; your provider logins stay)? [y/N] `) : false
  const oc = d.openCode()
  const how = { installer: "from OpenCode's installer, in ~/.opencode", npm: 'with npm', brew: 'with Homebrew' }[oc.kind]
  const removeOpenCode = oc.kind !== 'none' && oc.kind !== 'other'
    ? await ask(d.removeOpenCode, true, `Also remove OpenCode itself (installed ${how})? [y/N] `)
    : false

  const left = []
  for (const port of ports) {
    const r = svc.uninstall(port)
    io.say(r.ok ? `✓ Background service${port !== 4096 ? ` for port ${port}` : ''} stopped and removed` : `✖ Could not remove the background service for port ${port} (${r.why})`)
  }
  // Sessions: an OpenCode that has its database open would write it back — never delete under it. Asked here, after the
  // services (which run OpenCode) are stopped and before anything else goes. What counts is a PROCESS WITH THE DATA FOLDER
  // OPEN, not a port: the owner's test hit an OpenCode on 127.0.0.1:4096 that belonged to another WSL distro (distros share
  // ports) — nothing the person could close, and nothing to do with their sessions. One that is theirs, it offers to stop.
  while (removeSessions) {
    const procs = await d.openCodeProcesses()
    if (!procs.length) break
    const named = procs.map((p) => `${(p.cmd || 'opencode').slice(0, 70)} (process ${p.pid})`).join('; ')
    io.say(`OpenCode is still using the sessions: ${named}.`)
    if (d.yes) { io.say('✖ Keeping the OpenCode sessions.'); removeSessions = false; break }
    const a = await io.ask(`Stop ${procs.length > 1 ? 'them' : 'it'} now? [Y/n] — or type k to keep the sessions: `)
    if (/^k/i.test(a)) { removeSessions = false; break }
    if (/^n/i.test(a)) {
      if (/^k/i.test(await io.ask('Close it yourself, then press Enter — or type k to keep the sessions: '))) removeSessions = false
      continue
    }
    for (const p of procs) io.say((await d.stopProcess(p.pid)) ? `✓ Stopped process ${p.pid}` : `✖ Could not stop process ${p.pid}`)
  }
  for (const p of pairings) {
    let r
    try { r = await d.unpair(p) } catch (e) { r = { ok: false, why: (e && e.message) || String(e) } }
    if (r.ok) io.say(`✓ Removed "${p.name}" from ${p.account || 'your account'}${r.noop ? ' (it was not listed)' : ''}`)
    else { io.say(`✖ Could not remove "${p.name}" from ${p.account || 'your account'} (${r.why})`); left.push(p) }
  }
  if (removeKeys) { d.deleteKeys(); io.say(`✓ Removed the saved ${keys.join(' and ')}`) }
  for (const f of notes.pluginFiles) d.removePath(f)
  if (notes.pluginFiles.length) io.say('✓ Removed the project-notes plugin from OpenCode')
  if (removeNotes) { d.removePath(notes.root); io.say(`✓ Deleted ${notes.root}`) }
  if (removeSessions) { d.deleteSessions(); io.say(`✓ Deleted the OpenCode sessions in ${sessions.dir} (provider logins kept)`) }
  let ocGone = false
  if (removeOpenCode) {
    let r
    try { r = await d.removeOpenCodeProgram(oc) } catch (e) { r = { ok: false, why: (e && e.message) || String(e), said: [] } }
    for (const line of r.said || []) io.say(line)
    if (r.ok) { ocGone = true; io.say('✓ Removed OpenCode') } else io.say(`✖ Could not remove OpenCode (${r.why}) — to do it yourself: ${oc.hint}`)
  }
  d.removePath(d.codeDir)
  io.say(`✓ Deleted ${d.codeDir}`)
  if (d.script) { d.removePath(d.script); io.say(`✓ Deleted ${d.script}`) }
  io.say('')
  if (!ports.length && pairings.length) io.say('If witbitz-code is still running in a terminal window, close that window (Ctrl-C).')
  if (left.length) io.say(`Your phone may still list ${left.map((p) => `"${p.name}"`).join(', ')}: open Code → Settings → Remove there.`)
  if (ocGone) io.say(`witbitz-code and OpenCode are removed. Open a new terminal window so it forgets the old PATH.${removeSessions ? '' : `\nOpenCode's own data stays: ${sessions.dir} (sessions, saved logins) and its settings in ~/.config/opencode — delete those folders to remove everything.`}`)
  else if (oc.kind !== 'none') io.say(`witbitz-code is removed. OpenCode is still installed — to remove it too: ${oc.hint}`)
  else io.say('witbitz-code is removed.')
  return { done: true, left: left.length }
}
