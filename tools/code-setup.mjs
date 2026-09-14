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
import { readFileSync, existsSync, mkdirSync, copyFileSync, writeFileSync, rmSync, chmodSync } from 'node:fs'
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
    logsHint: () => '',
    extraHint: '',
  }
}

// ── the terminal ────────────────────────────────────────────────────────────────────────────────────────────────────────

/** Read one line from a terminal in raw mode — characters echoed, or hidden for a key. A pasted chunk is taken character
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
        if (ch === '\u007f' || ch === '\b') { if (s) { s = s.slice(0, -1); if (!hidden) output.write('\b \b') } continue }
        if (ch < ' ') continue
        s += ch
        if (!hidden) output.write(ch)
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
    const key = await io.secret(`   Paste your ${label} API key (typing is hidden; Enter to skip): `)
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
 *   io { say, ask, secret } · port · name · findOpenCode() → path|'' · installOpenCode() → boolean
 *   pairings() → [] (for this port) · pair() · hasTrustedRouter() · saveTrustedRouterKey(key) · tinfoilKey()
 *   saveTinfoilKey(key) · checkTrustedRouter(key) · checkTinfoil(key) · isListening() · service (serviceManager())
 *   serviceArgs { node, script, path } · bundled · serveHere()
 */
export async function runSetup(d) {
  const { io, port } = d
  const result = { opencode: false, paired: false, trustedrouter: false, tinfoil: false, running: '' }
  io.say(`witbitz-code setup — five steps; anything already done is skipped.\n`)

  // 1 — OpenCode
  io.say('1. OpenCode, the coding agent')
  let oc = d.findOpenCode()
  if (!oc) {
    io.say('   OpenCode is not installed.')
    if (yes(await io.ask('   Install it now with "npm install -g opencode-ai"? [Y/n] '))) {
      if (d.installOpenCode()) oc = d.findOpenCode()
    }
    if (!oc) {
      io.say('   ✖ OpenCode is still not installed. Install it one of these ways, then run setup again:')
      io.say('       npm install -g opencode-ai')
      io.say('       curl -fsSL https://opencode.ai/install | bash      (then open a new terminal)')
      return { ...result, stopped: 'opencode' }
    }
  }
  io.say(`   ✓ OpenCode is installed`)
  result.opencode = true

  // 2 — pairing
  io.say('\n2. This computer and your Witbitz account')
  let mine = d.pairings()
  if (!mine.length) {
    io.say('   On your phone, open Spaces → Settings → Back up & recovery → Add a device, and scan the code below.\n')
    await d.pair()
    mine = d.pairings()
    if (!mine.length) { io.say('   ✖ Pairing did not finish. Run setup again to retry.'); return { ...result, stopped: 'pair' } }
  }
  io.say(`   ✓ Paired: ${mine.map((p) => `"${p.name}" → ${p.account || 'your account'}`).join(', ')}`)
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
    while (await d.isListening()) {
      io.say(`   Something is already running on 127.0.0.1:${port} — most likely an OpenCode you started yourself.`)
      io.say('   Close it (and any opencode window attached to it). Started that way, its TrustedRouter calls are not protected.')
      const a = await io.ask('   Press Enter when it is closed, or type s to stop here: ')
      if (/^s/i.test(a)) { io.say(`   Stopped. When it is closed, run: node witbitz-code.mjs setup`); return { ...result, stopped: 'busy' } }
    }
    if (svc.available() && d.bundled) {
      if (yes(await io.ask('   Start witbitz-code now and every time you log in? [Y/n] '))) {
        const r = svc.install({ ...d.serviceArgs, port })
        if (r.ok) {
          io.say(`   ✓ Running in the background. Logs: ${svc.logsHint(port)}`)
          if (svc.extraHint) io.say(`     ${svc.extraHint}`)
          io.say('     Stop it with: node witbitz-code.mjs service uninstall')
          result.running = 'service'
        } else io.say(`   ✖ Could not start it in the background (${r.why}).`)
      }
    } else if (!d.bundled) io.say('   (Background start is for the downloaded witbitz-code.mjs; from the repository use tools/opencode-serve.sh.)')
    else io.say(`   Background start is not available: ${svc.unavailableWhy}.`)
  }

  if (result.running === 'service') { io.say('\nDone. Open Spaces → ☰ → Code on your phone.'); return result }
  io.say('\nDone. Starting witbitz-code in this window — keep it open (Ctrl-C stops it). Open Spaces → ☰ → Code on your phone.\n')
  result.running = 'here'
  await d.serveHere()
  return result
}
