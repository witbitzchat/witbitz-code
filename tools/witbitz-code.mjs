// witbitz-code — connect the Spaces Code section to OpenCode on this computer (docs/opencode-relay.md).
//
// The single-file download is this entry bundled with everything it imports (tools/build-witbitz-code.sh →
// spaces/public/downloads/witbitz-code.mjs, covered by the app's signed build certificate). Needs only Node ≥ 22.
//
//   node witbitz-code.mjs setup [--port 4096]      the whole setup, step by step (OpenCode, pairing, keys, background start)
//   node witbitz-code.mjs pair [--name desk]       scan the QR with the Spaces app → this computer joins that account
//   node witbitz-code.mjs serve [--port 4096]      start OpenCode (if it is not running) and the connector
//   node witbitz-code.mjs status                   what this computer is paired with
//   node witbitz-code.mjs rotate                   new secrets (no scan) — restart serve afterwards
//   node witbitz-code.mjs unpair [--account a@b]   remove this computer from an account
//   node witbitz-code.mjs tinfoil-key              store TINFOIL_API_KEY (read confidentially what a confidential model cannot see)
//   node witbitz-code.mjs trustedrouter-key        store the TrustedRouter key in OpenCode's credentials (what `opencode auth login` does)
//   node witbitz-code.mjs service install|uninstall|status [--port 4096]   start with the computer (systemd / launchd)
//   node witbitz-code.mjs uninstall [--yes] [--remove-keys|notes|sessions]   remove witbitz-code (keeps OpenCode)
import { spawn, spawnSync } from 'node:child_process'
import { connect as netConnect } from 'node:net'
import { main as pairMain, envSet, writeSecret, unpairEntry } from './opencode-pair.mjs'
import { startConnector, loadPairings, parseEnvPassword, pairingsForPort, PAIRINGS_PATH } from './opencode-connector.mjs'
import { startConfidentialProxy, proxyPortFor, proxyConfig, tinfoilKey } from './code-confidential.mjs'
import { policyConfig, mergeConfig } from './code-opencode-policy.mjs'
import { runSetup, runUninstall, serviceManager, readLine, validKeyShape, checkTinfoilKey, checkTrustedRouterKey, authPath, withAuthKey, withoutAuthKey, withoutEnvKeys, pairingPort, withPairingPort, openCodeInstall, openCodeRemovalHint, shellStartupFiles, withoutOpenCodePath } from './code-setup.mjs'
import { readFileSync, existsSync, mkdirSync, rmSync, readdirSync, readlinkSync, realpathSync, rmdirSync, accessSync, writeFileSync, copyFileSync, constants as fsConstants } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const VERSION = '1.2.0'
const ENV_PATH = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')

const HELP = `witbitz-code ${VERSION} — reach OpenCode on this computer from the Spaces Code section, end-to-end encrypted.

  setup [--port <n>] [--name <name>]
                               START HERE — installs OpenCode if needed, pairs, asks for your TrustedRouter and Tinfoil
                               keys, and keeps it running in the background. Safe to run again; done steps are skipped.
  pair [--name <name>]         show a QR code; scan it in Spaces (Settings → Back up & recovery → Add a device)
  serve [--port <n>] [--no-opencode]
                               start OpenCode on 127.0.0.1 (unless it is already running) and the connector
  status                       list this computer's pairings
  rotate [--account <email>]   replace the pairing secret(s) without a scan, then restart serve
  unpair [--account <email>]   remove this computer from an account
  tinfoil-key                  store your Tinfoil API key: images and files a CONFIDENTIAL model cannot read are read
                               inside Tinfoil's attested enclave with it (you pay Tinfoil; the key stays on this computer)
  trustedrouter-key            store your TrustedRouter API key in OpenCode's credentials (same as opencode auth login)
  service install|uninstall|status [--port <n>]
                               start witbitz-code with the computer (systemd user service on Linux, launchd on macOS)
  uninstall [--yes] [--remove-keys] [--remove-notes] [--remove-sessions] [--remove-opencode]
                               remove witbitz-code from this computer: the background service, this computer from your
                               accounts, its files — and, if you say so, the saved keys, project notes, OpenCode
                               sessions and OpenCode itself. Your projects always stay.

Nothing listens on the network: OpenCode stays on 127.0.0.1 and the connector dials out to wss://code-relay.witbitz.chat.
`

const flag = (args, name, dflt = '') => { const i = args.indexOf(name); return i >= 0 ? (args[i + 1] || '') : dflt }

/** Is anything accepting TCP connections on 127.0.0.1:port? A plain connect, not an HTTP request: a listener that does not
 *  speak HTTP (measured: sshd on 22) made the fetch throw, looked free, and OpenCode then failed to bind (ServeError). */
function isListening(port) {
  return new Promise((resolve) => {
    const sock = netConnect({ host: '127.0.0.1', port })
    const done = (v) => { sock.destroy(); resolve(v) }
    sock.setTimeout(1500, () => done(false))
    sock.once('connect', () => done(true))
    sock.once('error', () => done(false))
  })
}

export { pairingsForPort } // re-exported for the test; one OpenCode per port, one connector per OpenCode

/** Does OpenCode here have TrustedRouter credentials (the env, or `opencode auth login`)? Only then are the confidential
 *  models declared — otherwise they would show up on the menu of a computer that cannot call them. */
export function hasTrustedRouter(env = process.env) {
  if (env.TRUSTEDROUTER_API_KEY) return true
  try {
    const auth = JSON.parse(readFileSync(join(env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'opencode', 'auth.json'), 'utf8'))
    return !!(auth && auth.trustedrouter)
  } catch { return false }
}

const saveTinfoilKey = (key) => {
  const text = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, 'utf8') : ''
  writeSecret(ENV_PATH, envSet(text, 'TINFOIL_API_KEY', key))
}
/** The key goes into OpenCode's own credentials file — never into OpenCode's environment, which every shell command the
 *  agent runs inherits. */
const saveTrustedRouterKey = (key) => {
  const file = authPath()
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  writeSecret(file, withAuthKey(existsSync(file) ? readFileSync(file, 'utf8') : '', 'trustedrouter', key))
}

/** `tinfoil-key` / `trustedrouter-key`: ask (hidden), check with the provider, save. A key the provider rejects is not saved. */
async function setKey({ label, check, save, where, after }) {
  const key = await readLine(`${label} API key (it shows as *****): `, { hidden: true })
  if (!key) { console.error('witbitz-code: no key entered — nothing changed'); process.exit(1) }
  if (!validKeyShape(key)) { console.error('witbitz-code: that does not look like an API key (no spaces, 8–512 characters) — nothing changed'); process.exit(1) }
  const v = await check(key)
  if (v.ok === false) { console.error(`witbitz-code: ${v.why} — nothing changed`); process.exit(1) }
  save(key)
  console.error(`witbitz-code: saved in ${where} (only you can read it)${v.ok === null ? ` without checking it — ${v.why}` : ''}. ${after}`)
}

async function serve(args) {
  const port = Number(flag(args, '--port', '4096')) || 4096
  const all = loadPairings(undefined, () => {})
  if (!all.length) {
    console.error('witbitz-code: this computer is not paired yet — run: node witbitz-code.mjs setup')
    process.exit(1)
  }
  const mine = pairingsForPort(all, port)
  if (!mine.length) {
    console.error(`witbitz-code: no pairing uses OpenCode on port ${port} — pair with: witbitz-code pair --port ${port}`)
    process.exit(1)
  }
  let child = null
  if (!(await isListening(port)) && !args.includes('--no-opencode')) {
    if (!findOpenCode()) {
      console.error('witbitz-code: OpenCode is not installed (or not on PATH). Run node witbitz-code.mjs setup, or install it and run serve again:')
      console.error('  npm install -g opencode-ai        or        curl -fsSL https://opencode.ai/install | bash')
      process.exit(1)
    }
    const password = existsSync(ENV_PATH) ? parseEnvPassword(readFileSync(ENV_PATH, 'utf8')) : ''
    console.error(`witbitz-code: starting OpenCode on 127.0.0.1:${port}`)
    // Merged by OpenCode over the user's own config — their opencode.json is never written. ALWAYS the approvals policy
    // (subagents ask like their parent; a refusal does not end the turn — code-opencode-policy.mjs), and TrustedRouter
    // through the confidential-model proxy (below) only where TrustedRouter is actually connected.
    const content = mergeConfig(policyConfig(), hasTrustedRouter() ? proxyConfig(proxyPortFor(port)) : {})
    const env = { ...process.env, ...(password ? { OPENCODE_SERVER_PASSWORD: password } : {}), OPENCODE_CONFIG_CONTENT: JSON.stringify(content) }
    // The Tinfoil key is the proxy's (this process reads it). Handed to OpenCode it would be in every shell the agent runs,
    // and OpenCode would list Tinfoil as a plain provider whose attestation nothing checks.
    delete env.TINFOIL_API_KEY
    child = spawn('opencode', ['serve', '--port', String(port), '--hostname', '127.0.0.1'], { stdio: 'inherit', env })
    child.on('exit', (code) => { console.error(`witbitz-code: OpenCode exited (${code}) — stopping`); process.exit(code || 0) })
    const stop = () => { try { child.kill() } catch { /* */ } }
    process.on('exit', stop)
    for (let i = 0; i < 40 && !(await isListening(port)); i++) await new Promise((r) => setTimeout(r, 250))
  }
  let proxy = null, c = null
  try { proxy = await startConfidentialProxy({ port: proxyPortFor(port), onProgress: (ev) => { if (c) c.progress(ev) } }) } catch (e) {
    console.error(`witbitz-code: could not start the confidential-model proxy on 127.0.0.1:${proxyPortFor(port)} (${(e && e.code) || (e && e.message)})`)
  }
  if (proxy && !child) console.error(`witbitz-code: OpenCode was already running, so its TrustedRouter calls do not go through the confidential-model proxy and its subagents do not ask for approval — restart it with witbitz-code serve for both`)
  if (proxy && child && hasTrustedRouter()) console.error(`witbitz-code: confidential models are enforced (min_privacy + verified receipts)${tinfoilKey() ? ' and read images through Tinfoil' : ' — add a Tinfoil key (witbitz-code tinfoil-key) for them to read images'}`)
  c = await startConnector({ pairings: mine })
  console.error(`witbitz-code: serving ${mine.map((p) => `"${p.name}" → ${p.account || 'account'}`).join(', ')} through the sealed relay (Ctrl-C to stop)`)
  const bye = () => { c.stop(); if (proxy) proxy.close(); process.exit(0) }
  process.on('SIGINT', bye); process.on('SIGTERM', bye)
}

const portArg = (args) => {
  const port = Number(flag(args, '--port', '4096'))
  if (!Number.isInteger(port) || port < 1 || port > 65535) { console.error('witbitz-code: --port needs a port number'); process.exit(2) }
  return port
}

/** OpenCode on PATH, or where its own installer puts it (~/.opencode/bin — added to PATH here, so serve and the service find it). */
function findOpenCode() {
  const found = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['opencode'], { encoding: 'utf8' })
  if (found.status === 0 && found.stdout.trim()) return found.stdout.trim().split(/\r?\n/)[0]
  const own = join(homedir(), '.opencode', 'bin', 'opencode')
  if (existsSync(own)) { process.env.PATH = `${dirname(own)}:${process.env.PATH || ''}`; return own }
  return ''
}

async function setup(args) {
  if (!process.stdin.isTTY) { console.error('witbitz-code: setup asks questions — run it in a terminal'); process.exit(2) }
  const port = portArg(args)
  const name = flag(args, '--name')
  const say = (m) => console.error(m)
  await runSetup({
    io: { say, ask: (q) => readLine(q), secret: (q) => readLine(q, { hidden: true }) },
    port,
    findOpenCode,
    openCodeInstallPlans,
    installOpenCode: (kind) => (kind === 'npm'
      ? spawnSync('npm', ['install', '-g', 'opencode-ai'], { stdio: 'inherit' }).status === 0
      // measured 2026-09-14: non-interactive, no sudo, ~4 s — ~/.opencode/bin/opencode plus a "# opencode" PATH line
      // (the layout `uninstall` removes); findOpenCode() then puts ~/.opencode/bin on this process's PATH
      : spawnSync('bash', ['-c', 'curl -fsSL https://opencode.ai/install | bash'], { stdio: 'inherit' }).status === 0),
    portExplicit: args.includes('--port'),
    allPairings: () => loadPairings(undefined, () => {}),
    portOf: pairingPort,
    // --port always: an OpenCode asked for moves an account already paired (upsertPairing)
    pair: (p) => pairMain([...(name ? ['--name', name] : []), '--port', String(p)]),
    movePairing: (p, to) => writeSecret(PAIRINGS_PATH, JSON.stringify(withPairingPort(JSON.parse(readFileSync(PAIRINGS_PATH, 'utf8')), p, to), null, 1) + '\n'),
    hasTrustedRouter: () => hasTrustedRouter(),
    saveTrustedRouterKey,
    checkTrustedRouter: (k) => checkTrustedRouterKey(k),
    tinfoilKey: () => tinfoilKey(),
    saveTinfoilKey,
    checkTinfoil: (k) => checkTinfoilKey(k),
    isListening: (p) => isListening(p),
    portOwners: (p) => portOwners(p),
    wsl: (() => { try { return /microsoft/i.test(readFileSync('/proc/version', 'utf8')) } catch { return false } })(),
    stopProcess,
    freePort: async (from) => {
      for (let p = Math.max(from, 1024); p + 100 < 65536; p++) if (!(await isListening(p)) && !(await isListening(p + 100))) return p
      return from
    },
    service: serviceManager(),
    // read at step 5 — after step 1 may have put OpenCode's own bin folder on PATH
    get serviceArgs() { return { node: process.execPath, script: fileURLToPath(import.meta.url), path: process.env.PATH || '' } },
    bundled: process.env.WITBITZ_CODE_BUNDLED === '1',
    serveHere: (p) => serve(['--port', String(p)]),
  })
}

/** Stop a process: SIGTERM, up to 5 s, then SIGKILL. Gone = no such process, or a zombie (exited, not yet reaped by its
 *  parent — measured: kill(pid, 0) still succeeds on one). */
async function stopProcess(pid) {
  const gone = () => { try { process.kill(pid, 0) } catch { return true } try { return /^\d+ \(.*\) Z/.test(readFileSync(`/proc/${pid}/stat`, 'utf8')) } catch { return false } }
  try { process.kill(pid, 'SIGTERM') } catch { return gone() }
  for (let i = 0; i < 50; i++) { await new Promise((r) => setTimeout(r, 100)); if (gone()) return true }
  try { process.kill(pid, 'SIGKILL') } catch { /* gone meanwhile */ }
  await new Promise((r) => setTimeout(r, 300))
  return gone()
}

/** This user's processes LISTENING on a TCP port. Linux: the LISTEN sockets in /proc/net/tcp{,6} for that port, then the
 *  processes whose fds point at those socket inodes (measured: 4096 → `opencode serve`; system listeners on 22/53 and
 *  another WSL distro's show no owner — they are not this person's). macOS: lsof. */
function portOwners(port) {
  const hits = []
  if (existsSync('/proc/net/tcp')) {
    const inodes = new Set()
    for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
      let text = ''
      try { text = readFileSync(f, 'utf8') } catch { continue }
      for (const line of text.split('\n').slice(1)) {
        const c = line.trim().split(/\s+/)
        if (c.length >= 10 && c[3] === '0A' && parseInt(c[1].split(':').pop(), 16) === port) inodes.add(c[9])
      }
    }
    if (!inodes.size) return hits
    for (const p of readdirSync('/proc')) {
      if (!/^\d+$/.test(p) || Number(p) === process.pid) continue
      let fds
      try { fds = readdirSync(`/proc/${p}/fd`) } catch { continue }
      const owns = fds.some((f) => { try { const m = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${p}/fd/${f}`)); return !!m && inodes.has(m[1]) } catch { return false } })
      if (!owns) continue
      let cmd = ''
      try { cmd = readFileSync(`/proc/${p}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' ') } catch { /* gone */ }
      hits.push({ pid: Number(p), cmd })
    }
    return hits
  }
  const r = spawnSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'], { encoding: 'utf8' })
  for (const pid of new Set(String(r.stdout || '').split(/\s+/).filter(Boolean).map(Number))) {
    if (!pid || pid === process.pid) continue
    hits.push({ pid, cmd: String(spawnSync('ps', ['-o', 'command=', '-p', String(pid)], { encoding: 'utf8' }).stdout || '').trim() })
  }
  return hits
}

/** This user's processes that have OpenCode's data folder open — the only ones deleting the sessions would pull files out
 *  from under. Linux reads /proc (measured: finds `opencode serve` holding opencode.db in ~1 ms); macOS asks lsof. */
function openCodeHolders(dir) {
  const hits = []
  if (existsSync('/proc/self/fd')) {
    for (const p of readdirSync('/proc')) {
      if (!/^\d+$/.test(p) || Number(p) === process.pid) continue
      let fds
      try { fds = readdirSync(`/proc/${p}/fd`) } catch { continue } // another user's process: not readable, and not ours
      const holds = fds.some((f) => { try { const l = readlinkSync(`/proc/${p}/fd/${f}`); return l === dir || l.startsWith(dir + '/') } catch { return false } })
      if (!holds) continue
      let cmd = ''
      try { cmd = readFileSync(`/proc/${p}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' ') } catch { /* gone */ }
      hits.push({ pid: Number(p), cmd })
    }
    return hits
  }
  const files = ['opencode.db', 'opencode.db-wal', 'opencode.db-shm'].map((f) => join(dir, f)).filter((f) => existsSync(f))
  if (!files.length) return hits
  const r = spawnSync('lsof', ['-t', '--', ...files], { encoding: 'utf8' })
  for (const pid of new Set(String(r.stdout || '').split(/\s+/).filter(Boolean).map(Number))) {
    if (!pid || pid === process.pid) continue
    hits.push({ pid, cmd: String(spawnSync('ps', ['-o', 'command=', '-p', String(pid)], { encoding: 'utf8' }).stdout || '').trim() })
  }
  return hits
}

/** The ways to install OpenCode that work here without sudo, best first. */
function openCodeInstallPlans() {
  const has = (cmd) => spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { encoding: 'utf8' }).status === 0
  const plans = []
  if (has('npm')) {
    const root = String(spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout || '').trim()
    let writable = false
    try { if (root) { accessSync(existsSync(root) ? root : dirname(root), fsConstants.W_OK); writable = true } } catch { /* needs sudo */ }
    if (writable) plans.push({ kind: 'npm', label: 'with npm ("npm install -g opencode-ai")' })
  }
  if (has('curl') && has('bash')) plans.push({ kind: 'installer', label: `with OpenCode's installer ("curl -fsSL https://opencode.ai/install | bash" — into ~/.opencode, no sudo; it adds OpenCode to your PATH)` })
  return plans
}

/** OpenCode on this computer: how it was installed, and the command that removes it. */
function openCodeHere() {
  const path = findOpenCode()
  let real = path
  try { real = path ? realpathSync(path) : '' } catch { /* a dangling link: use the path */ }
  const info = openCodeInstall({ path, real, home: homedir() })
  let npmNeedsSudo = false
  if (info.kind === 'npm') {
    const root = String(spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout || '').trim()
    try { accessSync(root, fsConstants.W_OK) } catch { npmNeedsSudo = true }
  }
  return { ...info, npmNeedsSudo, hint: openCodeRemovalHint(info, { npmNeedsSudo }) }
}

/** Remove OpenCode the way it was installed. Never runs sudo — that is said instead. Checked afterwards: gone is gone. */
async function removeOpenCodeProgram(info) {
  const said = []
  if (info.kind === 'installer') {
    rmSync(info.dir, { recursive: true, force: true })
    for (const f of shellStartupFiles(homedir(), process.env)) {
      let text
      try { text = readFileSync(f, 'utf8') } catch { continue }
      const r = withoutOpenCodePath(text, info.binDir)
      if (!r.changed) continue
      copyFileSync(f, `${f}.before-witbitz-uninstall`)
      writeFileSync(f, r.text)
      said.push(`✓ Removed OpenCode's PATH line from ${f} (the file as it was: ${f}.before-witbitz-uninstall)`)
    }
  } else if (info.kind === 'npm') {
    if (info.npmNeedsSudo) return { ok: false, why: "npm's global folder needs sudo here", said }
    spawnSync('npm', ['uninstall', '-g', 'opencode-ai'], { stdio: 'inherit' })
  } else if (info.kind === 'brew') {
    spawnSync('brew', ['uninstall', 'opencode'], { stdio: 'inherit' })
  } else return { ok: false, why: 'unknown install', said }
  return existsSync(info.path) ? { ok: false, why: `${info.path} is still there`, said } : { ok: true, said }
}

async function uninstall(args) {
  const yes = args.includes('--yes')
  if (!yes && !process.stdin.isTTY) { console.error('witbitz-code: uninstall asks before it removes anything — run it in a terminal, or pass --yes'); process.exit(2) }
  const codeDir = join(homedir(), '.witbitz', 'code')
  const self = fileURLToPath(import.meta.url)
  const authFile = authPath()
  const hasTR = () => { try { return !!JSON.parse(readFileSync(authFile, 'utf8')).trustedrouter } catch { return false } }
  const r = await runUninstall({
    io: { say: (m) => console.error(m), ask: (q) => readLine(q) },
    yes,
    removeKeys: args.includes('--remove-keys'),
    removeNotes: args.includes('--remove-notes'),
    removeSessions: args.includes('--remove-sessions'),
    service: serviceManager(),
    allPairings: () => loadPairings(undefined, () => {}),
    unpair: (p) => unpairEntry(p),
    codeDir,
    // the downloaded file deletes itself; run from the repository, the source stays
    script: process.env.WITBITZ_CODE_BUNDLED === '1' ? self : '',
    // saved keys only — a key that lives in the shell's environment is not this tool's to remove
    hasKeys: () => [...(existsSync(ENV_PATH) && /^\s*(?:export\s+)?TINFOIL_API_KEY=/m.test(readFileSync(ENV_PATH, 'utf8')) ? ['Tinfoil key'] : []), ...(hasTR() ? ["TrustedRouter key (in OpenCode's credentials)"] : [])],
    deleteKeys: () => {
      if (existsSync(ENV_PATH)) writeSecret(ENV_PATH, withoutEnvKeys(readFileSync(ENV_PATH, 'utf8'), ['TINFOIL_API_KEY']))
      if (hasTR()) writeSecret(authFile, withoutAuthKey(readFileSync(authFile, 'utf8'), 'trustedrouter'))
    },
    removePath: (path) => rmSync(path, { recursive: true, force: true }),
    // project notes: the folder the witbitz-notes plugin writes, and the plugin files tools/opencode-config.mjs installs (the
    // progress plugin with them — it keeps nothing of its own)
    notes: () => {
      const root = process.env.WITBITZ_NOTES_DIR || join(homedir(), '.local', 'share', 'witbitz-notes')
      const cfg = join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'opencode')
      let folders = 0
      try { folders = readdirSync(root, { withFileTypes: true }).filter((e) => e.isDirectory()).length } catch { /* none */ }
      return { root, folders, pluginFiles: [join(cfg, 'plugins', 'witbitz-notes.js'), join(cfg, 'plugins', 'witbitz-progress.js'), join(cfg, 'commands', 'notes-init.md'), join(cfg, 'witbitz-confidential-models.json')].filter((f) => existsSync(f)) }
    },
    // OpenCode's sessions: its whole data folder except auth.json (the provider logins)
    sessions: () => { const dir = dirname(authFile); return { dir, exists: existsSync(dir) && readdirSync(dir).some((f) => f !== 'auth.json') } },
    deleteSessions: () => { const dir = dirname(authFile); for (const f of readdirSync(dir)) if (f !== 'auth.json') rmSync(join(dir, f), { recursive: true, force: true }) },
    openCodeProcesses: () => openCodeHolders(dirname(authFile)),
    openCode: openCodeHere,
    removeOpenCode: args.includes('--remove-opencode'),
    removeOpenCodeProgram,
    stopProcess,
  })
  if (r.done) try { rmdirSync(join(homedir(), '.witbitz')) } catch { /* not empty: something else of the person's lives there */ }
  // a pairings file kept somewhere else (WITBITZ_CODE_PAIRINGS) goes too once every account let go of this computer
  if (r.done && !r.left && PAIRINGS_PATH !== join(codeDir, 'pairings.json')) rmSync(PAIRINGS_PATH, { force: true })
}

async function service(args) {
  const [action] = args
  const port = portArg(args)
  const svc = serviceManager()
  if (action === 'status') { console.log(`${svc.kind === 'none' ? 'unsupported' : svc.status(port)}${svc.logsHint(port) ? ` · logs: ${svc.logsHint(port)}` : ''}`); return }
  if (action === 'uninstall') {
    const r = svc.uninstall(port)
    console.error(r.noop ? 'witbitz-code: no background service was installed' : 'witbitz-code: ✓ stopped, and it no longer starts with the computer (pairing and keys are kept)')
    return
  }
  if (action !== 'install') { console.error('witbitz-code: service install | uninstall | status [--port <n>]'); process.exit(2) }
  if (process.env.WITBITZ_CODE_BUNDLED !== '1') { console.error('witbitz-code: run this from the downloaded witbitz-code.mjs (from the repository, use tools/opencode-serve.sh)'); process.exit(2) }
  if (!svc.available()) { console.error(`witbitz-code: background start is not available — ${svc.unavailableWhy}`); process.exit(1) }
  if (!pairingsForPort(loadPairings(undefined, () => {}), port).length) { console.error('witbitz-code: pair first — node witbitz-code.mjs setup'); process.exit(1) }
  if (!findOpenCode()) { console.error('witbitz-code: OpenCode is not installed — node witbitz-code.mjs setup'); process.exit(1) }
  if (svc.status(port) !== 'active' && (await isListening(port))) { console.error(`witbitz-code: something is already running on 127.0.0.1:${port} (an OpenCode you started?) — close it first`); process.exit(1) }
  const r = svc.install({ node: process.execPath, script: fileURLToPath(import.meta.url), path: process.env.PATH || '', port })
  if (!r.ok) { console.error(`witbitz-code: ✖ ${r.why}`); process.exit(1) }
  console.error(`witbitz-code: ✓ running in the background and starting with the computer. Logs: ${svc.logsHint(port)}`)
}

const [cmd, ...rest] = process.env.WITBITZ_CODE_IMPORT === '1' ? ['__import__'] : process.argv.slice(2)
switch (cmd) {
  case '__import__': break
  case 'pair': await pairMain(rest); break
  case 'serve': await serve(rest); break
  case 'status': await pairMain(['--status']); break
  case 'rotate': await pairMain(['--rotate', ...rest]); break
  case 'unpair': await pairMain(['--unpair', ...rest]); break
  case 'setup': await setup(rest); break
  case 'service': await service(rest); break
  case 'uninstall': await uninstall(rest); break
  case 'tinfoil-key': await setKey({ label: 'Tinfoil', check: checkTinfoilKey, save: saveTinfoilKey, where: ENV_PATH, after: 'It is used from the next message — no restart needed.' }); break
  case 'trustedrouter-key': await setKey({ label: 'TrustedRouter', check: checkTrustedRouterKey, save: saveTrustedRouterKey, where: authPath(), after: 'Restart witbitz-code (or its background service) so OpenCode picks it up.' }); break
  case 'version': case '--version': case '-v': console.log(VERSION); break
  default: console.log(HELP); if (cmd && cmd !== 'help' && cmd !== '--help' && cmd !== '-h') process.exit(2)
}
