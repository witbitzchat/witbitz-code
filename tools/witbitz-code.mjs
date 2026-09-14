// witbitz-code — connect the Spaces Code section to OpenCode on this computer (docs/opencode-relay.md).
//
// The single-file download is this entry bundled with everything it imports (tools/build-witbitz-code.sh →
// spaces/public/downloads/witbitz-code.mjs, covered by the app's signed build certificate). Needs only Node ≥ 22.
//
//   node witbitz-code.mjs pair [--name desk]       scan the QR with the Spaces app → this computer joins that account
//   node witbitz-code.mjs serve [--port 4096]      start OpenCode (if it is not running) and the connector
//   node witbitz-code.mjs status                   what this computer is paired with
//   node witbitz-code.mjs rotate                   new secrets (no scan) — restart serve afterwards
//   node witbitz-code.mjs unpair [--account a@b]   remove this computer from an account
//   node witbitz-code.mjs tinfoil-key              store TINFOIL_API_KEY (read confidentially what a confidential model cannot see)
import { spawn, spawnSync } from 'node:child_process'
import { main as pairMain, envSet, writeSecret } from './opencode-pair.mjs'
import { startConnector, loadPairings, parseEnvPassword, pairingsForPort } from './opencode-connector.mjs'
import { startConfidentialProxy, proxyPortFor, proxyConfig, tinfoilKey } from './code-confidential.mjs'
import { policyConfig, mergeConfig } from './code-opencode-policy.mjs'
import { readFileSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const VERSION = '1.1.0'
const ENV_PATH = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')

const HELP = `witbitz-code ${VERSION} — reach OpenCode on this computer from the Spaces Code section, end-to-end encrypted.

  pair [--name <name>]         show a QR code; scan it in Spaces (Settings → Back up & recovery → Add a device)
  serve [--port <n>] [--no-opencode]
                               start OpenCode on 127.0.0.1 (unless it is already running) and the connector
  status                       list this computer's pairings
  rotate [--account <email>]   replace the pairing secret(s) without a scan, then restart serve
  unpair [--account <email>]   remove this computer from an account
  tinfoil-key                  store your Tinfoil API key: images and files a CONFIDENTIAL model cannot read are read
                               inside Tinfoil's attested enclave with it (you pay Tinfoil; the key stays on this computer)

Nothing listens on the network: OpenCode stays on 127.0.0.1 and the connector dials out to wss://code-relay.witbitz.chat.
`

const flag = (args, name, dflt = '') => { const i = args.indexOf(name); return i >= 0 ? (args[i + 1] || '') : dflt }

async function isListening(port) {
  try { await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1500) }); return true } catch { return false }
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

/** Ask for a secret without echoing it (a TTY in raw mode), else read one line from stdin. */
function readSecret(prompt) {
  return new Promise((resolve) => {
    const input = process.stdin
    process.stderr.write(prompt)
    if (!input.isTTY) { let s = ''; input.setEncoding('utf8'); input.on('data', (c) => { s += c }); input.on('end', () => resolve(s.split(/\r?\n/)[0].trim())); return }
    let s = ''
    input.setRawMode(true); input.resume(); input.setEncoding('utf8')
    const onData = (ch) => {
      if (ch === '\u0003') { input.setRawMode(false); process.stderr.write('\n'); process.exit(130) }
      if (ch === '\r' || ch === '\n' || ch === '\u0004') { input.setRawMode(false); input.pause(); input.off('data', onData); process.stderr.write('\n'); return resolve(s.trim()) }
      if (ch === '\u007f' || ch === '\b') { s = s.slice(0, -1); return }
      s += ch
    }
    input.on('data', onData)
  })
}

async function setTinfoilKey() {
  const key = await readSecret('Tinfoil API key (from tinfoil.sh — input hidden): ')
  if (!key) { console.error('witbitz-code: no key entered — nothing changed'); process.exit(1) }
  const text = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, 'utf8') : ''
  writeSecret(ENV_PATH, envSet(text, 'TINFOIL_API_KEY', key))
  console.error(`witbitz-code: saved TINFOIL_API_KEY in ${ENV_PATH} (only you can read it). It is used from the next message — no restart needed.`)
}

async function serve(args) {
  const port = Number(flag(args, '--port', '4096')) || 4096
  const all = loadPairings(undefined, () => {})
  if (!all.length) {
    console.error('witbitz-code: this computer is not paired yet — run: witbitz-code pair')
    process.exit(1)
  }
  const mine = pairingsForPort(all, port)
  if (!mine.length) {
    console.error(`witbitz-code: no pairing uses OpenCode on port ${port} — pair with: witbitz-code pair --port ${port}`)
    process.exit(1)
  }
  let child = null
  if (!(await isListening(port)) && !args.includes('--no-opencode')) {
    const found = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['opencode'], { encoding: 'utf8' })
    if (found.status !== 0) {
      console.error('witbitz-code: OpenCode is not installed (or not on PATH). Install it, then run serve again:')
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
    child = spawn('opencode', ['serve', '--port', String(port), '--hostname', '127.0.0.1'], { stdio: 'inherit', env })
    child.on('exit', (code) => { console.error(`witbitz-code: OpenCode exited (${code}) — stopping`); process.exit(code || 0) })
    const stop = () => { try { child.kill() } catch { /* */ } }
    process.on('exit', stop)
    for (let i = 0; i < 40 && !(await isListening(port)); i++) await new Promise((r) => setTimeout(r, 250))
  }
  let proxy = null
  try { proxy = await startConfidentialProxy({ port: proxyPortFor(port) }) } catch (e) {
    console.error(`witbitz-code: could not start the confidential-model proxy on 127.0.0.1:${proxyPortFor(port)} (${(e && e.code) || (e && e.message)})`)
  }
  if (proxy && !child) console.error(`witbitz-code: OpenCode was already running, so its TrustedRouter calls do not go through the confidential-model proxy and its subagents do not ask for approval — restart it with witbitz-code serve for both`)
  if (proxy && child && hasTrustedRouter()) console.error(`witbitz-code: confidential models are enforced (min_privacy + verified receipts)${tinfoilKey() ? ' and read images through Tinfoil' : ' — add a Tinfoil key (witbitz-code tinfoil-key) for them to read images'}`)
  const c = await startConnector({ pairings: mine })
  console.error(`witbitz-code: serving ${mine.map((p) => `"${p.name}" → ${p.account || 'account'}`).join(', ')} through the sealed relay (Ctrl-C to stop)`)
  const bye = () => { c.stop(); if (proxy) proxy.close(); process.exit(0) }
  process.on('SIGINT', bye); process.on('SIGTERM', bye)
}

const [cmd, ...rest] = process.env.WITBITZ_CODE_IMPORT === '1' ? ['__import__'] : process.argv.slice(2)
switch (cmd) {
  case '__import__': break
  case 'pair': await pairMain(rest); break
  case 'serve': await serve(rest); break
  case 'status': await pairMain(['--status']); break
  case 'rotate': await pairMain(['--rotate', ...rest]); break
  case 'unpair': await pairMain(['--unpair', ...rest]); break
  case 'tinfoil-key': await setTinfoilKey(); break
  case 'version': case '--version': case '-v': console.log(VERSION); break
  default: console.log(HELP); if (cmd && cmd !== 'help' && cmd !== '--help' && cmd !== '-h') process.exit(2)
}
