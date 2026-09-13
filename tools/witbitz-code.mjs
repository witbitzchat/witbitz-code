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
import { spawn, spawnSync } from 'node:child_process'
import { main as pairMain } from './opencode-pair.mjs'
import { startConnector, loadPairings, parseEnvPassword, pairingsForPort } from './opencode-connector.mjs'
import { readFileSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const VERSION = '1.0.0'
const ENV_PATH = process.env.OPENCODE_ENV_FILE || join(homedir(), '.opencode-server.env')

const HELP = `witbitz-code ${VERSION} — reach OpenCode on this computer from the Spaces Code section, end-to-end encrypted.

  pair [--name <name>]         show a QR code; scan it in Spaces (Settings → Back up & recovery → Add a device)
  serve [--port <n>] [--no-opencode]
                               start OpenCode on 127.0.0.1 (unless it is already running) and the connector
  status                       list this computer's pairings
  rotate [--account <email>]   replace the pairing secret(s) without a scan, then restart serve
  unpair [--account <email>]   remove this computer from an account

Nothing listens on the network: OpenCode stays on 127.0.0.1 and the connector dials out to wss://code-relay.witbitz.chat.
`

const flag = (args, name, dflt = '') => { const i = args.indexOf(name); return i >= 0 ? (args[i + 1] || '') : dflt }

async function isListening(port) {
  try { await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1500) }); return true } catch { return false }
}

export { pairingsForPort } // re-exported for the test; one OpenCode per port, one connector per OpenCode

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
    const env = { ...process.env, ...(password ? { OPENCODE_SERVER_PASSWORD: password } : {}) }
    child = spawn('opencode', ['serve', '--port', String(port), '--hostname', '127.0.0.1'], { stdio: 'inherit', env })
    child.on('exit', (code) => { console.error(`witbitz-code: OpenCode exited (${code}) — stopping`); process.exit(code || 0) })
    const stop = () => { try { child.kill() } catch { /* */ } }
    process.on('exit', stop)
    for (let i = 0; i < 40 && !(await isListening(port)); i++) await new Promise((r) => setTimeout(r, 250))
  }
  const c = await startConnector({ pairings: mine })
  console.error(`witbitz-code: serving ${mine.map((p) => `"${p.name}" → ${p.account || 'account'}`).join(', ')} through the sealed relay (Ctrl-C to stop)`)
  const bye = () => { c.stop(); process.exit(0) }
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
  case 'version': case '--version': case '-v': console.log(VERSION); break
  default: console.log(HELP); if (cmd && cmd !== 'help' && cmd !== '--help' && cmd !== '-h') process.exit(2)
}
