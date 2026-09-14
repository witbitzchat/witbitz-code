// tools/code-tools-probe.mjs — which suggested tools this computer has (spaces/public/codeTools.js), for "Set up this computer".
//
// A PATH lookup, nothing else: no process is started, no model is asked, nothing is installed. The connector answers the
// page's nonce-checked `{t:'tools'}` with this. Common install folders are searched too, because a connector started by a
// service manager often has a thinner PATH than the shell OpenCode's commands run in. The Python connector's
// witbitz_code/tools_probe.py gives the same answers (packages/witbitz-code-py/tests/test_tools_probe.py runs both).
//
//   probeTools({ env, platform, home, isExecutable }) → { tools: { ffmpeg: true, … }, platform: { os, pm } }
import { accessSync, statSync, constants } from 'node:fs'
import { homedir } from 'node:os'
import { TOOLS, PACKAGE_MANAGERS } from '../spaces/public/codeTools.js'

const EXTRA_POSIX = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/snap/bin', '/home/linuxbrew/.linuxbrew/bin']
const EXTRA_HOME = ['.local/bin', '.cargo/bin', 'bin']

function defaultIsExecutable(path) {
  try {
    if (!statSync(path).isFile()) return false
    accessSync(path, constants.X_OK)
    return true
  } catch { return false }
}

/** The folders searched, in order, without repeats. */
export function searchDirs({ env = process.env, platform = process.platform, home = homedir() } = {}) {
  const win = platform === 'win32'
  const sep = win ? ';' : ':'
  const fromPath = String(env.PATH || env.Path || '').split(sep).filter(Boolean)
  const extra = win ? [] : [...EXTRA_POSIX, ...(home ? EXTRA_HOME.map((d) => `${home.replace(/\/+$/, '')}/${d}`) : [])]
  return [...new Set([...fromPath, ...extra])]
}

export function probeTools({ env = process.env, platform = process.platform, home = homedir(), isExecutable = defaultIsExecutable } = {}) {
  const win = platform === 'win32'
  const dirs = searchDirs({ env, platform, home })
  const exts = win ? ['', ...String(env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean).map((e) => e.toLowerCase())] : ['']
  const join = (d, b) => (win ? `${d.replace(/[\\/]+$/, '')}\\${b}` : `${d.replace(/\/+$/, '')}/${b}`)
  const has = (bin) => dirs.some((d) => exts.some((e) => isExecutable(join(d, bin + e))))
  const tools = {}
  for (const t of TOOLS) tools[t.id] = t.bins.filter((b) => !(win && b === 'convert')).some(has) // Windows' convert.exe is not ImageMagick
  const os = Object.hasOwn(PACKAGE_MANAGERS, platform) ? platform : ''
  const pm = os ? (PACKAGE_MANAGERS[os].find(([, bin]) => has(bin)) || [''])[0] : ''
  return { tools, platform: { os, pm } }
}
