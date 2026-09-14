// tools/code-outputs.mjs — the connector serves a file a Code reply produced, for the page's automatic preview
// (spaces/public/codeOutputs.js has which files those are; docs/code-attachments.md §8).
//
// The route is the connector's own (GET /witbitz/output?session=&path=[&stat=1]) and never reaches OpenCode. The folder is
// the SESSION's, as OpenCode reports it — never one the page names. Checks, in this order:
//   by name  — an absolute one-line path inside the folder, of a kind the page shows, not secret-looking
//              (refused before the disk is asked, so the route cannot probe what exists elsewhere)
//   by disk  — the REAL path is still inside the folder's real path (no link out), still not secret-looking, still a kind
//              the page shows, a regular file
//   by size  — the bytes fit one relay message; `stat` answers without them, so a card can say "too large"
// What it grants: the agent can already read these files without asking; this only carries one to its owner's phone,
// sealed end to end.
import { realpathSync, statSync, readFileSync } from 'node:fs'
import { posix, basename } from 'node:path'
import { outputKind, outputMime, sensitivePath, validOutputPath } from '../spaces/public/codeOutputs.js'
import { MAX_SERVE_BYTES } from './code-attachments.mjs'

const answer = (st, o) => ({ st, b: JSON.stringify(o) })

export function serveOutput({ directory, path, stat = false, maxBytes = MAX_SERVE_BYTES }) {
  if (typeof directory !== 'string' || !directory.startsWith('/') || !validOutputPath(path)) return answer(400, { error: 'not a file in this session' })
  const dir = posix.normalize(directory).replace(/\/+$/, '')
  const abs = posix.normalize(path)
  if (!dir || !abs.startsWith(dir + '/')) return answer(403, { error: 'that file is outside the session\'s folder' })
  if (sensitivePath(abs.slice(dir.length))) return answer(403, { error: 'not shown: the name looks like a secret' })
  if (!outputKind(abs)) return answer(400, { error: 'not a file the page shows' })
  let realDir = '', real = ''
  try { realDir = realpathSync(dir) } catch { return answer(404, { error: 'the session\'s folder is not on this computer' }) }
  try { real = realpathSync(abs) } catch { return answer(404, { error: 'that file is not on the computer (any more)' }) }
  if (!real.startsWith(realDir + '/')) return answer(403, { error: 'that file leads outside the session\'s folder' })
  if (sensitivePath(real.slice(realDir.length))) return answer(403, { error: 'not shown: the file looks like a secret' })
  const kind = outputKind(real)
  if (!kind) return answer(400, { error: 'not a file the page shows' })
  let st
  try { st = statSync(real) } catch { return answer(404, { error: 'that file is not on the computer (any more)' }) }
  if (!st.isFile()) return answer(400, { error: 'not a file' })
  const meta = { name: basename(abs), kind, mime: outputMime(real), size: st.size, mtime: Math.round(st.mtimeMs) }
  if (stat) return answer(200, meta)
  if (st.size > maxBytes) return answer(413, { ...meta, error: `the file is over ${Math.round(maxBytes / 1048576)} MB — too large to send to the phone` })
  return answer(200, { ...meta, b64: readFileSync(real).toString('base64') })
}
