// opencode-config: write ~/.config/opencode/opencode.json from agent/modelCatalog.mjs.
//
//   node tools/opencode-config.mjs --print     → show the JSON, touch nothing
//   node tools/opencode-config.mjs             → write it (keeps a .bak of what was there)
//
// Why this exists at all: the catalog is the one place that knows which TrustedRouter models we offer and which of
// them can take pixels, and opencode needs that SAME knowledge declared in its own vocabulary before it will let a
// file part through. Hand-maintaining the second copy is how the two drift — and the drift is invisible, because
// opencode does not complain about a model it thinks is text-only, it just silently drops the image.
//
// Three findings are baked in here; each one cost a measurement, so they are written down rather than rediscovered:
//
//  1. ★ The key is `attachment` + `modalities`, NOT `capabilities`. A `capabilities` block is accepted by the schema
//     and then IGNORED — the server reported `input: []` and `tools: false` for every model while the config looked
//     perfectly reasonable. That is what "the files cannot be read by the agent" actually was.
//  2. ★ opencode injects `reasoning_effort:"medium"` for gpt-5-family ids off a hardcoded model-ID heuristic — there
//     is no config key for it (the published schema has none). TrustedRouter then REWRITES low/medium/high into
//     Anthropic's `thinking` and forwards that to the OpenAI upstream, which rejects it: `Unknown parameter:
//     'thinking'`. `none` and `minimal` are passed through untouched, so `reasoningEffort: 'none'` (camelCase — the
//     snake_case spelling is ignored) is the one value that gets GPT-5.1 a reply. Drop the option when TR is fixed.
//  3. A model's `vision` flag here is about the ROUTE, not the model. Do not "verify" it with a tiny test image:
//     grok-4.6 and gemma-4-uncensored both 400 on a 16×16 PNG ("Supplied image did not pass validation checks")
//     and both read a 256×256 one perfectly. A too-small probe reads exactly like a blind model.
//  4. ★ NO MODEL HERE TAKES A PDF, because the ROUTE cannot carry one. opencode sends the standard OpenAI file part
//     ({type:'file',file:{filename,file_data}}) and TrustedRouter's chat-completions surface answers 502
//     `provider error` for every model and every variant (with/without cache_control, data: URL or bare base64) —
//     the {"message":"provider error"} a PDF produced in the section. The SAME PDF read perfectly on TR's
//     /v1/messages (Anthropic-native `document` block), so this is the transport, not the models. Declaring `pdf`
//     here would only make opencode send bytes that die; with it absent, the client reads the document with our own
//     pdf.js and sends the text (spaces/public/pdfText.js), which works on all 18. Revisit if the section ever
//     speaks /v1/messages, or when TR accepts the file part.
import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { CATALOG, DEFAULTS } from '../agent/modelCatalog.mjs'
import { policyConfig } from './code-opencode-policy.mjs' // subagents ask like their parent; a refusal does not end the turn

const CONFIG_DIR = join(homedir(), '.config', 'opencode')
const OUT = join(CONFIG_DIR, 'opencode.json')
const NOTES_ROOT = process.env.WITBITZ_NOTES_DIR || join(homedir(), '.local', 'share', 'witbitz-notes')
const HERE = dirname(fileURLToPath(import.meta.url))
// TR's chat-completions surface takes images as data URLs; it takes PDFs on NO model (finding 4). A route marked
// `vision:false` takes neither. `attachment` is what opencode gates the file part on; `modalities.input` is what it
// shows the model — and what the client reads to decide whether a PDF must be turned into text first.
const inputsFor = (m) => (m.vision === false ? ['text'] : ['text', 'image'])

/** `proxyPort`: TrustedRouter goes through the connector's confidential-model proxy (tools/code-confidential.mjs). Only
 *  then does "· confidential" appear — without the proxy nothing enforces it, so the label would be a claim, not a fact —
 *  and a text-only confidential model is declared able to take images, because the proxy reads them through Tinfoil. */
export function buildConfig({ proxyPort = 0, notesRoot = NOTES_ROOT } = {}) {
  const models = {}
  for (const m of CATALOG) {
    if (m.route !== 'trustedrouter') continue // openai-direct has no OpenAI-compatible base URL of ours to point at
    const confidential = !!proxyPort && !!m.tiers?.includes('confidential')
    const inputs = confidential ? ['text', 'image'] : inputsFor(m)
    models[m.model] = {
      name: confidential ? `${m.label} · confidential` : m.label,
      attachment: inputs.includes('image'),
      tool_call: true,
      reasoning: false,
      modalities: { input: inputs, output: ['text'] },
      limit: { context: 200_000, output: m.params?.max_tokens ?? 16_000 },
      // finding 2 — without this GPT-5.1 cannot complete a single turn through TrustedRouter
      ...(m.model.includes('gpt-5') ? { options: { reasoningEffort: 'none' } } : {}),
    }
  }
  const fallback = CATALOG.find((m) => m.id === DEFAULTS.confidential && m.route === 'trustedrouter')
  return {
    $schema: 'https://opencode.ai/config.json',
    // The Code section's approvals reach subagents, and a refused call does not end the turn (code-opencode-policy.mjs).
    ...policyConfig(),
    // the catalog's confidential default is the cheap, fast, always-credentialled one — the right thing to land on
    model: `trustedrouter/${(fallback || CATALOG.find((m) => m.route === 'trustedrouter')).model}`,
    // Project notes (tools/opencode-plugins/witbitz-notes.js), for sessions WITHOUT the Code section's ruleset (the TUI):
    // reading the notes folder asks nothing (one folder for every model — the confidential split is gone, 2026-09-14).
    // The Code section's sessions override this (measured) and get a per-session rule from the connector instead.
    permission: { external_directory: { [`${notesRoot}/**`]: 'allow' } },
    provider: {
      trustedrouter: {
        name: 'TrustedRouter',
        options: { baseURL: proxyPort ? `http://127.0.0.1:${proxyPort}/v1` : 'https://api.trustedrouter.com/v1', apiKey: '{env:TRUSTEDROUTER_API_KEY}' },
        models,
      },
    },
  }
}

/** Put the notes plugin and /notes-init where OpenCode loads them ({plugin,plugins}/*.js, {command,commands}/**.md). The
 *  confidential-model list an earlier version installed for the notes is removed: the notes no longer split by model. */
export function installNotes({ configDir = CONFIG_DIR } = {}) {
  mkdirSync(join(configDir, 'plugins'), { recursive: true })
  mkdirSync(join(configDir, 'commands'), { recursive: true })
  copyFileSync(join(HERE, 'opencode-plugins', 'witbitz-notes.js'), join(configDir, 'plugins', 'witbitz-notes.js'))
  copyFileSync(join(HERE, 'opencode-commands', 'notes-init.md'), join(configDir, 'commands', 'notes-init.md'))
  rmSync(join(configDir, 'witbitz-confidential-models.json'), { force: true })
}

/** Put the progress plugin (tools/opencode-plugins/witbitz-progress.js) where OpenCode loads it: the agent's updates for the
 *  person, drawn in the Code section's transcript between its work rows. */
export function installProgress({ configDir = CONFIG_DIR } = {}) {
  mkdirSync(join(configDir, 'plugins'), { recursive: true })
  copyFileSync(join(HERE, 'opencode-plugins', 'witbitz-progress.js'), join(configDir, 'plugins', 'witbitz-progress.js'))
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const pp = process.argv.indexOf('--proxy-port')
  const proxyPort = pp >= 0 ? Number(process.argv[pp + 1]) || 0 : 0
  const json = JSON.stringify(buildConfig({ proxyPort }), null, 2)
  if (process.argv.includes('--print')) { console.log(json); process.exit(0) }
  mkdirSync(dirname(OUT), { recursive: true })
  if (existsSync(OUT)) { copyFileSync(OUT, OUT + '.bak'); console.log(`kept ${OUT}.bak`) }
  writeFileSync(OUT, json + '\n')
  installNotes()
  installProgress()
  console.log(`installed project notes: ${join(CONFIG_DIR, 'plugins', 'witbitz-notes.js')} + /notes-init (notes in ${NOTES_ROOT})`)
  console.log(`installed progress updates: ${join(CONFIG_DIR, 'plugins', 'witbitz-progress.js')}`)
  console.log(`wrote ${OUT} — ${Object.keys(buildConfig({ proxyPort }).provider.trustedrouter.models).length} models${proxyPort ? `, TrustedRouter via the confidential-model proxy on 127.0.0.1:${proxyPort}` : ''}`)
  console.log('restart the server for it to take effect: it reads this file once, at boot')
}
