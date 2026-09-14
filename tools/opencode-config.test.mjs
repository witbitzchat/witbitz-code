// The three findings that cost a measurement each. If one of these ever fails, a model silently stops working —
// the failure mode is never an error, it is an image the model never saw or a turn that answers nothing.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildConfig } from './opencode-config.mjs'
import { CATALOG } from '../agent/modelCatalog.mjs'

const cfg = buildConfig()
const models = cfg.provider.trustedrouter.models

test('every trustedrouter catalog entry is declared, and nothing else is', () => {
  const want = CATALOG.filter((m) => m.route === 'trustedrouter').map((m) => m.model)
  assert.deepEqual(Object.keys(models).sort(), [...want].sort())
})

test('finding 1: capability is declared with attachment + modalities, never `capabilities`', () => {
  // opencode ACCEPTS a `capabilities` block and ignores it — the server then reports input:[] for every model
  // and quietly drops file parts. The schema's words are `attachment` and `modalities`.
  for (const [id, m] of Object.entries(models)) {
    assert.ok(!('capabilities' in m), `${id} uses the ignored key`)
    assert.equal(typeof m.attachment, 'boolean', `${id} must declare attachment`)
    assert.ok(Array.isArray(m.modalities?.input), `${id} must declare modalities.input`)
    // the two must agree, or opencode offers an attach button for a model that will refuse the bytes
    assert.equal(m.attachment, m.modalities.input.includes('image'), `${id}: attachment and modalities disagree`)
  }
})

test('finding 2: gpt-5 ids pin reasoningEffort to none (camelCase)', () => {
  // opencode injects reasoning_effort:"medium" off a model-ID heuristic with no config key to turn it off, and
  // TrustedRouter rewrites low/medium/high into Anthropic's `thinking` → the OpenAI upstream 400s the whole turn.
  for (const [id, m] of Object.entries(models)) {
    if (!id.includes('gpt-5')) { assert.ok(!m.options?.reasoningEffort, `${id} should not pin effort`); continue }
    assert.equal(m.options?.reasoningEffort, 'none', `${id} must pin effort to none`)
    assert.ok(!('reasoning_effort' in (m.options || {})), `${id}: snake_case is ignored by opencode`)
  }
})

test('finding 3: vision follows the catalog route flag, in both directions', () => {
  const blind = CATALOG.find((m) => m.route === 'trustedrouter' && m.vision === false)
  const seeing = CATALOG.find((m) => m.route === 'trustedrouter' && m.vision !== false)
  assert.equal(models[blind.model].attachment, false, `${blind.model} is vision:false in the catalog`)
  assert.deepEqual(models[seeing.model].modalities.input, ['text', 'image'])
})

test('finding 4: NO model declares pdf — the route 502s the file part', () => {
  // Declaring it would make opencode send bytes that die on every model. With it absent the client extracts the
  // text itself (spaces/public/pdfText.js), so a PDF is answerable on all 18 instead of none.
  for (const [id, m] of Object.entries(models)) {
    assert.ok(!m.modalities.input.includes('pdf'), `${id} must not claim pdf on this route`)
  }
})

test('the default model is one we actually declared', () => {
  assert.ok(cfg.model.startsWith('trustedrouter/'))
  assert.ok(models[cfg.model.slice('trustedrouter/'.length)], 'default model must be in the provider')
})

test('the api key is a reference, never a literal', () => {
  assert.equal(cfg.provider.trustedrouter.options.apiKey, '{env:TRUSTEDROUTER_API_KEY}')
})

// ── project notes (tools/opencode-plugins/witbitz-notes.js) ─────────────────────────────────────────────────────────
// Measured (opencode 1.18.30, isolated server): plugins load from ~/.config/opencode/{plugin,plugins}/*.{ts,js}, commands
// from {command,commands}/**/*.md; a config-level external_directory allow applies to a session WITHOUT our ruleset (the TUI).
test('notes: the TUI may read the notes folder, and confidential notes still ask', async () => {
  const { buildConfig: build } = await import('./opencode-config.mjs')
  const c = build({ proxyPort: 4196, notesRoot: '/home/u/.local/share/witbitz-notes' })
  assert.deepEqual(c.permission, { external_directory: { '/home/u/.local/share/witbitz-notes/**': 'allow', '/home/u/.local/share/witbitz-notes/*/confidential/**': 'ask' } })
  assert.deepEqual(Object.keys(c.permission.external_directory).at(-1), '/home/u/.local/share/witbitz-notes/*/confidential/**', 'the ask comes last — the last matching rule wins')
})

test('notes: installing puts the plugin and /notes-init where OpenCode loads them, and lists the confidential models', async () => {
  const { installNotes, confidentialModelIds } = await import('./opencode-config.mjs')
  const { mkdtempSync, readFileSync, existsSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const dir = mkdtempSync(join(tmpdir(), 'wb-occfg-'))
  installNotes({ configDir: dir, proxyPort: 4196 })
  assert.ok(readFileSync(join(dir, 'plugins', 'witbitz-notes.js'), 'utf8').includes('export const WitbitzNotes'))
  assert.match(readFileSync(join(dir, 'commands', 'notes-init.md'), 'utf8'), /^---\ndescription:/)
  const listed = JSON.parse(readFileSync(join(dir, 'witbitz-confidential-models.json'), 'utf8'))
  assert.deepEqual(listed, confidentialModelIds({ proxyPort: 4196 }))
  assert.ok(listed.length > 0 && listed.every((id) => id.startsWith('trustedrouter/')))
  assert.deepEqual(confidentialModelIds({ proxyPort: 0 }), [], 'without the proxy nothing is confidential — the label is not a claim')
  installNotes({ configDir: join(dir, 'again'), proxyPort: 0 })
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'again', 'witbitz-confidential-models.json'), 'utf8')), [])
  assert.equal(existsSync(join(dir, 'plugins', 'witbitz-notes.test.mjs')), false, 'only the plugin, never its tests')
})
