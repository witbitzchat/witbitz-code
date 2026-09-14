// "Set up this computer" — the connector's PATH lookup (tools/code-tools-probe.mjs) and the catalog it answers against
// (spaces/public/codeTools.js). The Python twin is held to the same answers by packages/witbitz-code-py/tests/test_tools_probe.py.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { probeTools, searchDirs } from './code-tools-probe.mjs'
import { TOOLS, normToolsReport, missingTools, setupPrompt } from '../spaces/public/codeTools.js'

const fsWith = (paths) => { const set = new Set(paths); return (p) => set.has(p) }

test('a tool counts as installed when ANY of its names is on PATH, in any folder', () => {
  const r = probeTools({ env: { PATH: '/a:/b' }, platform: 'linux', home: '/home/u', isExecutable: fsWith(['/b/ffmpeg', '/a/python3', '/b/whisper-cli', '/a/convert']) })
  assert.equal(r.tools.ffmpeg, true)
  assert.equal(r.tools.python, true, 'python3 is Python')
  assert.equal(r.tools.whisper, true, 'whisper.cpp\'s whisper-cli is Whisper')
  assert.equal(r.tools.imagemagick, true, 'ImageMagick 6 ships only convert')
  assert.equal(r.tools.pandoc, false)
  assert.deepEqual(Object.keys(r.tools), TOOLS.map((t) => t.id), 'every catalog tool is answered, in order')
})

test('common install folders are searched even when a service started the connector with a thin PATH', () => {
  const r = probeTools({ env: { PATH: '/usr/bin' }, platform: 'darwin', home: '/Users/u', isExecutable: fsWith(['/opt/homebrew/bin/brew', '/opt/homebrew/bin/pandoc', '/Users/u/.local/bin/uv']) })
  assert.deepEqual({ pandoc: r.tools.pandoc, uv: r.tools.uv }, { pandoc: true, uv: true })
  assert.deepEqual(r.platform, { os: 'darwin', pm: 'brew' })
  assert.deepEqual(searchDirs({ env: { PATH: '/x:/usr/bin:/x' }, platform: 'linux', home: '/h' }).slice(0, 3), ['/x', '/usr/bin', '/opt/homebrew/bin'], 'PATH first, no repeats')
})

test('the package manager is the most preferred one found for the OS', () => {
  const linux = (bins) => probeTools({ env: { PATH: '/usr/bin' }, platform: 'linux', home: '', isExecutable: fsWith(bins.map((b) => '/usr/bin/' + b)) }).platform
  assert.deepEqual(linux(['dnf', 'apt-get']), { os: 'linux', pm: 'apt' })
  assert.deepEqual(linux(['pacman']), { os: 'linux', pm: 'pacman' })
  assert.deepEqual(linux([]), { os: 'linux', pm: '' })
  assert.deepEqual(probeTools({ env: {}, platform: 'freebsd', home: '', isExecutable: () => true }).platform, { os: '', pm: '' }, 'an OS it does not know')
})

test('Windows: PATHEXT, ";" separators, and its own convert.exe is not ImageMagick', () => {
  const r = probeTools({ env: { PATH: 'C:\\Tools;C:\\Windows\\System32', PATHEXT: '.EXE;.CMD' }, platform: 'win32', home: 'C:\\Users\\u',
    isExecutable: fsWith(['C:\\Tools\\ffmpeg.exe', 'C:\\Windows\\System32\\convert.exe', 'C:\\Tools\\winget.exe', 'C:\\Tools\\git.cmd']) })
  assert.deepEqual({ ffmpeg: r.tools.ffmpeg, git: r.tools.git, imagemagick: r.tools.imagemagick }, { ffmpeg: true, git: true, imagemagick: false })
  assert.deepEqual(r.platform, { os: 'win32', pm: 'winget' })
})

test('a report from the computer is trusted only for known tools, booleans, and known OS / package managers', () => {
  const r = normToolsReport({ t: 'tools', tools: { ffmpeg: false, git: true, evil: false, pandoc: 'no' }, platform: { os: 'linux', pm: 'brew; rm -rf /' }, extra: 1 })
  assert.deepEqual(r, { tools: { ffmpeg: false, git: true }, platform: { os: 'linux', pm: '' } })
  assert.deepEqual(missingTools(r).map((t) => t.id), ['ffmpeg'], 'a tool not mentioned is not called missing')
  assert.equal(normToolsReport(null), null)
  assert.equal(normToolsReport({ t: 'tools' }), null)
})

test('the setup prompt names the ticked tools with package hints, and says every command asks', () => {
  const p = setupPrompt({ ids: ['ffmpeg', 'whisper'], platform: { os: 'linux', pm: 'apt' } })
  assert.match(p, /ffmpeg \(`ffmpeg`\).*apt package `ffmpeg`/)
  assert.match(p, /Whisper .*no apt package.*uv tool install openai-whisper/)
  assert.doesNotMatch(p, /Pandoc|qpdf/, 'only what was ticked')
  assert.match(p, /runs Linux and has apt/)
  assert.match(p, /ask me for approval/)
  assert.match(p, /Do not change anything else/)
  assert.match(setupPrompt({ ids: ['git'], platform: { os: '', pm: '' } }), /this computer's OS/)
})
