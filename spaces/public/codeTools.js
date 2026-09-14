// spaces/public/codeTools.js — "Set up this computer": the tools a coding agent does better with, and how to ask for them.
//
// The owner: "after installing the spaces opencode we will suggest to install certain tools like whisper ffmpeg pdf tools
// … it can also be done first opening of the machine". Chosen design: the CONNECTOR checks what is installed (a PATH lookup
// — tools/code-tools-probe.mjs, and witbitz_code/tools_probe.py held to the same answers; no model, no approval cards), the
// page offers the missing ones (codeSetup.js), and "Install with the agent" starts an ordinary session whose every install
// command still asks. Nothing here installs anything.
//
// Shared by the page (labels, why, the prompt) and the Node connector (the binary names it looks for).

/** One entry per tool. `bins`: any of these on PATH ⇒ installed. `pkg`: the package per package manager, a hint for the
 *  agent (it still checks); '' ⇒ no package there, and `note` says how. */
export const TOOLS = [
  { id: 'git', label: 'Git', why: 'version control — most projects need it', bins: ['git'], pkg: { brew: 'git', apt: 'git', dnf: 'git', pacman: 'git', winget: 'Git.Git' } },
  { id: 'ripgrep', label: 'ripgrep', why: 'fast search through code', bins: ['rg'], pkg: { brew: 'ripgrep', apt: 'ripgrep', dnf: 'ripgrep', pacman: 'ripgrep', winget: 'BurntSushi.ripgrep.MSVC' } },
  { id: 'jq', label: 'jq', why: 'read and reshape JSON', bins: ['jq'], pkg: { brew: 'jq', apt: 'jq', dnf: 'jq', pacman: 'jq', winget: 'jqlang.jq' } },
  { id: 'python', label: 'Python 3', why: 'scripts and data work', bins: ['python3', 'python'], pkg: { brew: 'python', apt: 'python3', dnf: 'python3', pacman: 'python', winget: 'Python.Python.3.12' } },
  { id: 'uv', label: 'uv', why: 'installs Python tools cleanly, without touching the system Python', bins: ['uv'], pkg: { brew: 'uv', apt: '', dnf: '', pacman: 'uv', winget: 'astral-sh.uv' }, note: 'where there is no package: the official installer from astral.sh' },
  { id: 'ffmpeg', label: 'ffmpeg', why: 'cut, convert and read video and audio', bins: ['ffmpeg'], pkg: { brew: 'ffmpeg', apt: 'ffmpeg', dnf: 'ffmpeg', pacman: 'ffmpeg', winget: 'Gyan.FFmpeg' } },
  { id: 'whisper', label: 'Whisper', why: 'transcribe speech on this computer, without sending the audio anywhere', bins: ['whisper-cli', 'whisper-cpp', 'whisper'], pkg: { brew: 'whisper-cpp', apt: '', dnf: '', pacman: '', winget: '' }, note: 'where there is no package: `uv tool install openai-whisper`; either way it needs a model downloaded before first use — say how big it is before fetching it' },
  { id: 'poppler', label: 'Poppler', why: 'read PDFs as text and as images (pdftotext, pdftoppm)', bins: ['pdftotext'], pkg: { brew: 'poppler', apt: 'poppler-utils', dnf: 'poppler-utils', pacman: 'poppler', winget: '' } },
  { id: 'qpdf', label: 'qpdf', why: 'split, merge and repair PDFs', bins: ['qpdf'], pkg: { brew: 'qpdf', apt: 'qpdf', dnf: 'qpdf', pacman: 'qpdf', winget: 'QPDF.QPDF' } },
  { id: 'tesseract', label: 'Tesseract', why: 'read the text in scans and screenshots (OCR)', bins: ['tesseract'], pkg: { brew: 'tesseract', apt: 'tesseract-ocr', dnf: 'tesseract', pacman: 'tesseract', winget: 'UB-Mannheim.TesseractOCR' } },
  { id: 'pandoc', label: 'Pandoc', why: 'convert documents — Word, Markdown, HTML', bins: ['pandoc'], pkg: { brew: 'pandoc', apt: 'pandoc', dnf: 'pandoc', pacman: 'pandoc', winget: 'JohnMacFarlane.Pandoc' } },
  { id: 'imagemagick', label: 'ImageMagick', why: 'resize and convert images', bins: ['magick', 'convert'], pkg: { brew: 'imagemagick', apt: 'imagemagick', dnf: 'ImageMagick', pacman: 'imagemagick', winget: 'ImageMagick.ImageMagick' } },
]

/** Package managers, most preferred first per OS — the first one found on PATH is the one the agent is pointed at. */
export const PACKAGE_MANAGERS = {
  darwin: [['brew', 'brew'], ['port', 'port']],
  linux: [['apt', 'apt-get'], ['dnf', 'dnf'], ['pacman', 'pacman'], ['zypper', 'zypper'], ['apk', 'apk'], ['brew', 'brew']],
  win32: [['winget', 'winget'], ['choco', 'choco'], ['scoop', 'scoop']],
}

const OS_NAME = { darwin: 'macOS', linux: 'Linux', win32: 'Windows' }

/** A connector's `{t:'tools'}` answer → a well-formed one: known tool ids with booleans, an OS and a package manager
 *  from the lists above ('' otherwise). Everything else the message carries is dropped. */
export function normToolsReport(m) {
  if (!m || typeof m !== 'object' || !m.tools || typeof m.tools !== 'object') return null
  const tools = {}
  for (const t of TOOLS) if (typeof m.tools[t.id] === 'boolean') tools[t.id] = m.tools[t.id]
  const p = m.platform && typeof m.platform === 'object' ? m.platform : {}
  const os = Object.hasOwn(PACKAGE_MANAGERS, p.os) ? p.os : ''
  const pm = os && PACKAGE_MANAGERS[os].some(([id]) => id === p.pm) ? p.pm : ''
  return { tools, platform: { os, pm } }
}

/** The tools a report says are missing, in catalog order. A tool the report does not mention is not called missing. */
export const missingTools = (report) => (report ? TOOLS.filter((t) => report.tools[t.id] === false) : [])

/** The first message of the setup session. It asks — the approval cards are the real guard, but the agent is told so too. */
export function setupPrompt({ ids, platform }) {
  const chosen = TOOLS.filter((t) => ids.includes(t.id))
  const os = OS_NAME[platform && platform.os] || 'this computer\'s OS'
  const pm = (platform && platform.pm) || ''
  const lines = chosen.map((t) => {
    const pkg = pm && t.pkg[pm] !== undefined ? t.pkg[pm] : undefined
    const hint = pkg ? `${pm} package \`${pkg}\`` : pkg === '' ? `no ${pm} package` : ''
    return `- ${t.label} (${t.bins.map((b) => '`' + b + '`').join(' or ')}) — ${t.why}${hint ? `. Hint: ${hint}` : ''}${t.note ? `; ${t.note}` : ''}`
  })
  return [
    `Set up this computer for coding work. Install these tools, which are missing here:`,
    '',
    ...lines,
    '',
    `The computer runs ${os}${pm ? ` and has ${pm}` : ''}. Work through them one at a time:`,
    `1. Check it really is missing (\`command -v\`, or \`where\` on Windows) — skip it if it is already there.`,
    `2. Say the exact command you will run and why, then run it. Prefer the system package manager; use sudo only when the command needs it.`,
    `3. Confirm it works (for example \`--version\`).`,
    '',
    `Every command will ask me for approval first. Do not change anything else on the computer. If a tool cannot be installed here, say so and move on. End with a short list: installed, already there, skipped (and why).`,
  ].join('\n')
}
