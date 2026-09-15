// spaces/public/codeUpdate.js — "my-laptop runs an older witbitz-code": the note at the top of the Code session list.
//
// A computer keeps running the witbitz-code it was set up with until someone runs the installer again, and new features
// then silently do not appear there (the owner, on a second Ubuntu install with no setup card: "why on the other device I
// dont get the install"). Every connector announces what it can do in its hello (`caps`); a computer missing one a
// current connector announces is out of date, and this card says so with the one line that updates it.
//
// ★ When a connector gains a capability, add it to CONNECTOR_CAPS in the same commit (both connectors ship it; the page
//   and the download deploy together) — otherwise older computers are not told to update for it.

/** What a current connector announces — tools/opencode-connector.mjs and witbitz_code/connector.py `caps`. */
export const CONNECTOR_CAPS = ['auto', 'attachments', 'outputs', 'tools', 'seen', 'asks', 'folders']
export const UPDATE_COMMAND = 'curl -fsSL https://app.witbitz.chat/code.sh | bash'
export const UPDATE_COMMAND_PIPX = 'pipx upgrade witbitz-code'

const KEY = (computerId) => `code:update:${computerId}`
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n }

/** The capabilities this computer's connector lacks, given the transport's `can(cap)`. */
export const missingCaps = (can) => CONNECTOR_CAPS.filter((c) => !can(c))

/** "Not now" holds only for the SAME gap: a connector that falls further behind is shown the card again. */
export function updateDismissed(computerId, missing) {
  try { return localStorage.getItem(KEY(computerId)) === missing.join(',') } catch { return false }
}
export function dismissUpdate(computerId, missing) {
  try { localStorage.setItem(KEY(computerId), missing.join(',')) } catch { /* private mode: it shows again next time */ }
}

function commandRow(text) {
  const row = el('div', 'set-cmdrow')
  const cmd = el('code', 'set-cmd setup-cmd', text)
  const copy = el('button', 'ghost set-copy', 'Copy')
  copy.type = 'button'
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(text); copy.textContent = 'Copied' } catch { copy.textContent = 'Select it to copy' }
    setTimeout(() => { copy.textContent = 'Copy' }, 1600)
  }
  row.append(cmd, copy)
  return row
}

export function updateCard({ name, onDismiss }) {
  const card = el('section', 'setup-card update-card')
  card.setAttribute('aria-label', `Update witbitz-code on ${name}`)
  card.append(el('div', 'setup-h', `${name} runs an older witbitz-code`))
  card.append(el('p', 'setup-p', `Newer features — like checking which tools it has — need the current version. Run this in a terminal on ${name}; it keeps your pairing and restarts the connector:`))
  card.append(commandRow(UPDATE_COMMAND))
  card.append(el('p', 'setup-p update-alt', 'Installed with pipx instead?'))
  card.append(commandRow(UPDATE_COMMAND_PIPX))
  const actions = el('div', 'setup-actions')
  const later = el('button', 'ghost setup-later', 'Not now')
  later.type = 'button'
  later.onclick = () => onDismiss()
  actions.append(later)
  card.append(actions)
  return card
}

/** A short answer where the card would be — "All suggested tools are installed on my-laptop". */
export function noteCard({ text, onClose }) {
  const card = el('section', 'setup-card setup-note')
  card.setAttribute('role', 'status')
  card.append(el('span', 'setup-note-text', text))
  const ok = el('button', 'ghost setup-later', 'OK')
  ok.type = 'button'
  ok.onclick = () => onClose()
  card.append(ok)
  return card
}
