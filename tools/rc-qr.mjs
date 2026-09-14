// tools/rc-qr.mjs — render a pairing link as a QR from the CLI, reusing the SAME encoder the app ships
// (spaces/public/qrRender.js → vendor/qrcode.js). Two outputs: an ANSI block QR to scan straight off the terminal,
// and an SVG the operator can open/scan on another device. No new dependency.
import { qrModules } from '../spaces/public/qrRender.js'

const QUIET = 4 // modules of white margin; below ~4 a scanner loses the finder patterns

/** A scannable QR for the terminal, dark on a white ground via ANSI (not the terminal's theme, so it scans on a dark
 *  terminal too), with a quiet zone. Compact by default (the owner: "make the QR shown in the terminal smaller"): half
 *  blocks — one character is one module wide and two tall ("▀": top module in the foreground colour, bottom in the
 *  background) — a quarter of the old two-spaces-per-module area, and modules stay square because a terminal cell is
 *  about twice as tall as it is wide. WITBITZ_QR=large (or { compact: false }) draws the old one, for a terminal whose
 *  font renders ▀ badly. */
export function qrAnsi(text, { compact = process.env.WITBITZ_QR !== 'large' } = {}) {
  const { size, isDark } = qrModules(text)
  const dim = size + QUIET * 2
  const dark = (r, c) => r >= QUIET && c >= QUIET && r < QUIET + size && c < QUIET + size && isDark(r - QUIET, c - QUIET)
  const lines = []
  if (!compact) {
    const DARK = '\x1b[40m  \x1b[0m' // black bg, two spaces
    const LIGHT = '\x1b[47m  \x1b[0m' // white bg
    for (let r = 0; r < dim; r++) lines.push(Array.from({ length: dim }, (_, c) => (dark(r, c) ? DARK : LIGHT)).join(''))
    return lines.join('\n')
  }
  for (let r = 0; r < dim; r += 2) {
    let line = ''
    for (let c = 0; c < dim; c++) line += `\x1b[${dark(r, c) ? 30 : 97};${dark(r + 1, c) ? 40 : 107}m▀`
    lines.push(line + '\x1b[0m')
  }
  return lines.join('\n')
}

/** A crisp scalable QR as SVG (black modules on white, quiet zone) — write to a file and open/scan it on any device. */
export function qrSvg(text, px = 320) {
  const { size, isDark } = qrModules(text)
  const dim = size + QUIET * 2
  const rects = []
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (isDark(r, c)) rects.push(`<rect x="${c + QUIET}" y="${r + QUIET}" width="1" height="1"/>`)
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges" role="img" aria-label="Pairing QR">`
    + `<rect width="${dim}" height="${dim}" fill="#fff"/><g fill="#000">${rects.join('')}</g></svg>`
}
