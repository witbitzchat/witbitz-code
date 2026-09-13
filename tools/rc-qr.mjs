// tools/rc-qr.mjs — render a pairing link as a QR from the CLI, reusing the SAME encoder the app ships
// (spaces/public/qrRender.js → vendor/qrcode.js). Two outputs: an ANSI block QR to scan straight off the terminal,
// and an SVG the operator can open/scan on another device. No new dependency.
import { qrModules } from '../spaces/public/qrRender.js'

const QUIET = 4 // modules of white margin; below ~4 a scanner loses the finder patterns

/** A scannable QR for the terminal: each module = two spaces, dark on a white background via ANSI, with a quiet zone.
 *  White-background (not the terminal's theme) so it scans on a dark terminal too. */
export function qrAnsi(text) {
  const { size, isDark } = qrModules(text)
  const DARK = '\x1b[40m  \x1b[0m' // black bg, two spaces
  const LIGHT = '\x1b[47m  \x1b[0m' // white bg
  const rowStr = (cells) => cells.map((d) => (d ? DARK : LIGHT)).join('')
  const lines = []
  const blank = new Array(size + QUIET * 2).fill(false)
  for (let i = 0; i < QUIET; i++) lines.push(rowStr(blank))
  for (let r = 0; r < size; r++) {
    const cells = [...Array(QUIET).fill(false), ...Array.from({ length: size }, (_, c) => isDark(r, c)), ...Array(QUIET).fill(false)]
    lines.push(rowStr(cells))
  }
  for (let i = 0; i < QUIET; i++) lines.push(rowStr(blank))
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
