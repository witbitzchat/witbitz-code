// spaces/public/qrRender.js — draw a device-link challenge as a QR, and read one back off a camera frame.
//
// Rendering goes through a raw module bitmap rather than the encoder's own image helpers, for one reason: the same
// function that feeds the <canvas> in the browser feeds the DECODER in the test suite. Encoding with one library and
// decoding with the other, headlessly, is the only way to know the picture on the screen is actually scannable —
// "the encoder returned something" proves nothing.
import qrcode from './vendor/qrcode.js'

const QUIET = 4 // modules of margin; below ~4 the scanner loses the finder patterns against a busy background

/** Module matrix for `text` → { size, isDark(r,c) }. 'M' correction survives a phone screen's glare and moiré. */
export function qrModules(text) {
  const qr = qrcode(0, 'M') // 0 = pick the smallest version that fits
  qr.addData(String(text))
  qr.make()
  const size = qr.getModuleCount()
  return { size, isDark: (r, c) => qr.isDark(r, c) }
}

/** RGBA bitmap of the QR at `scale` px per module, with a quiet zone. Same pixels in node and in the browser. */
export function qrBitmap(text, scale = 4) {
  const { size, isDark } = qrModules(text)
  const dim = (size + QUIET * 2) * scale
  const data = new Uint8ClampedArray(dim * dim * 4).fill(255) // white, opaque
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isDark(r, c)) continue
      const x0 = (c + QUIET) * scale, y0 = (r + QUIET) * scale
      for (let y = y0; y < y0 + scale; y++) {
        for (let x = x0; x < x0 + scale; x++) {
          const i = (y * dim + x) * 4
          data[i] = data[i + 1] = data[i + 2] = 0
        }
      }
    }
  }
  return { data, width: dim, height: dim }
}

/** Paint into a <canvas>, sized to fit `px` on screen. */
export function drawQr(canvas, text, px = 240) {
  const { size } = qrModules(text)
  const scale = Math.max(2, Math.floor(px / (size + QUIET * 2)))
  const bmp = qrBitmap(text, scale)
  canvas.width = bmp.width; canvas.height = bmp.height
  canvas.style.width = canvas.style.height = bmp.width + 'px'
  canvas.getContext('2d').putImageData(new ImageData(bmp.data, bmp.width, bmp.height), 0, 0)
  return bmp.width
}

// ── Reading one back ─────────────────────────────────────────────────────────────────────────────────────────────────
// BarcodeDetector is native on Chrome/Android and absent on Safari, which is most of the users who will actually do
// this. jsQR covers the rest — 250 KB, so it is fetched only when a camera is genuinely open, never on page load.
let _jsQR = null
async function loadJsQR() {
  if (_jsQR) return _jsQR
  await new Promise((res, rej) => {
    const s = document.createElement('script')
    s.src = './vendor/jsQR.js'; s.onload = res; s.onerror = () => rej(new Error('decoder_unavailable'))
    document.head.appendChild(s)
  })
  _jsQR = window.jsQR
  if (!_jsQR) throw new Error('decoder_unavailable')
  return _jsQR
}

/** Decode one video frame → the QR's text, or ''. Native detector first, jsQR as the fallback. */
export async function decodeFrame(video, canvas) {
  const w = video.videoWidth, h = video.videoHeight
  if (!w || !h) return ''
  if (typeof window !== 'undefined' && window.BarcodeDetector) {
    try {
      const det = new window.BarcodeDetector({ formats: ['qr_code'] })
      const found = await det.detect(video)
      if (found && found.length) return found[0].rawValue || ''
    } catch { /* fall through to jsQR */ }
  }
  canvas.width = w; canvas.height = h
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  ctx.drawImage(video, 0, 0, w, h)
  const img = ctx.getImageData(0, 0, w, h)
  const jsQR = await loadJsQR()
  const r = jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' })
  return (r && r.data) || ''
}
