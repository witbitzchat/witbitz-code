import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { qrBitmap, qrModules } from '../public/qrRender.js'
import { newLinkChallenge, parseChallenge } from '../public/deviceLink.js'

// The only question that matters about a QR is whether a scanner can read it, and no assertion about the encoder's
// return value answers that. So this encodes with qrcode-generator and decodes with jsQR — the very library that will
// run on the phone — and checks the text survives the round trip.
//
// It catches the failures that actually happen: a quiet zone too thin to find the finder patterns, a challenge that
// outgrows the version, an encoder mode that mangles the base64url alphabet.
// Load the vendored decoder exactly as the phone will: a plain script that hangs itself off the global. (Importing it
// takes the UMD's browser branch and assigns to `undefined`, so a sandbox with a `self` is both simpler and truer.)
const sandbox = { self: {} }
vm.createContext(sandbox)
vm.runInContext(readFileSync(new URL('../public/vendor/jsQR.js', import.meta.url), 'utf8'), sandbox)
const jsQR = sandbox.self.jsQR
if (typeof jsQR !== 'function') throw new Error('vendored jsQR did not load')

const decode = (text, scale = 4) => {
  const { data, width, height } = qrBitmap(text, scale)
  const r = jsQR(data, width, height, { inversionAttempts: 'dontInvert' })
  return r && r.data
}

test('a real device-link challenge survives encode → decode', async () => {
  const ch = await newLinkChallenge()
  const back = decode(ch.text)
  assert.equal(back, ch.text, 'what the camera reads must be exactly what was drawn')
  // And it must still parse as a challenge afterwards — the round trip is only useful if the payload is intact.
  const parsed = parseChallenge(back)
  assert.ok(parsed, 'the decoded text must still be a valid challenge')
  assert.equal(parsed.ref, ch.ref)
  assert.equal(parsed.pub, ch.pub)
})

test('it holds up across many challenges, not just a lucky one', async () => {
  for (let i = 0; i < 8; i++) {
    const ch = await newLinkChallenge()
    assert.equal(decode(ch.text), ch.text, `challenge ${i} failed to round trip`)
  }
})

test('the base64url alphabet comes back byte-exact', () => {
  // -, _ and mixed case are where a wrong encoder mode silently corrupts a key.
  const tricky = 'wbzlink1:' + 'a'.repeat(32) + '.' + 'Az09-_Az09-_Az09-_Az09-_Az09-_Az09-_Az09-_Az09'
  assert.equal(decode(tricky), tricky)
})

test('the quiet zone is really there — a QR flush to the edge is unscannable in the wild', () => {
  const { size } = qrModules('wbzlink1:test')
  const { width } = qrBitmap('wbzlink1:test', 4)
  assert.equal(width, (size + 8) * 4, 'four modules of margin on each side')
})

test('it stays small enough to scan off a phone screen', async () => {
  const ch = await newLinkChallenge()
  const { size } = qrModules(ch.text)
  // Version = (size - 17) / 4. Past ~version 10 the modules get too fine for a screen-to-screen scan in poor light.
  assert.ok(size <= 57, `QR version too dense for screen-to-screen scanning: ${size} modules`)
})
