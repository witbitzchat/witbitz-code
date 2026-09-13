// spaces/public/compress.js — gzip codec for synced docs (native CompressionStream, no dep).
// Large index/pipes docs are wrapped { z: <gzip-b64> } to dodge the 413 ceiling; small docs stay
// PLAIN so any reader unwraps transparently. LEAF: pure functions, zero back-deps. $( -clean.

// the SMALL compressed bytes, and any reader unwraps it. Small docs stay PLAIN (readable without the codec). If the
// browser lacks CompressionStream we push plain — a truly huge doc can still 413, i.e. no worse than before.
export const _hasGzip = typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined'
export const _jsonBytes = (v) => { try { return new TextEncoder().encode(JSON.stringify(v ?? null)).length } catch { return Infinity } }
async function _streamToU8(stream) {
  const reader = stream.getReader(); const chunks = []; let n = 0
  for (;;) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); n += value.length }
  const out = new Uint8Array(n); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length }; return out
}
function _u8ToB64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s) }
function _b64ToU8(b64) { const s = atob(b64); const u8 = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i); return u8 }
export async function gzipB64(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj ?? null))
  const stream = new Response(bytes).body.pipeThrough(new CompressionStream('gzip'))
  return _u8ToB64(await _streamToU8(stream))
}
export async function gunzipB64(b64) {
  const stream = new Response(_b64ToU8(b64)).body.pipeThrough(new DecompressionStream('gzip'))
  return JSON.parse(new TextDecoder().decode(await _streamToU8(stream)))
}
