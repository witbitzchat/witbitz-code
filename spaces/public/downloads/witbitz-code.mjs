#!/usr/bin/env node
// witbitz-code — built from tools/witbitz-code.mjs (github.com/witbitzchat/witbitz-code). Run: node witbitz-code.mjs --help

// tools/witbitz-code.mjs
import { spawn, spawnSync } from "node:child_process";

// tools/opencode-pair.mjs
import { readFileSync, writeFileSync as writeFileSync2, chmodSync as chmodSync2, existsSync, mkdtempSync, mkdirSync, rmSync, renameSync as renameSync2 } from "node:fs";
import { homedir as homedir2, tmpdir, hostname } from "node:os";
import { join as join2, dirname } from "node:path";
import { randomBytes } from "node:crypto";

// spaces/public/compress.js
var _hasGzip = typeof CompressionStream !== "undefined" && typeof DecompressionStream !== "undefined";
var _jsonBytes = (v) => {
  try {
    return new TextEncoder().encode(JSON.stringify(v ?? null)).length;
  } catch {
    return Infinity;
  }
};
async function _streamToU8(stream) {
  const reader = stream.getReader();
  const chunks = [];
  let n = 0;
  for (; ; ) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    n += value.length;
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  ;
  return out;
}
function _u8ToB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function _b64ToU8(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
async function gzipB64(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj ?? null));
  const stream = new Response(bytes).body.pipeThrough(new CompressionStream("gzip"));
  return _u8ToB64(await _streamToU8(stream));
}
async function gunzipB64(b64) {
  const stream = new Response(_b64ToU8(b64)).body.pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(new TextDecoder().decode(await _streamToU8(stream)));
}

// tools/rc-link.mjs
import { writeFileSync, chmodSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// spaces/public/deviceLink.js
var LINK_PREFIX = "wbzlink1:";
var B64 = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
var UNB64 = (s) => {
  const b = atob(String(s).replace(/-/g, "+").replace(/_/g, "/"));
  const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
};
var te = new TextEncoder();
var td = new TextDecoder();
var P256 = { name: "ECDH", namedCurve: "P-256" };
var hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
async function exportPub(key) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const x = UNB64(jwk.x), y = UNB64(jwk.y);
  const out = new Uint8Array(33);
  out[0] = y[31] & 1 ? 3 : 2;
  out.set(x, 1);
  return B64(out);
}
var P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
var B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
var toBig = (u8) => BigInt("0x" + hex(u8));
var toBytes = (n) => {
  const h = n.toString(16).padStart(64, "0");
  const u = new Uint8Array(32);
  for (let i = 0; i < 32; i++) u[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return u;
};
function modPow(base, exp, m) {
  let r = 1n, b = base % m;
  while (exp > 0n) {
    if (exp & 1n) r = r * b % m;
    b = b * b % m;
    exp >>= 1n;
  }
  return r;
}
async function importPub(b64) {
  const raw = UNB64(b64);
  if (raw.length !== 33 || raw[0] !== 2 && raw[0] !== 3) throw new Error("bad_point");
  const x = toBig(raw.subarray(1));
  if (x >= P) throw new Error("bad_point");
  const y2 = (modPow(x, 3n, P) - 3n * x + B) % P;
  let y = modPow((y2 + P) % P, (P + 1n) / 4n, P);
  if (y * y % P !== (y2 + P) % P) throw new Error("bad_point");
  if ((y & 1n) !== BigInt(raw[0] & 1)) y = P - y;
  return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: B64(toBytes(x)), y: B64(toBytes(y)), ext: true }, P256, false, []);
}
async function sharedKey(priv, pub, ref) {
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
  const base = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: te.encode(ref), info: te.encode("witbitz-device-link-v1") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function newLinkChallenge() {
  const kp = await crypto.subtle.generateKey(P256, false, ["deriveBits"]);
  const ref = hex(crypto.getRandomValues(new Uint8Array(16)));
  const pub = await exportPub(kp.publicKey);
  return { ref, pub, priv: kp.privateKey, text: LINK_PREFIX + ref + "." + pub };
}
async function openLinkReply(priv, { ref, epk, blob }) {
  const key = await sharedKey(priv, await importPub(epk), ref);
  const raw = UNB64(blob);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(0, 12) }, key, raw.subarray(12));
  return JSON.parse(td.decode(pt));
}
function readLinkPayload(p) {
  if (!p || typeof p !== "object" || typeof p.master !== "string" || !p.master) return null;
  const ptr = (x) => x && typeof x.room === "string" && typeof x.mk === "string" && x.room && x.mk ? { room: x.room, mk: x.mk } : null;
  const anchor = (() => {
    const a = p.anchor;
    if (!a || a.method !== "google" && a.method !== "email" || typeof a.email !== "string" || !a.email) return null;
    if (a.method === "email" && !(typeof a.token === "string" && a.token)) return null;
    return { method: a.method, email: a.email, ...typeof a.token === "string" && a.token ? { token: a.token } : {}, ...a.exp ? { exp: a.exp } : {} };
  })();
  return {
    master: p.master,
    code: typeof p.code === "string" ? p.code : "",
    email: typeof p.email === "string" ? p.email : "",
    // Half a release is no release: a token-less rel must not look like one and skip the gated read.
    rel: p.rel && typeof p.rel.token === "string" && p.rel.token ? { gid: String(p.rel.gid || ""), token: p.rel.token } : null,
    idx: ptr(p.idx),
    // index-room pointer handed over directly (gated accounts, where the receiver can't do the backup read)
    pipes: ptr(p.pipes),
    // private-lanes / assistant room pointer
    anchor
    // giver's email/Google identity → the linked device shows "signed in as …" (adoptAnchor on the receiver)
  };
}

// spaces/public/recovery.js
var enc = new TextEncoder();
var dec = new TextDecoder();
var SALT = enc.encode("witbitz-spaces-backup-v1");
var fromB64url = (s) => {
  const b = atob(String(s).replace(/-/g, "+").replace(/_/g, "/"));
  const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
};
async function hkdf(codeBytes, info, len) {
  const km = await crypto.subtle.importKey("raw", codeBytes, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: SALT, info: enc.encode(info) }, km, len * 8));
}
async function deriveKeysFromSecret(secretBytes) {
  if (!secretBytes || secretBytes.length < 16) throw new Error("bad_secret");
  const idBytes = await hkdf(secretBytes, "id", 16);
  const id = Array.from(idBytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const key = await crypto.subtle.importKey("raw", await hkdf(secretBytes, "enc", 32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const wt = Array.from(await hkdf(secretBytes, "bak-write", 32), (b) => b.toString(16).padStart(2, "0")).join("");
  return { id, key, wt };
}
async function unseal(key, blob) {
  const buf = fromB64url(blob);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
  return JSON.parse(dec.decode(pt));
}

// spaces/public/vendor/qrcode.js
var qrcode = function(typeNumber, errorCorrectionLevel) {
  const PAD0 = 236;
  const PAD1 = 17;
  let _typeNumber = typeNumber;
  const _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
  let _modules = null;
  let _moduleCount = 0;
  let _dataCache = null;
  const _dataList = [];
  const _this = {};
  const makeImpl = function(test, maskPattern) {
    _moduleCount = _typeNumber * 4 + 17;
    _modules = (function(moduleCount) {
      const modules = new Array(moduleCount);
      for (let row = 0; row < moduleCount; row += 1) {
        modules[row] = new Array(moduleCount);
        for (let col = 0; col < moduleCount; col += 1) {
          modules[row][col] = null;
        }
      }
      return modules;
    })(_moduleCount);
    setupPositionProbePattern(0, 0);
    setupPositionProbePattern(_moduleCount - 7, 0);
    setupPositionProbePattern(0, _moduleCount - 7);
    setupPositionAdjustPattern();
    setupTimingPattern();
    setupTypeInfo(test, maskPattern);
    if (_typeNumber >= 7) {
      setupTypeNumber(test);
    }
    if (_dataCache == null) {
      _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
    }
    mapData(_dataCache, maskPattern);
  };
  const setupPositionProbePattern = function(row, col) {
    for (let r = -1; r <= 7; r += 1) {
      if (row + r <= -1 || _moduleCount <= row + r) continue;
      for (let c = -1; c <= 7; c += 1) {
        if (col + c <= -1 || _moduleCount <= col + c) continue;
        if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
          _modules[row + r][col + c] = true;
        } else {
          _modules[row + r][col + c] = false;
        }
      }
    }
  };
  const getBestMaskPattern = function() {
    let minLostPoint = 0;
    let pattern = 0;
    for (let i = 0; i < 8; i += 1) {
      makeImpl(true, i);
      const lostPoint = QRUtil.getLostPoint(_this);
      if (i == 0 || minLostPoint > lostPoint) {
        minLostPoint = lostPoint;
        pattern = i;
      }
    }
    return pattern;
  };
  const setupTimingPattern = function() {
    for (let r = 8; r < _moduleCount - 8; r += 1) {
      if (_modules[r][6] != null) {
        continue;
      }
      _modules[r][6] = r % 2 == 0;
    }
    for (let c = 8; c < _moduleCount - 8; c += 1) {
      if (_modules[6][c] != null) {
        continue;
      }
      _modules[6][c] = c % 2 == 0;
    }
  };
  const setupPositionAdjustPattern = function() {
    const pos = QRUtil.getPatternPosition(_typeNumber);
    for (let i = 0; i < pos.length; i += 1) {
      for (let j = 0; j < pos.length; j += 1) {
        const row = pos[i];
        const col = pos[j];
        if (_modules[row][col] != null) {
          continue;
        }
        for (let r = -2; r <= 2; r += 1) {
          for (let c = -2; c <= 2; c += 1) {
            if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
              _modules[row + r][col + c] = true;
            } else {
              _modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  };
  const setupTypeNumber = function(test) {
    const bits = QRUtil.getBCHTypeNumber(_typeNumber);
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
    }
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
    }
  };
  const setupTypeInfo = function(test, maskPattern) {
    const data = _errorCorrectionLevel << 3 | maskPattern;
    const bits = QRUtil.getBCHTypeInfo(data);
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 6) {
        _modules[i][8] = mod;
      } else if (i < 8) {
        _modules[i + 1][8] = mod;
      } else {
        _modules[_moduleCount - 15 + i][8] = mod;
      }
    }
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 8) {
        _modules[8][_moduleCount - i - 1] = mod;
      } else if (i < 9) {
        _modules[8][15 - i - 1 + 1] = mod;
      } else {
        _modules[8][15 - i - 1] = mod;
      }
    }
    _modules[_moduleCount - 8][8] = !test;
  };
  const mapData = function(data, maskPattern) {
    let inc = -1;
    let row = _moduleCount - 1;
    let bitIndex = 7;
    let byteIndex = 0;
    const maskFunc = QRUtil.getMaskFunction(maskPattern);
    for (let col = _moduleCount - 1; col > 0; col -= 2) {
      if (col == 6) col -= 1;
      while (true) {
        for (let c = 0; c < 2; c += 1) {
          if (_modules[row][col - c] == null) {
            let dark = false;
            if (byteIndex < data.length) {
              dark = (data[byteIndex] >>> bitIndex & 1) == 1;
            }
            const mask = maskFunc(row, col - c);
            if (mask) {
              dark = !dark;
            }
            _modules[row][col - c] = dark;
            bitIndex -= 1;
            if (bitIndex == -1) {
              byteIndex += 1;
              bitIndex = 7;
            }
          }
        }
        row += inc;
        if (row < 0 || _moduleCount <= row) {
          row -= inc;
          inc = -inc;
          break;
        }
      }
    }
  };
  const createBytes = function(buffer, rsBlocks) {
    let offset = 0;
    let maxDcCount = 0;
    let maxEcCount = 0;
    const dcdata = new Array(rsBlocks.length);
    const ecdata = new Array(rsBlocks.length);
    for (let r = 0; r < rsBlocks.length; r += 1) {
      const dcCount = rsBlocks[r].dataCount;
      const ecCount = rsBlocks[r].totalCount - dcCount;
      maxDcCount = Math.max(maxDcCount, dcCount);
      maxEcCount = Math.max(maxEcCount, ecCount);
      dcdata[r] = new Array(dcCount);
      for (let i = 0; i < dcdata[r].length; i += 1) {
        dcdata[r][i] = 255 & buffer.getBuffer()[i + offset];
      }
      offset += dcCount;
      const rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
      const rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);
      const modPoly = rawPoly.mod(rsPoly);
      ecdata[r] = new Array(rsPoly.getLength() - 1);
      for (let i = 0; i < ecdata[r].length; i += 1) {
        const modIndex = i + modPoly.getLength() - ecdata[r].length;
        ecdata[r][i] = modIndex >= 0 ? modPoly.getAt(modIndex) : 0;
      }
    }
    let totalCodeCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalCodeCount += rsBlocks[i].totalCount;
    }
    const data = new Array(totalCodeCount);
    let index = 0;
    for (let i = 0; i < maxDcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < dcdata[r].length) {
          data[index] = dcdata[r][i];
          index += 1;
        }
      }
    }
    for (let i = 0; i < maxEcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < ecdata[r].length) {
          data[index] = ecdata[r][i];
          index += 1;
        }
      }
    }
    return data;
  };
  const createData = function(typeNumber2, errorCorrectionLevel2, dataList) {
    const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, errorCorrectionLevel2);
    const buffer = qrBitBuffer();
    for (let i = 0; i < dataList.length; i += 1) {
      const data = dataList[i];
      buffer.put(data.getMode(), 4);
      buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
      data.write(buffer);
    }
    let totalDataCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalDataCount += rsBlocks[i].dataCount;
    }
    if (buffer.getLengthInBits() > totalDataCount * 8) {
      throw "code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")";
    }
    if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
      buffer.put(0, 4);
    }
    while (buffer.getLengthInBits() % 8 != 0) {
      buffer.putBit(false);
    }
    while (true) {
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD0, 8);
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD1, 8);
    }
    return createBytes(buffer, rsBlocks);
  };
  _this.addData = function(data, mode) {
    mode = mode || "Byte";
    let newData = null;
    switch (mode) {
      case "Numeric":
        newData = qrNumber(data);
        break;
      case "Alphanumeric":
        newData = qrAlphaNum(data);
        break;
      case "Byte":
        newData = qr8BitByte(data);
        break;
      case "Kanji":
        newData = qrKanji(data);
        break;
      default:
        throw "mode:" + mode;
    }
    _dataList.push(newData);
    _dataCache = null;
  };
  _this.isDark = function(row, col) {
    if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
      throw row + "," + col;
    }
    return _modules[row][col];
  };
  _this.getModuleCount = function() {
    return _moduleCount;
  };
  _this.make = function() {
    if (_typeNumber < 1) {
      let typeNumber2 = 1;
      for (; typeNumber2 < 40; typeNumber2++) {
        const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, _errorCorrectionLevel);
        const buffer = qrBitBuffer();
        for (let i = 0; i < _dataList.length; i++) {
          const data = _dataList[i];
          buffer.put(data.getMode(), 4);
          buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
          data.write(buffer);
        }
        let totalDataCount = 0;
        for (let i = 0; i < rsBlocks.length; i++) {
          totalDataCount += rsBlocks[i].dataCount;
        }
        if (buffer.getLengthInBits() <= totalDataCount * 8) {
          break;
        }
      }
      _typeNumber = typeNumber2;
    }
    makeImpl(false, getBestMaskPattern());
  };
  _this.createTableTag = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    let qrHtml = "";
    qrHtml += '<table style="';
    qrHtml += " border-width: 0px; border-style: none;";
    qrHtml += " border-collapse: collapse;";
    qrHtml += " padding: 0px; margin: " + margin + "px;";
    qrHtml += '">';
    qrHtml += "<tbody>";
    for (let r = 0; r < _this.getModuleCount(); r += 1) {
      qrHtml += "<tr>";
      for (let c = 0; c < _this.getModuleCount(); c += 1) {
        qrHtml += '<td style="';
        qrHtml += " border-width: 0px; border-style: none;";
        qrHtml += " border-collapse: collapse;";
        qrHtml += " padding: 0px; margin: 0px;";
        qrHtml += " width: " + cellSize + "px;";
        qrHtml += " height: " + cellSize + "px;";
        qrHtml += " background-color: ";
        qrHtml += _this.isDark(r, c) ? "#000000" : "#ffffff";
        qrHtml += ";";
        qrHtml += '"/>';
      }
      qrHtml += "</tr>";
    }
    qrHtml += "</tbody>";
    qrHtml += "</table>";
    return qrHtml;
  };
  _this.createSvgTag = function(cellSize, margin, alt, title) {
    let opts = {};
    if (typeof arguments[0] == "object") {
      opts = arguments[0];
      cellSize = opts.cellSize;
      margin = opts.margin;
      alt = opts.alt;
      title = opts.title;
    }
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    alt = typeof alt === "string" ? { text: alt } : alt || {};
    alt.text = alt.text || null;
    alt.id = alt.text ? alt.id || "qrcode-description" : null;
    title = typeof title === "string" ? { text: title } : title || {};
    title.text = title.text || null;
    title.id = title.text ? title.id || "qrcode-title" : null;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let c, mc, r, mr, qrSvg2 = "", rect;
    rect = "l" + cellSize + ",0 0," + cellSize + " -" + cellSize + ",0 0,-" + cellSize + "z ";
    qrSvg2 += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
    qrSvg2 += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : "";
    qrSvg2 += ' viewBox="0 0 ' + size + " " + size + '" ';
    qrSvg2 += ' preserveAspectRatio="xMinYMin meet"';
    qrSvg2 += title.text || alt.text ? ' role="img" aria-labelledby="' + escapeXml([title.id, alt.id].join(" ").trim()) + '"' : "";
    qrSvg2 += ">";
    qrSvg2 += title.text ? '<title id="' + escapeXml(title.id) + '">' + escapeXml(title.text) + "</title>" : "";
    qrSvg2 += alt.text ? '<description id="' + escapeXml(alt.id) + '">' + escapeXml(alt.text) + "</description>" : "";
    qrSvg2 += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
    qrSvg2 += '<path d="';
    for (r = 0; r < _this.getModuleCount(); r += 1) {
      mr = r * cellSize + margin;
      for (c = 0; c < _this.getModuleCount(); c += 1) {
        if (_this.isDark(r, c)) {
          mc = c * cellSize + margin;
          qrSvg2 += "M" + mc + "," + mr + rect;
        }
      }
    }
    qrSvg2 += '" stroke="transparent" fill="black"/>';
    qrSvg2 += "</svg>";
    return qrSvg2;
  };
  _this.createDataURL = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    return createDataURL(size, size, function(x, y) {
      if (min <= x && x < max && min <= y && y < max) {
        const c = Math.floor((x - min) / cellSize);
        const r = Math.floor((y - min) / cellSize);
        return _this.isDark(r, c) ? 0 : 1;
      } else {
        return 1;
      }
    });
  };
  _this.createImgTag = function(cellSize, margin, alt) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let img = "";
    img += "<img";
    img += ' src="';
    img += _this.createDataURL(cellSize, margin);
    img += '"';
    img += ' width="';
    img += size;
    img += '"';
    img += ' height="';
    img += size;
    img += '"';
    if (alt) {
      img += ' alt="';
      img += escapeXml(alt);
      img += '"';
    }
    img += "/>";
    return img;
  };
  const escapeXml = function(s) {
    let escaped = "";
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charAt(i);
      switch (c) {
        case "<":
          escaped += "&lt;";
          break;
        case ">":
          escaped += "&gt;";
          break;
        case "&":
          escaped += "&amp;";
          break;
        case '"':
          escaped += "&quot;";
          break;
        default:
          escaped += c;
          break;
      }
    }
    return escaped;
  };
  const _createHalfASCII = function(margin) {
    const cellSize = 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r1, r2, p;
    const blocks = {
      "\u2588\u2588": "\u2588",
      "\u2588 ": "\u2580",
      " \u2588": "\u2584",
      "  ": " "
    };
    const blocksLastLineNoMargin = {
      "\u2588\u2588": "\u2580",
      "\u2588 ": "\u2580",
      " \u2588": " ",
      "  ": " "
    };
    let ascii = "";
    for (y = 0; y < size; y += 2) {
      r1 = Math.floor((y - min) / cellSize);
      r2 = Math.floor((y + 1 - min) / cellSize);
      for (x = 0; x < size; x += 1) {
        p = "\u2588";
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
          p = " ";
        }
        if (min <= x && x < max && min <= y + 1 && y + 1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
          p += " ";
        } else {
          p += "\u2588";
        }
        ascii += margin < 1 && y + 1 >= max ? blocksLastLineNoMargin[p] : blocks[p];
      }
      ascii += "\n";
    }
    if (size % 2 && margin > 0) {
      return ascii.substring(0, ascii.length - size - 1) + Array(size + 1).join("\u2580");
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.createASCII = function(cellSize, margin) {
    cellSize = cellSize || 1;
    if (cellSize < 2) {
      return _createHalfASCII(margin);
    }
    cellSize -= 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r, p;
    const white = Array(cellSize + 1).join("\u2588\u2588");
    const black = Array(cellSize + 1).join("  ");
    let ascii = "";
    let line = "";
    for (y = 0; y < size; y += 1) {
      r = Math.floor((y - min) / cellSize);
      line = "";
      for (x = 0; x < size; x += 1) {
        p = 1;
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
          p = 0;
        }
        line += p ? white : black;
      }
      for (r = 0; r < cellSize; r += 1) {
        ascii += line + "\n";
      }
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.renderTo2dContext = function(context, cellSize) {
    cellSize = cellSize || 2;
    const length = _this.getModuleCount();
    for (let row = 0; row < length; row++) {
      for (let col = 0; col < length; col++) {
        context.fillStyle = _this.isDark(row, col) ? "black" : "white";
        context.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
      }
    }
  };
  return _this;
};
qrcode.stringToBytes = function(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    bytes.push(c & 255);
  }
  return bytes;
};
qrcode.createStringToBytes = function(unicodeData, numChars) {
  const unicodeMap = (function() {
    const bin = base64DecodeInputStream(unicodeData);
    const read = function() {
      const b = bin.read();
      if (b == -1) throw "eof";
      return b;
    };
    let count = 0;
    const unicodeMap2 = {};
    while (true) {
      const b0 = bin.read();
      if (b0 == -1) break;
      const b1 = read();
      const b2 = read();
      const b3 = read();
      const k = String.fromCharCode(b0 << 8 | b1);
      const v = b2 << 8 | b3;
      unicodeMap2[k] = v;
      count += 1;
    }
    if (count != numChars) {
      throw count + " != " + numChars;
    }
    return unicodeMap2;
  })();
  const unknownChar = "?".charCodeAt(0);
  return function(s) {
    const bytes = [];
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charCodeAt(i);
      if (c < 128) {
        bytes.push(c);
      } else {
        const b = unicodeMap[s.charAt(i)];
        if (typeof b == "number") {
          if ((b & 255) == b) {
            bytes.push(b);
          } else {
            bytes.push(b >>> 8);
            bytes.push(b & 255);
          }
        } else {
          bytes.push(unknownChar);
        }
      }
    }
    return bytes;
  };
};
var QRMode = {
  MODE_NUMBER: 1 << 0,
  MODE_ALPHA_NUM: 1 << 1,
  MODE_8BIT_BYTE: 1 << 2,
  MODE_KANJI: 1 << 3
};
var QRErrorCorrectionLevel = {
  L: 1,
  M: 0,
  Q: 3,
  H: 2
};
var QRMaskPattern = {
  PATTERN000: 0,
  PATTERN001: 1,
  PATTERN010: 2,
  PATTERN011: 3,
  PATTERN100: 4,
  PATTERN101: 5,
  PATTERN110: 6,
  PATTERN111: 7
};
var QRUtil = (function() {
  const PATTERN_POSITION_TABLE = [
    [],
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
    [6, 30, 54],
    [6, 32, 58],
    [6, 34, 62],
    [6, 26, 46, 66],
    [6, 26, 48, 70],
    [6, 26, 50, 74],
    [6, 30, 54, 78],
    [6, 30, 56, 82],
    [6, 30, 58, 86],
    [6, 34, 62, 90],
    [6, 28, 50, 72, 94],
    [6, 26, 50, 74, 98],
    [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106],
    [6, 32, 58, 84, 110],
    [6, 30, 58, 86, 114],
    [6, 34, 62, 90, 118],
    [6, 26, 50, 74, 98, 122],
    [6, 30, 54, 78, 102, 126],
    [6, 26, 52, 78, 104, 130],
    [6, 30, 56, 82, 108, 134],
    [6, 34, 60, 86, 112, 138],
    [6, 30, 58, 86, 114, 142],
    [6, 34, 62, 90, 118, 146],
    [6, 30, 54, 78, 102, 126, 150],
    [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158],
    [6, 32, 58, 84, 110, 136, 162],
    [6, 26, 54, 82, 110, 138, 166],
    [6, 30, 58, 86, 114, 142, 170]
  ];
  const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
  const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
  const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
  const _this = {};
  const getBCHDigit = function(data) {
    let digit = 0;
    while (data != 0) {
      digit += 1;
      data >>>= 1;
    }
    return digit;
  };
  _this.getBCHTypeInfo = function(data) {
    let d = data << 10;
    while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
      d ^= G15 << getBCHDigit(d) - getBCHDigit(G15);
    }
    return (data << 10 | d) ^ G15_MASK;
  };
  _this.getBCHTypeNumber = function(data) {
    let d = data << 12;
    while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
      d ^= G18 << getBCHDigit(d) - getBCHDigit(G18);
    }
    return data << 12 | d;
  };
  _this.getPatternPosition = function(typeNumber) {
    return PATTERN_POSITION_TABLE[typeNumber - 1];
  };
  _this.getMaskFunction = function(maskPattern) {
    switch (maskPattern) {
      case QRMaskPattern.PATTERN000:
        return function(i, j) {
          return (i + j) % 2 == 0;
        };
      case QRMaskPattern.PATTERN001:
        return function(i, j) {
          return i % 2 == 0;
        };
      case QRMaskPattern.PATTERN010:
        return function(i, j) {
          return j % 3 == 0;
        };
      case QRMaskPattern.PATTERN011:
        return function(i, j) {
          return (i + j) % 3 == 0;
        };
      case QRMaskPattern.PATTERN100:
        return function(i, j) {
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
        };
      case QRMaskPattern.PATTERN101:
        return function(i, j) {
          return i * j % 2 + i * j % 3 == 0;
        };
      case QRMaskPattern.PATTERN110:
        return function(i, j) {
          return (i * j % 2 + i * j % 3) % 2 == 0;
        };
      case QRMaskPattern.PATTERN111:
        return function(i, j) {
          return (i * j % 3 + (i + j) % 2) % 2 == 0;
        };
      default:
        throw "bad maskPattern:" + maskPattern;
    }
  };
  _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
    let a = qrPolynomial([1], 0);
    for (let i = 0; i < errorCorrectLength; i += 1) {
      a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0));
    }
    return a;
  };
  _this.getLengthInBits = function(mode, type) {
    if (1 <= type && type < 10) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 10;
        case QRMode.MODE_ALPHA_NUM:
          return 9;
        case QRMode.MODE_8BIT_BYTE:
          return 8;
        case QRMode.MODE_KANJI:
          return 8;
        default:
          throw "mode:" + mode;
      }
    } else if (type < 27) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 12;
        case QRMode.MODE_ALPHA_NUM:
          return 11;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 10;
        default:
          throw "mode:" + mode;
      }
    } else if (type < 41) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 14;
        case QRMode.MODE_ALPHA_NUM:
          return 13;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 12;
        default:
          throw "mode:" + mode;
      }
    } else {
      throw "type:" + type;
    }
  };
  _this.getLostPoint = function(qrcode2) {
    const moduleCount = qrcode2.getModuleCount();
    let lostPoint = 0;
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount; col += 1) {
        let sameCount = 0;
        const dark = qrcode2.isDark(row, col);
        for (let r = -1; r <= 1; r += 1) {
          if (row + r < 0 || moduleCount <= row + r) {
            continue;
          }
          for (let c = -1; c <= 1; c += 1) {
            if (col + c < 0 || moduleCount <= col + c) {
              continue;
            }
            if (r == 0 && c == 0) {
              continue;
            }
            if (dark == qrcode2.isDark(row + r, col + c)) {
              sameCount += 1;
            }
          }
        }
        if (sameCount > 5) {
          lostPoint += 3 + sameCount - 5;
        }
      }
    }
    ;
    for (let row = 0; row < moduleCount - 1; row += 1) {
      for (let col = 0; col < moduleCount - 1; col += 1) {
        let count = 0;
        if (qrcode2.isDark(row, col)) count += 1;
        if (qrcode2.isDark(row + 1, col)) count += 1;
        if (qrcode2.isDark(row, col + 1)) count += 1;
        if (qrcode2.isDark(row + 1, col + 1)) count += 1;
        if (count == 0 || count == 4) {
          lostPoint += 3;
        }
      }
    }
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount - 6; col += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row, col + 1) && qrcode2.isDark(row, col + 2) && qrcode2.isDark(row, col + 3) && qrcode2.isDark(row, col + 4) && !qrcode2.isDark(row, col + 5) && qrcode2.isDark(row, col + 6)) {
          lostPoint += 40;
        }
      }
    }
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount - 6; row += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row + 1, col) && qrcode2.isDark(row + 2, col) && qrcode2.isDark(row + 3, col) && qrcode2.isDark(row + 4, col) && !qrcode2.isDark(row + 5, col) && qrcode2.isDark(row + 6, col)) {
          lostPoint += 40;
        }
      }
    }
    let darkCount = 0;
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount; row += 1) {
        if (qrcode2.isDark(row, col)) {
          darkCount += 1;
        }
      }
    }
    const ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
    lostPoint += ratio * 10;
    return lostPoint;
  };
  return _this;
})();
var QRMath = (function() {
  const EXP_TABLE = new Array(256);
  const LOG_TABLE = new Array(256);
  for (let i = 0; i < 8; i += 1) {
    EXP_TABLE[i] = 1 << i;
  }
  for (let i = 8; i < 256; i += 1) {
    EXP_TABLE[i] = EXP_TABLE[i - 4] ^ EXP_TABLE[i - 5] ^ EXP_TABLE[i - 6] ^ EXP_TABLE[i - 8];
  }
  for (let i = 0; i < 255; i += 1) {
    LOG_TABLE[EXP_TABLE[i]] = i;
  }
  const _this = {};
  _this.glog = function(n) {
    if (n < 1) {
      throw "glog(" + n + ")";
    }
    return LOG_TABLE[n];
  };
  _this.gexp = function(n) {
    while (n < 0) {
      n += 255;
    }
    while (n >= 256) {
      n -= 255;
    }
    return EXP_TABLE[n];
  };
  return _this;
})();
var qrPolynomial = function(num2, shift) {
  if (typeof num2.length == "undefined") {
    throw num2.length + "/" + shift;
  }
  const _num = (function() {
    let offset = 0;
    while (offset < num2.length && num2[offset] == 0) {
      offset += 1;
    }
    const _num2 = new Array(num2.length - offset + shift);
    for (let i = 0; i < num2.length - offset; i += 1) {
      _num2[i] = num2[i + offset];
    }
    return _num2;
  })();
  const _this = {};
  _this.getAt = function(index) {
    return _num[index];
  };
  _this.getLength = function() {
    return _num.length;
  };
  _this.multiply = function(e) {
    const num3 = new Array(_this.getLength() + e.getLength() - 1);
    for (let i = 0; i < _this.getLength(); i += 1) {
      for (let j = 0; j < e.getLength(); j += 1) {
        num3[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i)) + QRMath.glog(e.getAt(j)));
      }
    }
    return qrPolynomial(num3, 0);
  };
  _this.mod = function(e) {
    if (_this.getLength() - e.getLength() < 0) {
      return _this;
    }
    const ratio = QRMath.glog(_this.getAt(0)) - QRMath.glog(e.getAt(0));
    const num3 = new Array(_this.getLength());
    for (let i = 0; i < _this.getLength(); i += 1) {
      num3[i] = _this.getAt(i);
    }
    for (let i = 0; i < e.getLength(); i += 1) {
      num3[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i)) + ratio);
    }
    return qrPolynomial(num3, 0).mod(e);
  };
  return _this;
};
var QRRSBlock = (function() {
  const RS_BLOCK_TABLE = [
    // L
    // M
    // Q
    // H
    // 1
    [1, 26, 19],
    [1, 26, 16],
    [1, 26, 13],
    [1, 26, 9],
    // 2
    [1, 44, 34],
    [1, 44, 28],
    [1, 44, 22],
    [1, 44, 16],
    // 3
    [1, 70, 55],
    [1, 70, 44],
    [2, 35, 17],
    [2, 35, 13],
    // 4
    [1, 100, 80],
    [2, 50, 32],
    [2, 50, 24],
    [4, 25, 9],
    // 5
    [1, 134, 108],
    [2, 67, 43],
    [2, 33, 15, 2, 34, 16],
    [2, 33, 11, 2, 34, 12],
    // 6
    [2, 86, 68],
    [4, 43, 27],
    [4, 43, 19],
    [4, 43, 15],
    // 7
    [2, 98, 78],
    [4, 49, 31],
    [2, 32, 14, 4, 33, 15],
    [4, 39, 13, 1, 40, 14],
    // 8
    [2, 121, 97],
    [2, 60, 38, 2, 61, 39],
    [4, 40, 18, 2, 41, 19],
    [4, 40, 14, 2, 41, 15],
    // 9
    [2, 146, 116],
    [3, 58, 36, 2, 59, 37],
    [4, 36, 16, 4, 37, 17],
    [4, 36, 12, 4, 37, 13],
    // 10
    [2, 86, 68, 2, 87, 69],
    [4, 69, 43, 1, 70, 44],
    [6, 43, 19, 2, 44, 20],
    [6, 43, 15, 2, 44, 16],
    // 11
    [4, 101, 81],
    [1, 80, 50, 4, 81, 51],
    [4, 50, 22, 4, 51, 23],
    [3, 36, 12, 8, 37, 13],
    // 12
    [2, 116, 92, 2, 117, 93],
    [6, 58, 36, 2, 59, 37],
    [4, 46, 20, 6, 47, 21],
    [7, 42, 14, 4, 43, 15],
    // 13
    [4, 133, 107],
    [8, 59, 37, 1, 60, 38],
    [8, 44, 20, 4, 45, 21],
    [12, 33, 11, 4, 34, 12],
    // 14
    [3, 145, 115, 1, 146, 116],
    [4, 64, 40, 5, 65, 41],
    [11, 36, 16, 5, 37, 17],
    [11, 36, 12, 5, 37, 13],
    // 15
    [5, 109, 87, 1, 110, 88],
    [5, 65, 41, 5, 66, 42],
    [5, 54, 24, 7, 55, 25],
    [11, 36, 12, 7, 37, 13],
    // 16
    [5, 122, 98, 1, 123, 99],
    [7, 73, 45, 3, 74, 46],
    [15, 43, 19, 2, 44, 20],
    [3, 45, 15, 13, 46, 16],
    // 17
    [1, 135, 107, 5, 136, 108],
    [10, 74, 46, 1, 75, 47],
    [1, 50, 22, 15, 51, 23],
    [2, 42, 14, 17, 43, 15],
    // 18
    [5, 150, 120, 1, 151, 121],
    [9, 69, 43, 4, 70, 44],
    [17, 50, 22, 1, 51, 23],
    [2, 42, 14, 19, 43, 15],
    // 19
    [3, 141, 113, 4, 142, 114],
    [3, 70, 44, 11, 71, 45],
    [17, 47, 21, 4, 48, 22],
    [9, 39, 13, 16, 40, 14],
    // 20
    [3, 135, 107, 5, 136, 108],
    [3, 67, 41, 13, 68, 42],
    [15, 54, 24, 5, 55, 25],
    [15, 43, 15, 10, 44, 16],
    // 21
    [4, 144, 116, 4, 145, 117],
    [17, 68, 42],
    [17, 50, 22, 6, 51, 23],
    [19, 46, 16, 6, 47, 17],
    // 22
    [2, 139, 111, 7, 140, 112],
    [17, 74, 46],
    [7, 54, 24, 16, 55, 25],
    [34, 37, 13],
    // 23
    [4, 151, 121, 5, 152, 122],
    [4, 75, 47, 14, 76, 48],
    [11, 54, 24, 14, 55, 25],
    [16, 45, 15, 14, 46, 16],
    // 24
    [6, 147, 117, 4, 148, 118],
    [6, 73, 45, 14, 74, 46],
    [11, 54, 24, 16, 55, 25],
    [30, 46, 16, 2, 47, 17],
    // 25
    [8, 132, 106, 4, 133, 107],
    [8, 75, 47, 13, 76, 48],
    [7, 54, 24, 22, 55, 25],
    [22, 45, 15, 13, 46, 16],
    // 26
    [10, 142, 114, 2, 143, 115],
    [19, 74, 46, 4, 75, 47],
    [28, 50, 22, 6, 51, 23],
    [33, 46, 16, 4, 47, 17],
    // 27
    [8, 152, 122, 4, 153, 123],
    [22, 73, 45, 3, 74, 46],
    [8, 53, 23, 26, 54, 24],
    [12, 45, 15, 28, 46, 16],
    // 28
    [3, 147, 117, 10, 148, 118],
    [3, 73, 45, 23, 74, 46],
    [4, 54, 24, 31, 55, 25],
    [11, 45, 15, 31, 46, 16],
    // 29
    [7, 146, 116, 7, 147, 117],
    [21, 73, 45, 7, 74, 46],
    [1, 53, 23, 37, 54, 24],
    [19, 45, 15, 26, 46, 16],
    // 30
    [5, 145, 115, 10, 146, 116],
    [19, 75, 47, 10, 76, 48],
    [15, 54, 24, 25, 55, 25],
    [23, 45, 15, 25, 46, 16],
    // 31
    [13, 145, 115, 3, 146, 116],
    [2, 74, 46, 29, 75, 47],
    [42, 54, 24, 1, 55, 25],
    [23, 45, 15, 28, 46, 16],
    // 32
    [17, 145, 115],
    [10, 74, 46, 23, 75, 47],
    [10, 54, 24, 35, 55, 25],
    [19, 45, 15, 35, 46, 16],
    // 33
    [17, 145, 115, 1, 146, 116],
    [14, 74, 46, 21, 75, 47],
    [29, 54, 24, 19, 55, 25],
    [11, 45, 15, 46, 46, 16],
    // 34
    [13, 145, 115, 6, 146, 116],
    [14, 74, 46, 23, 75, 47],
    [44, 54, 24, 7, 55, 25],
    [59, 46, 16, 1, 47, 17],
    // 35
    [12, 151, 121, 7, 152, 122],
    [12, 75, 47, 26, 76, 48],
    [39, 54, 24, 14, 55, 25],
    [22, 45, 15, 41, 46, 16],
    // 36
    [6, 151, 121, 14, 152, 122],
    [6, 75, 47, 34, 76, 48],
    [46, 54, 24, 10, 55, 25],
    [2, 45, 15, 64, 46, 16],
    // 37
    [17, 152, 122, 4, 153, 123],
    [29, 74, 46, 14, 75, 47],
    [49, 54, 24, 10, 55, 25],
    [24, 45, 15, 46, 46, 16],
    // 38
    [4, 152, 122, 18, 153, 123],
    [13, 74, 46, 32, 75, 47],
    [48, 54, 24, 14, 55, 25],
    [42, 45, 15, 32, 46, 16],
    // 39
    [20, 147, 117, 4, 148, 118],
    [40, 75, 47, 7, 76, 48],
    [43, 54, 24, 22, 55, 25],
    [10, 45, 15, 67, 46, 16],
    // 40
    [19, 148, 118, 6, 149, 119],
    [18, 75, 47, 31, 76, 48],
    [34, 54, 24, 34, 55, 25],
    [20, 45, 15, 61, 46, 16]
  ];
  const qrRSBlock = function(totalCount, dataCount) {
    const _this2 = {};
    _this2.totalCount = totalCount;
    _this2.dataCount = dataCount;
    return _this2;
  };
  const _this = {};
  const getRsBlockTable = function(typeNumber, errorCorrectionLevel) {
    switch (errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default:
        return void 0;
    }
  };
  _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {
    const rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);
    if (typeof rsBlock == "undefined") {
      throw "bad rs block @ typeNumber:" + typeNumber + "/errorCorrectionLevel:" + errorCorrectionLevel;
    }
    const length = rsBlock.length / 3;
    const list = [];
    for (let i = 0; i < length; i += 1) {
      const count = rsBlock[i * 3 + 0];
      const totalCount = rsBlock[i * 3 + 1];
      const dataCount = rsBlock[i * 3 + 2];
      for (let j = 0; j < count; j += 1) {
        list.push(qrRSBlock(totalCount, dataCount));
      }
    }
    return list;
  };
  return _this;
})();
var qrBitBuffer = function() {
  const _buffer = [];
  let _length = 0;
  const _this = {};
  _this.getBuffer = function() {
    return _buffer;
  };
  _this.getAt = function(index) {
    const bufIndex = Math.floor(index / 8);
    return (_buffer[bufIndex] >>> 7 - index % 8 & 1) == 1;
  };
  _this.put = function(num2, length) {
    for (let i = 0; i < length; i += 1) {
      _this.putBit((num2 >>> length - i - 1 & 1) == 1);
    }
  };
  _this.getLengthInBits = function() {
    return _length;
  };
  _this.putBit = function(bit) {
    const bufIndex = Math.floor(_length / 8);
    if (_buffer.length <= bufIndex) {
      _buffer.push(0);
    }
    if (bit) {
      _buffer[bufIndex] |= 128 >>> _length % 8;
    }
    _length += 1;
  };
  return _this;
};
var qrNumber = function(data) {
  const _mode = QRMode.MODE_NUMBER;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const data2 = _data;
    let i = 0;
    while (i + 2 < data2.length) {
      buffer.put(strToNum(data2.substring(i, i + 3)), 10);
      i += 3;
    }
    if (i < data2.length) {
      if (data2.length - i == 1) {
        buffer.put(strToNum(data2.substring(i, i + 1)), 4);
      } else if (data2.length - i == 2) {
        buffer.put(strToNum(data2.substring(i, i + 2)), 7);
      }
    }
  };
  const strToNum = function(s) {
    let num2 = 0;
    for (let i = 0; i < s.length; i += 1) {
      num2 = num2 * 10 + chatToNum(s.charAt(i));
    }
    return num2;
  };
  const chatToNum = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    }
    throw "illegal char :" + c;
  };
  return _this;
};
var qrAlphaNum = function(data) {
  const _mode = QRMode.MODE_ALPHA_NUM;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const s = _data;
    let i = 0;
    while (i + 1 < s.length) {
      buffer.put(
        getCode(s.charAt(i)) * 45 + getCode(s.charAt(i + 1)),
        11
      );
      i += 2;
    }
    if (i < s.length) {
      buffer.put(getCode(s.charAt(i)), 6);
    }
  };
  const getCode = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    } else if ("A" <= c && c <= "Z") {
      return c.charCodeAt(0) - "A".charCodeAt(0) + 10;
    } else {
      switch (c) {
        case " ":
          return 36;
        case "$":
          return 37;
        case "%":
          return 38;
        case "*":
          return 39;
        case "+":
          return 40;
        case "-":
          return 41;
        case ".":
          return 42;
        case "/":
          return 43;
        case ":":
          return 44;
        default:
          throw "illegal char :" + c;
      }
    }
  };
  return _this;
};
var qr8BitByte = function(data) {
  const _mode = QRMode.MODE_8BIT_BYTE;
  const _data = data;
  const _bytes = qrcode.stringToBytes(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _bytes.length;
  };
  _this.write = function(buffer) {
    for (let i = 0; i < _bytes.length; i += 1) {
      buffer.put(_bytes[i], 8);
    }
  };
  return _this;
};
var qrKanji = function(data) {
  const _mode = QRMode.MODE_KANJI;
  const _data = data;
  const stringToBytes2 = qrcode.stringToBytes;
  !(function(c, code) {
    const test = stringToBytes2(c);
    if (test.length != 2 || (test[0] << 8 | test[1]) != code) {
      throw "sjis not supported.";
    }
  })("\u53CB", 38726);
  const _bytes = stringToBytes2(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return ~~(_bytes.length / 2);
  };
  _this.write = function(buffer) {
    const data2 = _bytes;
    let i = 0;
    while (i + 1 < data2.length) {
      let c = (255 & data2[i]) << 8 | 255 & data2[i + 1];
      if (33088 <= c && c <= 40956) {
        c -= 33088;
      } else if (57408 <= c && c <= 60351) {
        c -= 49472;
      } else {
        throw "illegal char at " + (i + 1) + "/" + c;
      }
      c = (c >>> 8 & 255) * 192 + (c & 255);
      buffer.put(c, 13);
      i += 2;
    }
    if (i < data2.length) {
      throw "illegal char at " + (i + 1);
    }
  };
  return _this;
};
var byteArrayOutputStream = function() {
  const _bytes = [];
  const _this = {};
  _this.writeByte = function(b) {
    _bytes.push(b & 255);
  };
  _this.writeShort = function(i) {
    _this.writeByte(i);
    _this.writeByte(i >>> 8);
  };
  _this.writeBytes = function(b, off, len) {
    off = off || 0;
    len = len || b.length;
    for (let i = 0; i < len; i += 1) {
      _this.writeByte(b[i + off]);
    }
  };
  _this.writeString = function(s) {
    for (let i = 0; i < s.length; i += 1) {
      _this.writeByte(s.charCodeAt(i));
    }
  };
  _this.toByteArray = function() {
    return _bytes;
  };
  _this.toString = function() {
    let s = "";
    s += "[";
    for (let i = 0; i < _bytes.length; i += 1) {
      if (i > 0) {
        s += ",";
      }
      s += _bytes[i];
    }
    s += "]";
    return s;
  };
  return _this;
};
var base64EncodeOutputStream = function() {
  let _buffer = 0;
  let _buflen = 0;
  let _length = 0;
  let _base64 = "";
  const _this = {};
  const writeEncoded = function(b) {
    _base64 += String.fromCharCode(encode(b & 63));
  };
  const encode = function(n) {
    if (n < 0) {
      throw "n:" + n;
    } else if (n < 26) {
      return 65 + n;
    } else if (n < 52) {
      return 97 + (n - 26);
    } else if (n < 62) {
      return 48 + (n - 52);
    } else if (n == 62) {
      return 43;
    } else if (n == 63) {
      return 47;
    } else {
      throw "n:" + n;
    }
  };
  _this.writeByte = function(n) {
    _buffer = _buffer << 8 | n & 255;
    _buflen += 8;
    _length += 1;
    while (_buflen >= 6) {
      writeEncoded(_buffer >>> _buflen - 6);
      _buflen -= 6;
    }
  };
  _this.flush = function() {
    if (_buflen > 0) {
      writeEncoded(_buffer << 6 - _buflen);
      _buffer = 0;
      _buflen = 0;
    }
    if (_length % 3 != 0) {
      const padlen = 3 - _length % 3;
      for (let i = 0; i < padlen; i += 1) {
        _base64 += "=";
      }
    }
  };
  _this.toString = function() {
    return _base64;
  };
  return _this;
};
var base64DecodeInputStream = function(str) {
  const _str = str;
  let _pos = 0;
  let _buffer = 0;
  let _buflen = 0;
  const _this = {};
  _this.read = function() {
    while (_buflen < 8) {
      if (_pos >= _str.length) {
        if (_buflen == 0) {
          return -1;
        }
        throw "unexpected end of file./" + _buflen;
      }
      const c = _str.charAt(_pos);
      _pos += 1;
      if (c == "=") {
        _buflen = 0;
        return -1;
      } else if (c.match(/^\s$/)) {
        continue;
      }
      _buffer = _buffer << 6 | decode(c.charCodeAt(0));
      _buflen += 6;
    }
    const n = _buffer >>> _buflen - 8 & 255;
    _buflen -= 8;
    return n;
  };
  const decode = function(c) {
    if (65 <= c && c <= 90) {
      return c - 65;
    } else if (97 <= c && c <= 122) {
      return c - 97 + 26;
    } else if (48 <= c && c <= 57) {
      return c - 48 + 52;
    } else if (c == 43) {
      return 62;
    } else if (c == 47) {
      return 63;
    } else {
      throw "c:" + c;
    }
  };
  return _this;
};
var gifImage = function(width, height) {
  const _width = width;
  const _height = height;
  const _data = new Array(width * height);
  const _this = {};
  _this.setPixel = function(x, y, pixel) {
    _data[y * _width + x] = pixel;
  };
  _this.write = function(out) {
    out.writeString("GIF87a");
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(128);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(255);
    out.writeByte(255);
    out.writeByte(255);
    out.writeString(",");
    out.writeShort(0);
    out.writeShort(0);
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(0);
    const lzwMinCodeSize = 2;
    const raster = getLZWRaster(lzwMinCodeSize);
    out.writeByte(lzwMinCodeSize);
    let offset = 0;
    while (raster.length - offset > 255) {
      out.writeByte(255);
      out.writeBytes(raster, offset, 255);
      offset += 255;
    }
    out.writeByte(raster.length - offset);
    out.writeBytes(raster, offset, raster.length - offset);
    out.writeByte(0);
    out.writeString(";");
  };
  const bitOutputStream = function(out) {
    const _out = out;
    let _bitLength = 0;
    let _bitBuffer = 0;
    const _this2 = {};
    _this2.write = function(data, length) {
      if (data >>> length != 0) {
        throw "length over";
      }
      while (_bitLength + length >= 8) {
        _out.writeByte(255 & (data << _bitLength | _bitBuffer));
        length -= 8 - _bitLength;
        data >>>= 8 - _bitLength;
        _bitBuffer = 0;
        _bitLength = 0;
      }
      _bitBuffer = data << _bitLength | _bitBuffer;
      _bitLength = _bitLength + length;
    };
    _this2.flush = function() {
      if (_bitLength > 0) {
        _out.writeByte(_bitBuffer);
      }
    };
    return _this2;
  };
  const getLZWRaster = function(lzwMinCodeSize) {
    const clearCode = 1 << lzwMinCodeSize;
    const endCode = (1 << lzwMinCodeSize) + 1;
    let bitLength = lzwMinCodeSize + 1;
    const table = lzwTable();
    for (let i = 0; i < clearCode; i += 1) {
      table.add(String.fromCharCode(i));
    }
    table.add(String.fromCharCode(clearCode));
    table.add(String.fromCharCode(endCode));
    const byteOut = byteArrayOutputStream();
    const bitOut = bitOutputStream(byteOut);
    bitOut.write(clearCode, bitLength);
    let dataIndex = 0;
    let s = String.fromCharCode(_data[dataIndex]);
    dataIndex += 1;
    while (dataIndex < _data.length) {
      const c = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;
      if (table.contains(s + c)) {
        s = s + c;
      } else {
        bitOut.write(table.indexOf(s), bitLength);
        if (table.size() < 4095) {
          if (table.size() == 1 << bitLength) {
            bitLength += 1;
          }
          table.add(s + c);
        }
        s = c;
      }
    }
    bitOut.write(table.indexOf(s), bitLength);
    bitOut.write(endCode, bitLength);
    bitOut.flush();
    return byteOut.toByteArray();
  };
  const lzwTable = function() {
    const _map = {};
    let _size = 0;
    const _this2 = {};
    _this2.add = function(key) {
      if (_this2.contains(key)) {
        throw "dup key:" + key;
      }
      _map[key] = _size;
      _size += 1;
    };
    _this2.size = function() {
      return _size;
    };
    _this2.indexOf = function(key) {
      return _map[key];
    };
    _this2.contains = function(key) {
      return typeof _map[key] != "undefined";
    };
    return _this2;
  };
  return _this;
};
var createDataURL = function(width, height, getPixel) {
  const gif = gifImage(width, height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      gif.setPixel(x, y, getPixel(x, y));
    }
  }
  const b = byteArrayOutputStream();
  gif.write(b);
  const base64 = base64EncodeOutputStream();
  const bytes = b.toByteArray();
  for (let i = 0; i < bytes.length; i += 1) {
    base64.writeByte(bytes[i]);
  }
  base64.flush();
  return "data:image/gif;base64," + base64;
};
var qrcode_default = qrcode;
var stringToBytes = qrcode.stringToBytes;

// spaces/public/qrRender.js
function qrModules(text) {
  const qr = qrcode_default(0, "M");
  qr.addData(String(text));
  qr.make();
  const size = qr.getModuleCount();
  return { size, isDark: (r, c) => qr.isDark(r, c) };
}

// tools/rc-qr.mjs
var QUIET = 4;
function qrAnsi(text) {
  const { size, isDark } = qrModules(text);
  const DARK = "\x1B[40m  \x1B[0m";
  const LIGHT = "\x1B[47m  \x1B[0m";
  const rowStr = (cells) => cells.map((d) => d ? DARK : LIGHT).join("");
  const lines = [];
  const blank = new Array(size + QUIET * 2).fill(false);
  for (let i = 0; i < QUIET; i++) lines.push(rowStr(blank));
  for (let r = 0; r < size; r++) {
    const cells = [...Array(QUIET).fill(false), ...Array.from({ length: size }, (_, c) => isDark(r, c)), ...Array(QUIET).fill(false)];
    lines.push(rowStr(cells));
  }
  for (let i = 0; i < QUIET; i++) lines.push(rowStr(blank));
  return lines.join("\n");
}
function qrSvg(text, px = 320) {
  const { size, isDark } = qrModules(text);
  const dim = size + QUIET * 2;
  const rects = [];
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (isDark(r, c)) rects.push(`<rect x="${c + QUIET}" y="${r + QUIET}" width="1" height="1"/>`);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges" role="img" aria-label="Pairing QR"><rect width="${dim}" height="${dim}" fill="#fff"/><g fill="#000">${rects.join("")}</g></svg>`;
}

// tools/rc-link.mjs
var parseOrigins = (env) => String(env || "https://spaces.witbitz.chat,https://witbitz-spaces.pages.dev").split(",").map((o) => o.trim().replace(/\/$/, "")).filter(Boolean);
var ORIGINS = parseOrigins(process.env.RC_LINK_ORIGIN);
var ACCOUNT_PATH = process.env.RC_ACCOUNT || join(homedir(), ".witbitz-rc.account.json");
var POLL_MS = 2500;
var LIFE_MS = Number(process.env.RC_LINK_WAIT_MS || 3e5);
function accountFromPayload(pay) {
  if (!pay || typeof pay.master !== "string" || !pay.master) return null;
  return {
    v: 1,
    linkedAt: Date.now(),
    master: pay.master,
    code: pay.code || "",
    email: pay.email || pay.anchor && pay.anchor.email || "",
    idx: pay.idx || null,
    // the INDEX ROOM (the drawer's sync doc) — the whole point: write a room here → it shows in the drawer
    rel: pay.rel || null,
    // gated-backup release token, if the giver passed a factor — lets a future backup-pull fetch the index room when idx wasn't handed over
    pipes: pay.pipes || null,
    anchor: pay.anchor || null
  };
}
async function pullIndexRoom(account, origins, fetchImpl = fetch) {
  if (!account || !account.master) return null;
  let master;
  try {
    master = Buffer.from(String(account.master).replace(/-/g, "+").replace(/_/g, "/"), "base64");
  } catch {
    return null;
  }
  if (master.length !== 32) return null;
  const loc = await deriveKeysFromSecret(new Uint8Array(master));
  const rel = account.rel && account.rel.token;
  for (const origin of origins) {
    let blob = null;
    if (rel) {
      try {
        const r = await fetchImpl(`${origin}/api/backup/release`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: rel, id: loc.id }) }).then((x) => x.json());
        if (r && r.ok && r.blob) blob = r.blob;
      } catch {
      }
    }
    if (!blob) continue;
    try {
      const payload = await unseal(loc.key, blob);
      if (payload && payload.indexRoom && payload.indexRoom.room && payload.indexRoom.mk) return payload.indexRoom;
    } catch {
    }
  }
  return null;
}
function storeAccount(account, path = ACCOUNT_PATH) {
  const tmp = `${path}.${process.pid}.${Date.now().toString(36)}.tmp`;
  writeFileSync(tmp, JSON.stringify(account, null, 1), { mode: 384 });
  chmodSync(tmp, 384);
  renameSync(tmp, path);
  return path;
}
async function linkNode({ accountPath = ACCOUNT_PATH, lifeMs = LIFE_MS, nextHint = true } = {}) {
  const ch = await newLinkChallenge();
  console.log(`rc-link: pairing this node to your account \xB7 polling ${ORIGINS.join(", ")}
`);
  console.log("On your phone or desktop, in Spaces: Settings \u2192 Back up & recovery \u2192 Add a device, then scan this:\n");
  console.log(qrAnsi(ch.text) + "\n");
  const svg = join(homedir(), ".witbitz-rc.link.svg");
  writeFileSync(svg, qrSvg(ch.text) + "\n");
  chmodSync(svg, 384);
  console.log(`  (QR also saved to ${svg} \xB7 raw: ${ch.text})`);
  console.log(`  waiting up to ${Math.round(lifeMs / 1e3)}s for your device to seal the account to this node\u2026
`);
  const until = Date.now() + lifeMs;
  let warned503 = false;
  while (Date.now() < until) {
    await new Promise((r2) => setTimeout(r2, POLL_MS));
    let r = null;
    for (const origin of ORIGINS) {
      let rr;
      try {
        rr = await fetch(`${origin}/api/link?ref=${ch.ref}`, { cache: "no-store" }).then((x) => x.json());
      } catch {
        continue;
      }
      if (rr && rr.reason === "unavailable" && !warned503) {
        console.error(`rc-link: note \u2014 ${origin} has no device-link relay (OTP_KV unbound); ignoring it.`);
        warned503 = true;
      }
      if (rr && rr.ok) {
        r = rr;
        break;
      }
    }
    if (!r || !r.ok) continue;
    let pay = null;
    try {
      pay = readLinkPayload(await openLinkReply(ch.priv, { ref: ch.ref, epk: r.epk, blob: r.blob }));
    } catch {
    }
    if (!pay) {
      console.error("rc-link: a reply arrived but did not open \u2014 start again on both devices.");
      return null;
    }
    const account = accountFromPayload(pay);
    if (!account) {
      console.error("rc-link: the reply carried no account key.");
      return null;
    }
    let idxVia = account.idx ? "link" : "";
    if (!account.idx) {
      process.stdout.write("rc-link: no index pointer in the link \u2014 recovering it from your account backup\u2026 ");
      const idx = await pullIndexRoom(account, ORIGINS).catch(() => null);
      if (idx) {
        account.idx = idx;
        idxVia = "backup";
        console.log("\u2713");
      } else console.log("not found (the release token may have expired \u2014 re-link, or use the one-tap link from rc-mkroom)");
    }
    const path = storeAccount(account, accountPath);
    console.log(`rc-link: \u2713 linked as a device of ${account.email || "(your account)"}`);
    console.log(`  account \u2192 ${path} (0600)`);
    console.log(`  index room \u2192 ${account.idx ? account.idx.room + " (via " + idxVia + ")" : "(none \u2014 rc-mkroom will fall back to a one-tap link)"}`);
    if (nextHint) console.log(`
next: create a code room that lands in your drawer:  node tools/rc-mkroom.mjs`);
    return account;
  }
  console.error("rc-link: the code expired before your device sealed to it. Run it again for a fresh QR.");
  return null;
}
if (false) {
  linkNode().then((a) => {
    if (!a) process.exit(1);
  }).catch((e) => {
    console.error("rc-link: FATAL \u2014", e && e.message || e);
    process.exit(1);
  });
}

// spaces/public/codeComputers.js
var COMPUTERS_DOC = "computers";
var ID = /^[A-Za-z0-9_-]{8,64}$/;
var SECRET = /^[A-Za-z0-9_-]{43}$/;
var okRelay = (u) => {
  try {
    const x = new URL(String(u));
    return x.protocol === "wss:" || x.protocol === "ws:" && ["127.0.0.1", "localhost"].includes(x.hostname);
  } catch {
    return false;
  }
};
var num = (v) => typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
var dict = (src) => Object.assign(/* @__PURE__ */ Object.create(null), src || {});
function normEntry(e) {
  if (!e || typeof e !== "object") return null;
  const mod = num(e.mod);
  if (!mod) return null;
  if (e.removed) return { removed: true, mod };
  if (typeof e.secret !== "string" || !SECRET.test(e.secret) || !okRelay(e.relay)) return null;
  return { name: Array.from(String(e.name || "computer")).slice(0, 80).join(""), relay: String(e.relay), secret: e.secret, pairedAt: num(e.pairedAt) || mod, mod };
}
function normRegistry(doc) {
  const out = { v: 1, computers: dict() };
  const src = doc && typeof doc === "object" && doc.computers && typeof doc.computers === "object" ? doc.computers : {};
  for (const [id, e] of Object.entries(src)) {
    if (!ID.test(id)) continue;
    const n = normEntry(e);
    if (n) out.computers[id] = n;
  }
  return out;
}
function mergeRegistry(a, b) {
  const x = normRegistry(a), y = normRegistry(b);
  const out = { v: 1, computers: dict(x.computers) };
  for (const [id, e] of Object.entries(y.computers)) {
    const cur = out.computers[id];
    if (!cur || e.mod > cur.mod || e.mod === cur.mod && e.removed && !cur.removed) out.computers[id] = e;
  }
  return out;
}
function liveComputers(reg) {
  return Object.entries(normRegistry(reg).computers).filter(([, e]) => !e.removed).sort((p, q) => p[1].pairedAt - q[1].pairedAt || (p[0] < q[0] ? -1 : 1)).map(([id, e]) => ({ id, name: e.name, relay: e.relay, secret: e.secret }));
}
function withComputer(reg, id, { name, relay, secret }, now = Date.now()) {
  const prev = normRegistry(reg).computers[id];
  const mod = Math.max(now, prev ? prev.mod + 1 : 0);
  return mergeRegistry(reg, { computers: dict({ [id]: { name, relay, secret, pairedAt: prev && !prev.removed ? prev.pairedAt : now, mod } }) });
}
function withoutComputer(reg, id, now = Date.now()) {
  const prev = normRegistry(reg).computers[id];
  return mergeRegistry(reg, { computers: dict({ [id]: { removed: true, mod: Math.max(now, prev ? prev.mod + 1 : 0) } }) });
}

// spaces/public/codeRelay.js
var RELAY_URL = "wss://code-relay.witbitz.chat";
var SALT2 = "witbitz-code-relay-v1";
var te2 = new TextEncoder();
var td2 = new TextDecoder();
function b64u(bytes) {
  let s = "";
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i += 32768) s += String.fromCharCode.apply(null, b.subarray(i, i + 32768));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(str) {
  const s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - s.length % 4) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
var newRelaySecret = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
async function deriveRelay(secret) {
  const raw = unb64u(secret);
  if (raw.length !== 32) throw new Error("relay secret must be 32 bytes");
  const base = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits", "deriveKey"]);
  const params = (info) => ({ name: "HKDF", hash: "SHA-256", salt: te2.encode(SALT2), info: te2.encode(info) });
  const channel = b64u(await crypto.subtle.deriveBits(params("channel"), base, 256));
  const key = (info) => crypto.subtle.deriveKey(params(info), base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { channel, c2s: await key("client-to-computer"), s2c: await key("computer-to-client") };
}
var aadOf = (v, s, q) => te2.encode(`wbcr1|${v}|${s}|${q}`);
function makeSealer(key) {
  const s = b64u(crypto.getRandomValues(new Uint8Array(12)));
  let q = 0;
  return {
    sender: s,
    async seal(msg) {
      const seq = ++q;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadOf(1, s, seq) }, key, te2.encode(JSON.stringify(msg)));
      return JSON.stringify({ v: 1, s, q: seq, n: b64u(iv), c: b64u(ct) });
    }
  };
}
function makeOpener(key, { maxSenders = 64, onEvict = () => {
} } = {}) {
  const last = /* @__PURE__ */ new Map();
  return {
    async open(text) {
      let f;
      try {
        f = typeof text === "string" ? JSON.parse(text) : null;
      } catch {
        return null;
      }
      if (!f || f.v !== 1 || typeof f.s !== "string" || !Number.isSafeInteger(f.q) || f.q < 1 || typeof f.n !== "string" || typeof f.c !== "string") return null;
      if (f.q <= (last.get(f.s) || 0)) return null;
      let pt;
      try {
        pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(f.n), additionalData: aadOf(f.v, f.s, f.q) }, key, unb64u(f.c));
      } catch {
        return null;
      }
      if (f.q <= (last.get(f.s) || 0)) return null;
      last.delete(f.s);
      last.set(f.s, f.q);
      if (last.size > maxSenders) {
        const gone = last.keys().next().value;
        last.delete(gone);
        try {
          onEvict(gone);
        } catch {
        }
      }
      try {
        return JSON.parse(td2.decode(pt));
      } catch {
        return null;
      }
    }
  };
}
function peersOf(text) {
  if (typeof text !== "string" || !text.startsWith('{"t":"peers"')) return null;
  try {
    const m = JSON.parse(text);
    return Number.isInteger(m.n) ? m.n : null;
  } catch {
    return null;
  }
}
var CHUNK = 192 * 1024;
var MAX_TOTAL = 32 * 1024 * 1024;
function chunkMessage(msg, size = CHUNK) {
  if (typeof msg.b !== "string" || msg.b.length <= size) return [msg];
  const of = Math.ceil(msg.b.length / size);
  const parts = [];
  for (let i = 0; i < of; i++) parts.push({ ...msg, b: msg.b.slice(i * size, (i + 1) * size), part: i, of });
  return parts;
}
function makeReassembler({ timeoutMs = 6e4, maxTotal = MAX_TOTAL } = {}) {
  const open = /* @__PURE__ */ new Map();
  return {
    push(msg) {
      if (!msg || msg.of === void 0) return msg;
      const { of, part } = msg;
      if (!Number.isInteger(of) || of < 1 || !Number.isInteger(part) || part < 0 || part >= of || typeof msg.b !== "string") return null;
      const k = `${msg.t}:${msg.id}`;
      const now = Date.now();
      for (const [key, e2] of open) if (now - e2.at > timeoutMs) open.delete(key);
      let e = open.get(k);
      if (!e) {
        e = { parts: new Array(of), got: 0, size: 0, at: now };
        open.set(k, e);
      }
      if (e.parts.length !== of) {
        open.delete(k);
        return null;
      }
      if (e.parts[part] === void 0) {
        e.parts[part] = msg.b;
        e.got++;
        e.size += msg.b.length;
      }
      if (e.size > maxTotal) {
        open.delete(k);
        return null;
      }
      if (e.got < of) return null;
      open.delete(k);
      const whole = { ...msg, b: e.parts.join("") };
      delete whole.part;
      delete whole.of;
      return whole;
    }
  };
}
var RelayPeer = class {
  constructor({ secret, role, relay = RELAY_URL, WebSocketImpl = globalThis.WebSocket, onMessage = () => {
  }, onPeers = () => {
  }, onState = () => {
  }, onEvict = () => {
  }, maxSenders = 64, minBackoff = 500, maxBackoff = 15e3 }) {
    if (role !== "client" && role !== "computer") throw new Error("role must be client or computer");
    Object.assign(this, { secret, role, relay: String(relay).replace(/\/+$/, ""), WebSocketImpl, onMessage, onPeers, onState, onEvict, maxSenders, minBackoff, maxBackoff });
    this.peers = 0;
    this.state = "idle";
    this.ws = null;
    this.backoff = minBackoff;
    this.timer = 0;
    this.stopped = true;
    this.reasm = makeReassembler();
    this.keys = null;
    this.sendChain = Promise.resolve();
    this.recvChain = Promise.resolve();
  }
  async start() {
    if (!this.stopped) return;
    this.stopped = false;
    if (!this.keys) this.keys = await deriveRelay(this.secret);
    this.connect();
  }
  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    this.waiting = false;
    try {
      if (this.ws) this.ws.close(1e3);
    } catch {
    }
    this.ws = null;
    this.setState("closed");
  }
  /** Reconnect now (e.g. the page became visible again) instead of waiting out the backoff. */
  kick() {
    if (this.stopped || this.state === "open" || this.state === "connecting" && !this.waiting) return;
    clearTimeout(this.timer);
    this.waiting = false;
    this.backoff = this.minBackoff;
    this.connect();
  }
  /** Drop the current socket and dial again now — for a socket that is "open" but has gone silent (a dead network path). */
  reconnect() {
    if (this.stopped) return;
    const ws = this.ws;
    this.ws = null;
    try {
      if (ws) ws.close(4e3, "silent");
    } catch {
    }
    this.peers = 0;
    clearTimeout(this.timer);
    this.waiting = false;
    this.backoff = this.minBackoff;
    this.connect();
  }
  get channel() {
    return this.keys && this.keys.channel;
  }
  get isOpen() {
    return this.state === "open";
  }
  setState(s) {
    if (this.state !== s) {
      this.state = s;
      try {
        this.onState(s);
      } catch {
      }
    }
  }
  connect() {
    if (this.stopped) return;
    const { c2s, s2c, channel } = this.keys;
    const sealer = makeSealer(this.role === "client" ? c2s : s2c);
    const opener = makeOpener(this.role === "client" ? s2c : c2s, { maxSenders: this.maxSenders, onEvict: (s) => this.onEvict(s) });
    let ws;
    try {
      ws = new this.WebSocketImpl(`${this.relay}/c/${channel}`);
    } catch {
      this.retry();
      return;
    }
    this.ws = ws;
    this.sealer = sealer;
    this.setState("connecting");
    ws.onopen = () => {
      if (this.ws !== ws) return;
      this.backoff = this.minBackoff;
      this.setState("open");
    };
    ws.onmessage = (e) => {
      this.recvChain = this.recvChain.then(async () => {
        if (this.ws !== ws) return;
        const text = typeof e.data === "string" ? e.data : null;
        const n = peersOf(text);
        if (n !== null) {
          this.peers = n;
          try {
            this.onPeers(n);
          } catch {
          }
          return;
        }
        const msg = this.reasm.push(await opener.open(text));
        if (msg) {
          try {
            this.onMessage(msg);
          } catch {
          }
        }
      }).catch(() => {
      });
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.peers = 0;
      try {
        this.onPeers(0);
      } catch {
      }
      this.retry();
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
      }
    };
  }
  retry() {
    if (this.stopped) return;
    this.setState("connecting");
    clearTimeout(this.timer);
    const wait = this.backoff;
    this.backoff = Math.min(this.maxBackoff, this.backoff * 2);
    this.waiting = true;
    this.timer = setTimeout(() => {
      this.waiting = false;
      this.connect();
    }, wait);
  }
  /** Seal and send (chunked if large). Resolves false when there is no open socket — the caller decides what that means. */
  send(msg) {
    const run = async () => {
      const ws = this.ws;
      if (!ws || this.state !== "open") return false;
      const sealer = this.sealer;
      for (const part of chunkMessage(msg)) {
        const frame = await sealer.seal(part);
        if (this.ws !== ws) return false;
        try {
          ws.send(frame);
        } catch {
          return false;
        }
      }
      return true;
    };
    const p = this.sendChain.then(run, run);
    this.sendChain = p.catch(() => false);
    return p;
  }
};
var SEG = "(?!\\.)[A-Za-z0-9_.-]{1,128}";
var ALLOW = [
  ["GET", "/experimental/session"],
  ["GET", "/agent"],
  ["GET", "/api/model"],
  ["GET", "/config"],
  ["POST", "/session"],
  ["GET", `/session/${SEG}/message`],
  ["POST", `/session/${SEG}/message`],
  ["POST", `/session/${SEG}/abort`],
  ["POST", `/session/${SEG}/permissions/${SEG}`],
  ["PATCH", `/session/${SEG}`],
  ["DELETE", `/session/${SEG}`],
  // New session's folder picker: the computer's home, and folder listings under it (names, never contents). Neither
  // raises the ceiling — a session the page can already create reads files with `read`/`list` allowed.
  ["GET", "/path"],
  ["GET", "/file"]
].map(([m, p]) => [m, new RegExp(`^${p}$`)]);
function allowedRequest(method, pathWithQuery) {
  const m = String(method || "").toUpperCase();
  const p = String(pathWithQuery || "");
  if (!p.startsWith("/") || p.includes("..") || p.includes("//") || p.includes("#")) return false;
  const path = p.split("?")[0];
  return ALLOW.some(([am, re]) => am === m && re.test(path));
}
function allowedEventPath(p) {
  const s = String(p || "");
  if (s === "/event") return true;
  const m = s.match(/^\/event\?directory=([^&#]*)$/);
  return !!m;
}

// tools/opencode-pair.mjs
var GZIP_OVER = 24e3;
async function unwrapIndexState(state) {
  return state && typeof state === "object" && typeof state.z === "string" ? gunzipB64(state.z) : state;
}
async function wrapIndexState(state) {
  return _hasGzip && _jsonBytes(state) > GZIP_OVER ? { z: await gzipB64(state) } : state;
}
var API = process.env.RC_BASE || "https://api.witbitz.chat/v1/space";
var ORIGIN = process.env.RC_ORIGIN || "https://witbitz-spaces.pages.dev";
var PAIRINGS_PATH = process.env.WITBITZ_CODE_PAIRINGS || join2(homedir2(), ".witbitz", "code", "pairings.json");
var ENV_PATH = process.env.OPENCODE_ENV_FILE || join2(homedir2(), ".opencode-server.env");
var START_HINT = true ? "node witbitz-code.mjs serve" : "bash tools/opencode-serve.sh";
function writeSecret(path, data) {
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync2(tmp, data, { mode: 384 });
    chmodSync2(tmp, 384);
    renameSync2(tmp, path);
  } catch (e) {
    try {
      rmSync(tmp, { force: true });
    } catch {
    }
    throw e;
  }
}
function envGet(text, key) {
  let v = null;
  for (const line of String(text || "").split(/\r?\n/)) {
    const m = line.match(new RegExp(`^\\s*(?:export\\s+)?${key}=(.*)$`));
    if (m) v = m[1].trim().replace(/^(['"])(.*)\1$/, "$2");
  }
  return v;
}
function envSet(text, key, value) {
  const keep = String(text || "").split(/\r?\n/).filter((l) => !new RegExp(`^\\s*(?:export\\s+)?${key}=`).test(l));
  while (keep.length && keep[keep.length - 1] === "") keep.pop();
  keep.push(`${key}=${value}`);
  return keep.join("\n") + "\n";
}
var newPassword = () => randomBytes(24).toString("base64url");
var newComputerId = () => randomBytes(16).toString("base64url");
function normPairings(doc) {
  const list = doc && Array.isArray(doc.pairings) ? doc.pairings : [];
  return { v: 1, pairings: list.filter((p) => p && p.idx && p.idx.room && p.idx.mk && typeof p.secret === "string" && typeof p.computerId === "string") };
}
function upsertPairing(doc, { account, idx, name, relay = RELAY_URL, opencodeUrl = "http://127.0.0.1:4096" }, { rotate = false, mintId = newComputerId, mintSecret = newRelaySecret } = {}) {
  const cur = normPairings(doc);
  const i = cur.pairings.findIndex((p) => p.idx.room === idx.room);
  const prev = i >= 0 ? cur.pairings[i] : null;
  const entry = {
    account: account || prev && prev.account || "",
    idx: { room: idx.room, mk: idx.mk },
    computerId: prev ? prev.computerId : mintId(),
    secret: prev && !rotate ? prev.secret : mintSecret(),
    name: name || prev && prev.name || hostname(),
    relay,
    opencodeUrl: prev && prev.opencodeUrl || opencodeUrl
  };
  const pairings = cur.pairings.slice();
  if (i >= 0) pairings[i] = entry;
  else pairings.push(entry);
  const others = pairings.filter((p) => p.idx.room !== idx.room && p.opencodeUrl === entry.opencodeUrl);
  return { doc: { v: 1, pairings }, entry, isNew: !prev, sharedWith: others.map((p) => p.account || "(another account)") };
}
function removePairings(doc, account = "") {
  const cur = normPairings(doc);
  const gone = cur.pairings.filter((p) => !account || p.account === account);
  return { doc: { v: 1, pairings: cur.pairings.filter((p) => !gone.includes(p)) }, removed: gone };
}
async function readDoc(call2, idx, name) {
  const rd = await call2({ op: "state", room: idx.room, mk: idx.mk, name });
  if (rd.status !== 200 || !rd.j || rd.j.error) return { ok: false, why: `${name} read refused (${rd.status}${rd.j && rd.j.error ? ": " + rd.j.error : ""}) \u2014 NOT writing` };
  try {
    return { ok: true, state: await unwrapIndexState(rd.j.state || null) };
  } catch (e) {
    return { ok: false, why: `${name} unreadable (${e && e.message || e}) \u2014 NOT writing` };
  }
}
async function publishComputer({ call: call2, idx, computerId, name, relay, secret, now = Date.now() }) {
  const rd = await readDoc(call2, idx, COMPUTERS_DOC);
  if (!rd.ok) return rd;
  const next = withComputer(rd.state, computerId, { name, relay, secret }, now);
  const wr = await call2({ op: "state", room: idx.room, mk: idx.mk, name: COMPUTERS_DOC, patch: await wrapIndexState({ ...next, at: now }), summary: "computer paired", by: "node" });
  if (wr.status !== 200) return { ok: false, why: `computers write refused (${wr.status})` };
  const back = await readDoc(call2, idx, COMPUTERS_DOC);
  const got = back.ok && normRegistry(back.state).computers[computerId];
  if (!got || got.removed || got.secret !== secret) return { ok: false, why: "wrote the registry but the read-back does not match \u2014 check the account before relying on it" };
  return { ok: true, computers: liveComputers(back.state) };
}
async function unpublishComputer({ call: call2, idx, computerId, now = Date.now() }) {
  const rd = await readDoc(call2, idx, COMPUTERS_DOC);
  if (!rd.ok) return rd;
  const cur = normRegistry(rd.state).computers[computerId];
  if (!cur || cur.removed) return { ok: true, noop: true };
  const next = withoutComputer(rd.state, computerId, now);
  const wr = await call2({ op: "state", room: idx.room, mk: idx.mk, name: COMPUTERS_DOC, patch: await wrapIndexState({ ...next, at: now }), summary: "computer unpaired", by: "node" });
  if (wr.status !== 200) return { ok: false, why: `computers write refused (${wr.status})` };
  const back = await readDoc(call2, idx, COMPUTERS_DOC);
  if (!back.ok || !normRegistry(back.state).computers[computerId] || !normRegistry(back.state).computers[computerId].removed) return { ok: false, why: "wrote the tombstone but the read-back does not show it" };
  return { ok: true };
}
async function clearLegacyDirect({ call: call2, idx, now = Date.now() }) {
  const rd = await readDoc(call2, idx, "index2");
  if (!rd.ok) return rd;
  const s = rd.state && typeof rd.state === "object" ? rd.state : {};
  const prev = s.code && typeof s.code === "object" ? s.code : null;
  if (!prev || !prev.base && !prev.pass) return { ok: true, noop: true };
  const code = { base: "", pass: "", model: typeof prev.model === "string" ? prev.model : "", agent: typeof prev.agent === "string" ? prev.agent : "", mod: Math.max(now, (Number(prev.mod) || 0) + 1) };
  const next = { ...s, v: s.v || 2, code, at: now };
  const wr = await call2({ op: "state", room: idx.room, mk: idx.mk, name: "index2", patch: await wrapIndexState(next), summary: "code direct server cleared", by: "node" });
  if (wr.status !== 200) return { ok: false, why: `index2 write refused (${wr.status})` };
  const back = await readDoc(call2, idx, "index2");
  if (!back.ok || !back.state || !back.state.code || back.state.code.base !== "" || back.state.code.pass !== "") return { ok: false, why: "cleared index2 but the read-back does not match" };
  return { ok: true };
}
var call = async (body) => {
  const r = await fetch(API, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: JSON.stringify(body) });
  let j = null;
  try {
    j = await r.json();
  } catch {
  }
  return { status: r.status, j };
};
var readPairings = () => {
  try {
    return normPairings(JSON.parse(readFileSync(PAIRINGS_PATH, "utf8")));
  } catch {
    return normPairings(null);
  }
};
function writePairings(doc) {
  mkdirSync(dirname(PAIRINGS_PATH), { recursive: true, mode: 448 });
  writeSecret(PAIRINGS_PATH, JSON.stringify(doc, null, 1) + "\n");
}
function parseArgs(argv) {
  const a = { rotate: false, dry: false, unpair: false, status: false, name: "", account: "", opencodeUrl: "" };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === "--rotate") a.rotate = true;
    else if (x === "--dry-run") a.dry = true;
    else if (x === "--unpair") a.unpair = true;
    else if (x === "--status") a.status = true;
    else if (x === "--name") a.name = argv[++i] || "";
    else if (x === "--account") a.account = argv[++i] || "";
    else if (x === "--opencode-url") a.opencodeUrl = argv[++i] || "";
    else if (x === "--port") {
      const p = Number(argv[++i]);
      if (p) a.opencodeUrl = `http://127.0.0.1:${p}`;
    } else {
      console.error(`opencode-pair: unknown argument ${x}`);
      process.exit(2);
    }
  }
  return a;
}
async function linkByQr() {
  console.log("opencode-pair: on your phone open Spaces \u2192 Settings \u2192 Back up & recovery \u2192 Add a device, and scan the QR below with the account to pair.\n");
  const dir = mkdtempSync(join2(tmpdir(), "oc-pair-"));
  const tmp = join2(dir, "account.json");
  try {
    const acct = await linkNode({ accountPath: tmp, nextHint: false });
    if (!acct) return null;
    if (!acct.idx || !acct.idx.room || !acct.idx.mk) {
      console.error("opencode-pair: the scan carried no index-room pointer, so there is nowhere to publish \u2014 nothing changed.");
      return null;
    }
    return acct;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
function ensureLocalPassword() {
  const envText = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  if (envGet(envText, "OPENCODE_SERVER_PASSWORD")) return;
  writeSecret(ENV_PATH, envSet(envText, "OPENCODE_SERVER_PASSWORD", newPassword()));
  console.log(`opencode-pair: \u2713 minted a local OpenCode password in ${ENV_PATH} (0600) \u2014 it never leaves this computer`);
}
async function publishEntry(e) {
  const r = await publishComputer({ call, idx: e.idx, computerId: e.computerId, name: e.name, relay: e.relay, secret: e.secret });
  if (!r.ok) {
    console.error(`opencode-pair: \u2716 ${e.account || "account"}: ${r.why}`);
    return false;
  }
  console.log(`opencode-pair: \u2713 "${e.name}" is in ${e.account || "the account"}'s computers (${r.computers.length} paired)`);
  const l = await clearLegacyDirect({ call, idx: e.idx });
  if (!l.ok) console.log(`opencode-pair: \u26A0 could not clear the old direct-server settings (${l.why}) \u2014 harmless while a computer is paired`);
  else if (!l.noop) console.log("opencode-pair: \u2713 cleared the old direct-server address from the account (devices use the relay now)");
  return true;
}
async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const doc = readPairings();
  if (args.status) {
    if (!doc.pairings.length) console.log("opencode-pair: not paired");
    for (const p of doc.pairings) console.log(`\xB7 "${p.name}" \u2192 ${p.account || "(account)"} \xB7 OpenCode ${p.opencodeUrl} \xB7 relay ${p.relay}`);
    return;
  }
  if (args.unpair) {
    const targets = doc.pairings.filter((p) => !args.account || p.account === args.account);
    if (!targets.length) {
      console.error(`opencode-pair: no pairing${args.account ? " for " + args.account : ""} on this computer`);
      process.exit(1);
    }
    if (targets.length > 1 && !args.account) {
      console.error(`opencode-pair: this computer is paired with ${targets.length} accounts (${targets.map((p) => p.account).join(", ")}) \u2014 pass --account <email>`);
      process.exit(1);
    }
    if (args.dry) {
      console.log(`opencode-pair: --dry-run \u2014 would remove "${targets[0].name}" from ${targets[0].account}`);
      return;
    }
    let ok = true;
    for (const p of targets) {
      const r = await unpublishComputer({ call, idx: p.idx, computerId: p.computerId });
      if (!r.ok) {
        ok = false;
        console.error(`opencode-pair: \u2716 ${p.account}: ${r.why} \u2014 kept the local pairing so you can retry`);
        continue;
      }
      console.log(`opencode-pair: \u2713 removed "${p.name}" from ${p.account}${r.noop ? " (it was not listed)" : ""} \u2014 every device drops it on its next sync`);
      writePairings(removePairings(readPairings(), p.account).doc);
    }
    console.log(`opencode-pair: restart the connector (${START_HINT}) so it stops answering on the old channel.`);
    if (!ok) process.exit(1);
    return;
  }
  if (args.rotate) {
    if (!doc.pairings.length) {
      console.error("opencode-pair: nothing to rotate \u2014 pair first");
      process.exit(1);
    }
    const toRotate = doc.pairings.filter((x) => !args.account || x.account === args.account);
    if (args.dry) {
      console.log(`opencode-pair: --dry-run \u2014 would rotate ${toRotate.length} pairing(s)`);
      return;
    }
    let cur = doc;
    let ok = true;
    for (const p of toRotate) {
      const u2 = upsertPairing(cur, { account: p.account, idx: p.idx, name: p.name, relay: p.relay, opencodeUrl: p.opencodeUrl }, { rotate: true });
      if (await publishEntry(u2.entry)) {
        cur = u2.doc;
        writePairings(cur);
      } else ok = false;
    }
    console.log("opencode-pair: restart the connector so it listens on the new channel(s).");
    if (!ok) process.exit(1);
    return;
  }
  if (args.dry) {
    console.log("opencode-pair: --dry-run \u2014 would show the QR, then publish this computer to the scanning account");
    return;
  }
  const acct = await linkByQr();
  if (!acct) {
    console.error("opencode-pair: pairing did not complete \u2014 nothing changed.");
    process.exit(1);
  }
  const u = upsertPairing(doc, { account: acct.email || "", idx: acct.idx, name: args.name, opencodeUrl: args.opencodeUrl || void 0 });
  ensureLocalPassword();
  if (!await publishEntry(u.entry)) {
    console.error("opencode-pair: nothing saved locally \u2014 scan again to retry.");
    process.exit(1);
  }
  writePairings(u.doc);
  console.log(`opencode-pair: \u2713 ${u.isNew ? "paired" : "refreshed"} "${u.entry.name}" with ${u.entry.account || "your account"} (${PAIRINGS_PATH})`);
  if (u.sharedWith.length) {
    console.log(`opencode-pair: \u26A0 this computer's OpenCode (${u.entry.opencodeUrl}) is now reachable from ${u.entry.account} AND ${u.sharedWith.join(", ")}.`);
    console.log("               OpenCode has no users: they share every session, file and shell. Fine for your own accounts;");
    console.log("               for another person run a separate OpenCode (another port and OS user) and pair with --opencode-url.");
  }
  console.log(`opencode-pair: next \u2014 start OpenCode and the connector:  ${START_HINT}`);
}
if (false) {
  main().catch((e) => {
    console.error("opencode-pair: FATAL \u2014", e && e.message || e);
    process.exit(1);
  });
}

// tools/opencode-connector.mjs
import { readFileSync as readFileSync2, existsSync as existsSync2 } from "node:fs";
import { homedir as homedir3, hostname as hostname2 } from "node:os";
import { join as join3 } from "node:path";
var VERSION = "1";
var PAIRINGS_PATH2 = process.env.WITBITZ_CODE_PAIRINGS || join3(homedir3(), ".witbitz", "code", "pairings.json");
var DEFAULT_ENV = process.env.OPENCODE_ENV_FILE || join3(homedir3(), ".opencode-server.env");
var REQUEST_TIMEOUT_MS = 3e4;
var HELLO_EVERY_MS = 2e4;
var SUB_TTL_MS = 75e3;
var MAX_RESPONSE = 30 * 1024 * 1024;
var START_HINT2 = true ? "node witbitz-code.mjs serve" : "bash tools/opencode-serve.sh";
function parseEnvPassword(text) {
  let v = "";
  for (const line of String(text || "").split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?OPENCODE_SERVER_PASSWORD=(.*)$/);
    if (m) v = m[1].trim().replace(/^(['"])(.*)\1$/, "$2");
  }
  return v;
}
function loadPairings(path = PAIRINGS_PATH2, log = console.error) {
  if (!existsSync2(path)) return [];
  let doc;
  try {
    doc = JSON.parse(readFileSync2(path, "utf8"));
  } catch (e) {
    log(`opencode-connector: ${path} is not valid JSON (${e.message})`);
    return [];
  }
  const list = Array.isArray(doc && doc.pairings) ? doc.pairings : [];
  return list.filter((p) => {
    const ok = p && typeof p.secret === "string" && p.secret.length >= 43;
    if (!ok) log("opencode-connector: skipping a pairing with no secret");
    return ok;
  });
}
function pairingsForPort(pairings, port) {
  return pairings.filter((p) => {
    try {
      const u = new URL(p.opencodeUrl || "http://127.0.0.1:4096");
      return Number(u.port || (u.protocol === "https:" ? 443 : 80)) === Number(port);
    } catch {
      return false;
    }
  });
}
function sseReader(onData) {
  let buf = "";
  return (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.search(/\r?\n\r?\n/)) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(buf.slice(i).match(/^\r?\n\r?\n/)[0].length + i);
      const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
      if (data) onData(data);
    }
  };
}
async function startConnector({ pairings, fetchImpl = fetch, WebSocketImpl = globalThis.WebSocket, flushMs = 120, log = console.error, requestTimeoutMs = REQUEST_TIMEOUT_MS, maxSenders = 64, maxResponseBytes = MAX_RESPONSE } = {}) {
  const running = [];
  for (const p of pairings) running.push(await servePairing(p, { fetchImpl, WebSocketImpl, flushMs, log, requestTimeoutMs, maxSenders, maxResponseBytes }));
  return { peers: running.map((r) => r.peer), stop: () => {
    for (const r of running) r.stop();
  } };
}
async function servePairing(pairing, { fetchImpl, WebSocketImpl, flushMs, log, requestTimeoutMs, maxSenders, maxResponseBytes }) {
  const name = pairing.name || hostname2();
  const base = String(pairing.opencodeUrl || "http://127.0.0.1:4096").replace(/\/+$/, "");
  const password = () => pairing.password || parseEnvPassword(existsSync2(pairing.envFile || DEFAULT_ENV) ? readFileSync2(pairing.envFile || DEFAULT_ENV, "utf8") : "");
  const auth = () => {
    const pw = password();
    return pw ? { authorization: "Basic " + Buffer.from("opencode:" + pw).toString("base64") } : {};
  };
  const inflight = /* @__PURE__ */ new Map();
  const subs = /* @__PURE__ */ new Map();
  let helloTimer = 0;
  let nonce = "";
  const freshNonce = () => {
    nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString("base64url");
  };
  const peer = new RelayPeer({
    secret: pairing.secret,
    role: "computer",
    relay: pairing.relay || RELAY_URL,
    WebSocketImpl,
    maxSenders,
    onState: (s) => {
      log(`opencode-connector: ${name} \xB7 relay ${s}`);
      if (s === "open") {
        freshNonce();
        hello();
      }
    },
    onPeers: (n) => {
      if (n >= 2) hello();
      else for (const k of [...subs.keys()]) unsubscribe(k, ALL);
    },
    onMessage: (m) => {
      handle(m).catch((e) => log(`opencode-connector: ${name} \xB7 ${e && e.message}`));
    },
    // A page socket fell out of the replay window: its recorded frames would open again — rotate the nonce so every
    // request it ever sealed is refused, and tell the pages (they re-ask reads under the new one).
    onEvict: () => {
      freshNonce();
      hello();
    }
  });
  function hello() {
    if (nonce) peer.send({ t: "hello", ver: VERSION, name, computerId: pairing.computerId || "", k: nonce, ts: Date.now() });
  }
  async function handle(m) {
    if (!m || typeof m.t !== "string") return;
    if (m.t === "ping") return hello();
    const current = typeof m.k === "string" && m.k === nonce;
    if (m.t === "cancel") {
      if (current) {
        const c = inflight.get(m.id);
        if (c) c.abort();
      }
      return;
    }
    if (m.t === "sub") {
      if (current) subscribe(m.p, m.c);
      return;
    }
    if (m.t === "unsub") {
      if (current) unsubscribe(m.p, m.c);
      return;
    }
    if (m.t !== "req") return;
    const id = typeof m.id === "string" ? m.id : "";
    if (!id) return;
    const reply = (st, b) => peer.send({ t: "res", id, st, b: typeof b === "string" ? b : JSON.stringify(b) });
    if (id.length > 64) return reply(400, { error: "request id longer than 64 characters" });
    if (!current) return reply(409, { error: "stale: this computer's connector changed \u2014 reconnecting" });
    if (!allowedRequest(m.m, m.p)) return reply(403, { error: "not allowed by the connector" });
    const ctrl = new AbortController();
    inflight.set(id, ctrl);
    let timedOut = false;
    const timer = /\/message$/.test(m.p.split("?")[0]) && m.m === "POST" ? 0 : setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, requestTimeoutMs);
    try {
      const r = await fetchImpl(base + m.p, {
        method: m.m,
        headers: { ...auth(), ...typeof m.b === "string" ? { "content-type": "application/json" } : {} },
        body: typeof m.b === "string" ? m.b : void 0,
        signal: ctrl.signal
      });
      const chunks = [];
      let size = 0;
      const dec2 = new TextDecoder();
      if (r.body) {
        for await (const chunk of r.body) {
          size += chunk.byteLength;
          if (size > maxResponseBytes) {
            ctrl.abort();
            return reply(413, { error: `OpenCode's answer is over ${Math.round(maxResponseBytes / 1048576) || "<1"} MB \u2014 too large to send through the relay` });
          }
          chunks.push(dec2.decode(chunk, { stream: true }));
        }
      }
      chunks.push(dec2.decode());
      await reply(r.status, chunks.join(""));
    } catch (e) {
      if (timedOut) return reply(504, { error: `OpenCode did not answer within ${Math.round(requestTimeoutMs / 1e3)} s` });
      if (ctrl.signal.aborted) return reply(499, { error: "cancelled" });
      await reply(502, { error: `OpenCode is not answering at ${base} \u2014 start it on that computer: ${START_HINT2}` });
    } finally {
      clearTimeout(timer);
      inflight.delete(id);
    }
  }
  function subscribe(p, c) {
    if (!allowedEventPath(p)) return;
    const cid = typeof c === "string" && c ? c.slice(0, 64) : "_";
    const existing = subs.get(p);
    if (existing) {
      existing.clients.set(cid, Date.now());
      return;
    }
    const sub = { ctrl: new AbortController(), clients: /* @__PURE__ */ new Map([[cid, Date.now()]]), buffer: [], timer: 0 };
    subs.set(p, sub);
    const flush = () => {
      sub.timer = 0;
      if (!sub.buffer.length) return;
      const batch = sub.buffer.splice(0);
      peer.send({ t: "evts", p, b: JSON.stringify(batch) });
    };
    const pump = async () => {
      while (subs.get(p) === sub) {
        try {
          const r = await fetchImpl(base + p, { headers: { ...auth(), accept: "text/event-stream" }, signal: sub.ctrl.signal });
          if (!r.ok || !r.body) throw new Error(`event stream ${r.status}`);
          const feed = sseReader((data) => {
            sub.buffer.push(data);
            if (!sub.timer) sub.timer = setTimeout(flush, flushMs);
          });
          const dec2 = new TextDecoder();
          for await (const chunk of r.body) feed(dec2.decode(chunk, { stream: true }));
        } catch {
        }
        if (subs.get(p) !== sub) break;
        await new Promise((r) => setTimeout(r, 1e3));
      }
    };
    pump();
  }
  const ALL = /* @__PURE__ */ Symbol("every client");
  function unsubscribe(p, c) {
    const sub = subs.get(p);
    if (!sub) return;
    if (c !== ALL) {
      sub.clients.delete(typeof c === "string" && c ? c.slice(0, 64) : "_");
      if (sub.clients.size) return;
    }
    subs.delete(p);
    clearTimeout(sub.timer);
    try {
      sub.ctrl.abort();
    } catch {
    }
  }
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [p, s] of subs) {
      for (const [cid, at] of s.clients) if (now - at > SUB_TTL_MS) s.clients.delete(cid);
      if (!s.clients.size) unsubscribe(p, ALL);
    }
  }, 15e3);
  helloTimer = setInterval(() => {
    if (peer.peers >= 2) hello();
  }, HELLO_EVERY_MS);
  await peer.start();
  return {
    peer,
    stop: () => {
      clearInterval(sweep);
      clearInterval(helloTimer);
      for (const k of [...subs.keys()]) unsubscribe(k, ALL);
      for (const c of inflight.values()) {
        try {
          c.abort();
        } catch {
        }
      }
      peer.stop();
    }
  };
}
if (false) {
  main().catch((e) => {
    console.error("opencode-connector: FATAL \u2014", e && e.message || e);
    process.exit(1);
  });
}

// tools/witbitz-code.mjs
import { readFileSync as readFileSync3, existsSync as existsSync3 } from "node:fs";
import { homedir as homedir4 } from "node:os";
import { join as join4 } from "node:path";
var VERSION2 = "1.0.0";
var ENV_PATH2 = process.env.OPENCODE_ENV_FILE || join4(homedir4(), ".opencode-server.env");
var HELP = `witbitz-code ${VERSION2} \u2014 reach OpenCode on this computer from the Spaces Code section, end-to-end encrypted.

  pair [--name <name>]         show a QR code; scan it in Spaces (Settings \u2192 Back up & recovery \u2192 Add a device)
  serve [--port <n>] [--no-opencode]
                               start OpenCode on 127.0.0.1 (unless it is already running) and the connector
  status                       list this computer's pairings
  rotate [--account <email>]   replace the pairing secret(s) without a scan, then restart serve
  unpair [--account <email>]   remove this computer from an account

Nothing listens on the network: OpenCode stays on 127.0.0.1 and the connector dials out to wss://code-relay.witbitz.chat.
`;
var flag = (args, name, dflt = "") => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] || "" : dflt;
};
async function isListening(port) {
  try {
    await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1500) });
    return true;
  } catch {
    return false;
  }
}
async function serve(args) {
  const port = Number(flag(args, "--port", "4096")) || 4096;
  const all = loadPairings(void 0, () => {
  });
  if (!all.length) {
    console.error("witbitz-code: this computer is not paired yet \u2014 run: witbitz-code pair");
    process.exit(1);
  }
  const mine = pairingsForPort(all, port);
  if (!mine.length) {
    console.error(`witbitz-code: no pairing uses OpenCode on port ${port} \u2014 pair with: witbitz-code pair --port ${port}`);
    process.exit(1);
  }
  let child = null;
  if (!await isListening(port) && !args.includes("--no-opencode")) {
    const found = spawnSync(process.platform === "win32" ? "where" : "which", ["opencode"], { encoding: "utf8" });
    if (found.status !== 0) {
      console.error("witbitz-code: OpenCode is not installed (or not on PATH). Install it, then run serve again:");
      console.error("  npm install -g opencode-ai        or        curl -fsSL https://opencode.ai/install | bash");
      process.exit(1);
    }
    const password = existsSync3(ENV_PATH2) ? parseEnvPassword(readFileSync3(ENV_PATH2, "utf8")) : "";
    console.error(`witbitz-code: starting OpenCode on 127.0.0.1:${port}`);
    const env = { ...process.env, ...password ? { OPENCODE_SERVER_PASSWORD: password } : {} };
    child = spawn("opencode", ["serve", "--port", String(port), "--hostname", "127.0.0.1"], { stdio: "inherit", env });
    child.on("exit", (code) => {
      console.error(`witbitz-code: OpenCode exited (${code}) \u2014 stopping`);
      process.exit(code || 0);
    });
    const stop = () => {
      try {
        child.kill();
      } catch {
      }
    };
    process.on("exit", stop);
    for (let i = 0; i < 40 && !await isListening(port); i++) await new Promise((r) => setTimeout(r, 250));
  }
  const c = await startConnector({ pairings: mine });
  console.error(`witbitz-code: serving ${mine.map((p) => `"${p.name}" \u2192 ${p.account || "account"}`).join(", ")} through the sealed relay (Ctrl-C to stop)`);
  const bye = () => {
    c.stop();
    process.exit(0);
  };
  process.on("SIGINT", bye);
  process.on("SIGTERM", bye);
}
var [cmd, ...rest] = process.env.WITBITZ_CODE_IMPORT === "1" ? ["__import__"] : process.argv.slice(2);
switch (cmd) {
  case "__import__":
    break;
  case "pair":
    await main(rest);
    break;
  case "serve":
    await serve(rest);
    break;
  case "status":
    await main(["--status"]);
    break;
  case "rotate":
    await main(["--rotate", ...rest]);
    break;
  case "unpair":
    await main(["--unpair", ...rest]);
    break;
  case "version":
  case "--version":
  case "-v":
    console.log(VERSION2);
    break;
  default:
    console.log(HELP);
    if (cmd && cmd !== "help" && cmd !== "--help" && cmd !== "-h") process.exit(2);
}
export {
  pairingsForPort
};
