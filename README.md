# witbitz-code

Reach [OpenCode](https://opencode.ai) on your own computer from the **Code** section of the Witbitz Spaces app — your
phone on cellular, a tablet, another laptop — end-to-end encrypted, with no open port, no VPN and no server address to
type.

```
 Spaces app (Code)                                             your computer
 seals every request ──wss──▶  code-relay.witbitz.chat  ◀──wss── witbitz-code (connector) ──http──▶ opencode serve
                               forwards sealed frames                                         127.0.0.1 only
                               it cannot read
```

- **OpenCode stays on `127.0.0.1`.** The connector makes one *outbound* WebSocket to the relay and calls OpenCode's API
  locally, the way a browser on the same machine would.
- **Every frame is AES-256-GCM** under keys derived (HKDF-SHA-256) from a 32-byte pairing secret that only your devices
  and your computer hold. The relay sees a random channel name, timing and sizes — never content.
- **The connector does only what the Code page does** (sessions, turns, permissions, the model catalog, the event
  stream). Any other OpenCode call is refused on your computer, before it reaches OpenCode.

Setup guide: **[witbitz.chat/docs/opencode.md](https://witbitz.chat/docs/opencode.md)**.
The full design — wire format, key derivation, replay protection, the relay's limits — is
[`docs/opencode-relay.md`](docs/opencode-relay.md).

## Install

**Single file (Node.js ≥ 22)** — the build the app serves:

```bash
curl -fsSLo witbitz-code.mjs https://app.witbitz.chat/downloads/witbitz-code.mjs
node witbitz-code.mjs pair --name "my laptop"   # scan the QR in Spaces → Settings → Back up & recovery → Add a device
node witbitz-code.mjs serve                     # starts OpenCode on 127.0.0.1:4096 if needed, then the connector
```

**Python (≥ 3.10)** — a second, independent implementation of the same protocol:

```bash
pipx install "git+https://github.com/witbitzchat/witbitz-code#subdirectory=packages/witbitz-code-py"
witbitz-code pair --name "my laptop"
witbitz-code serve
```

Commands, in both: `pair`, `serve [--port N]`, `status`, `rotate`, `unpair [--account EMAIL]`, `version`.

## Verify the download is this source

The single file is built from this repository with a pinned esbuild, and it ships inside the Spaces app build, so its
hash is listed in the app's asset manifest (the manifest the app's signed build certificate commits to):

```bash
npm ci && npm run build                                    # → spaces/public/downloads/witbitz-code.mjs
sha256sum spaces/public/downloads/witbitz-code.mjs
curl -s https://app.witbitz.chat/assets-manifest.json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["files"]["downloads/witbitz-code.mjs"])'
```

The two hashes match when this snapshot and the live app are the same release.

## Layout

Paths mirror the Witbitz app's repository, so imports, tests and the build are unchanged from where they run in
production.

| Path | What |
|---|---|
| `tools/witbitz-code.mjs` | the CLI (`pair`, `serve`, …) — the entry of the single-file build |
| `tools/opencode-connector.mjs` | the connector: relay socket, request allowlist, OpenCode calls, event forwarding |
| `tools/opencode-pair.mjs`, `tools/rc-link.mjs`, `tools/rc-qr.mjs` | pairing: the QR device link, the pairings file, publishing the computer to the account |
| `spaces/public/codeRelay.js` | the frame codec shared by the page and the connector: key derivation, sealing, replay window, chunking, the allowlist |
| `spaces/public/codeTransport.js`, `opencodeWire.js` | the page's side: the relay transport and OpenCode's event mapping |
| `spaces/public/codeComputers.js` | the account's sealed registry of paired computers |
| `spaces/public/deviceLink.js`, `recovery.js`, `compress.js`, `qrRender.js` | device link and account sealing used by pairing |
| `spaces/public/downloads/witbitz-code.mjs` | the built single file (a test fails if it is stale) |
| `relay/relay.mjs` | the relay — a Cloudflare Worker + Durable Object that forwards frames between the sockets on a channel |
| `packages/witbitz-code-py/` | the Python implementation, tested against the JavaScript one |
| `docs/opencode-relay.md` | the design |

Some comments and the design doc refer to parts of the Spaces app that are not in this repository (for example the Code
page itself, `opencodeApp.js`).

## Tests

```bash
npm ci
npm test              # codec, connector, pairing, page transport, QR, build freshness
npm run test:relay    # the relay in the Workers runtime (miniflare)
npm run test:python   # the Python package, including frames and flows checked against the JavaScript modules
```

(`test:python` needs `pip install -e "packages/witbitz-code-py[test]"` first.)

## Security

Please report vulnerabilities privately to **security@witbitz.chat**.

## License

MIT — see [LICENSE](LICENSE). Third-party code: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
