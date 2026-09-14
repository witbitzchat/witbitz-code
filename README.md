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
- **Auto mode is decided on your computer** (per session, off by default). What is never safe is refused, like `rm -rf ~`.
  Read-only commands inside the project and ordinary edits are allowed, and the session's own model reviews the rest
  with no tools. Anything short of a clear, low-risk allow still comes to you, and nothing is granted "always". Decisions
  are logged as digests in `~/.witbitz/code/auto-log.jsonl`. Design: [`docs/code-auto-mode.md`](docs/code-auto-mode.md).
- **Subagents ask like the session that started them.** OpenCode does not pass a session's "ask" rules on to the agents
  its task tool starts, so `serve` gives OpenCode's `explore` and `general` agents their own ask rules for shell commands,
  edits and web fetches (merged over your OpenCode config, which is never written). A refused call no longer ends the turn:
  the agent is told why. Auto lets an agent start only when that agent's own commands will ask.
  [`tools/code-opencode-policy.mjs`](tools/code-opencode-policy.mjs) has the details.
- **Confidential models are enforced here** (Node connector). TrustedRouter calls for a model labelled confidential go
  through a local proxy that requires confidential routing and checks each reply's signed receipt; images and documents
  for text-only confidential models are read through Tinfoil with your own key (`witbitz-code tinfoil-key`).
- **Attachments are saved on your computer** (`~/.witbitz/code/attachments/<session>/`), where the agent reads them like
  any file. Design: [`docs/code-attachments.md`](docs/code-attachments.md).

Setup guide: **[witbitz.chat/docs/opencode.md](https://witbitz.chat/docs/opencode.md)**.
The full design — wire format, key derivation, replay protection, the relay's limits — is
[`docs/opencode-relay.md`](docs/opencode-relay.md).

## Install

**Single file (Node.js ≥ 22)** — the build the app serves:

```bash
curl -fsSLo witbitz-code.mjs https://app.witbitz.chat/downloads/witbitz-code.mjs
node witbitz-code.mjs setup
```

`setup` walks five steps and skips what is already done: installs OpenCode if it is missing (asks first), pairs this
computer (scan the QR in Spaces → Settings → Back up & recovery → Add a device), asks for your TrustedRouter key and an
optional Tinfoil key (each checked with the provider before it is saved; the TrustedRouter key goes into OpenCode's own
`auth.json`, never into OpenCode's environment), and offers to keep it running with the computer (a systemd user
service on Linux, a launch agent on macOS). The same, one command at a time:

```bash
node witbitz-code.mjs pair --name "my laptop"   # scan the QR in Spaces → Settings → Back up & recovery → Add a device
node witbitz-code.mjs serve                     # starts OpenCode on 127.0.0.1:4096 if needed, then the connector
node witbitz-code.mjs service install           # optional: start with the computer
```

**Python (≥ 3.10)** — a second, independent implementation of the same protocol:

```bash
pipx install "git+https://github.com/witbitzchat/witbitz-code#subdirectory=packages/witbitz-code-py"
witbitz-code pair --name "my laptop"
witbitz-code serve
```

Commands, in both: `pair`, `serve [--port N]`, `status`, `rotate`, `unpair [--account EMAIL]`, `version`. The Node build
also has `setup`, `service install|uninstall|status`, `trustedrouter-key` and `tinfoil-key`, and runs the
confidential-model proxy; the Python package has none of these yet.

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
| `tools/code-setup.mjs` | `setup`: the walk-through, the TrustedRouter/Tinfoil key checks, and the systemd/launchd service |
| `tools/code-auto.mjs`, `tools/code-auto-runner.mjs` | Auto mode: the rules (hard deny, fast allow, the reviewer prompt, verdict parsing) and the loop that answers OpenCode's permission asks |
| `tools/code-auto.vectors.json` | the shared Auto cases both implementations are tested against |
| `tools/code-opencode-policy.mjs` | the OpenCode config `serve` merges in: subagents' ask rules, and a refusal that does not end the turn |
| `tools/code-confidential.mjs`, `agent/` | the confidential-model proxy, and the attestation and receipt verification it uses (TrustedRouter's gateway, Tinfoil) |
| `tools/code-attachments.mjs`, `spaces/public/codeAttachments.js` | attachments saved on the computer for the agent to read |
| `tools/opencode-config.mjs`, `tools/opencode-plugins/`, `tools/opencode-commands/` | writing an OpenCode config for TrustedRouter's models, and the project-notes plugin |
| `spaces/public/downloads/witbitz-code.mjs` | the built single file (a test fails if it is stale) |
| `relay/relay.mjs` | the relay — a Cloudflare Worker + Durable Object that forwards frames between the sockets on a channel |
| `packages/witbitz-code-py/` | the Python implementation, tested against the JavaScript one |
| `docs/opencode-relay.md`, `docs/code-auto-mode.md`, `docs/code-attachments.md` | the design: the relay, Auto mode, attachments |

Some comments and the design doc refer to parts of the Spaces app that are not in this repository (for example the Code
page itself, `opencodeApp.js`).

## Tests

```bash
npm ci
npm test              # codec, connector, pairing, page transport, QR, Auto mode, subagent policy, confidential proxy, attachments, build freshness
npm run test:relay    # the relay in the Workers runtime (miniflare)
npm run test:python   # the Python package, including frames, flows and Auto decisions checked against the JavaScript modules
```

(`test:python` needs `pip install -e "packages/witbitz-code-py[test]"` first.)

## Security

Please report vulnerabilities privately to **security@witbitz.chat**.

## License

MIT — see [LICENSE](LICENSE). Third-party code: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
