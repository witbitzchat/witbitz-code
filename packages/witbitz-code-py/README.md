# witbitz-code

Use the **Code** section of Witbitz Spaces, on any device you're signed in on, to reach
[OpenCode](https://opencode.ai) running on your computer. It's end-to-end encrypted, needs no open port, and doesn't need
Tailscale.

This is the Python build of the `witbitz-code` tool. It speaks the same wire protocol, uses the same pairing file and the
same account registry as the single-file Node download (`node witbitz-code.mjs`), so either one can pair a computer and
the other can serve or unpair it.

## Install

```sh
pipx install witbitz-code          # or: pip install witbitz-code
```

Python 3.10 or newer. Dependencies: `cryptography`, `websockets`, `httpx`, `segno`.

You also need OpenCode itself: `npm install -g opencode-ai` or `curl -fsSL https://opencode.ai/install | bash`.

## Use

```sh
witbitz-code pair                 # shows a QR code: scan it in Spaces → Settings → Back up & recovery → Add a device
witbitz-code serve                # starts OpenCode on 127.0.0.1:4096 (unless it is running) and the connector
```

Then open Code in Spaces. Leave `serve` running (Ctrl-C stops it).

| command | what it does |
|---|---|
| `pair [--name <name>] [--port <n> \| --opencode-url <url>]` | Show the QR code. The account that scans it gets this computer. `--name` sets the label your devices show (default: the hostname). |
| `serve [--port <n>] [--no-opencode]` | Start OpenCode on `127.0.0.1:<n>` (default 4096) if nothing is listening there, then connect the pairings whose OpenCode is on that port. One OpenCode per port, one `serve` per OpenCode. |
| `status` | List this computer's pairings: name, account, OpenCode address and relay. Secrets are never printed. |
| `rotate [--account <email>]` | Replace the pairing secret(s) without scanning again, then restart `serve`. Devices pick up the new secret on their next sync. |
| `unpair [--account <email>]` | Remove this computer from an account. Every device drops it on its next sync. |
| `version`, `--help` | |

`pair`, `rotate` and `unpair` also accept `--dry-run`.

**More than one account.** Each account that scans the QR code gets its own pairing, with its own secret and relay
channel. OpenCode has no users, so every paired account reaches the same sessions, files and shell. That's fine when
all the accounts are yours. If a second account belongs to **another person**, run a separate OpenCode for them
(another port, ideally another OS user) and pair that account with `--port`.

## How it works

```
 phone / desktop (Code page)                               this computer
 seal ▸ frames ◂ open  ── wss ─▶ code-relay.witbitz.chat ◀─ wss ──  witbitz-code serve ──▶ opencode (127.0.0.1)
```

- **Both ends dial out** to `wss://code-relay.witbitz.chat`. Nothing listens on your network, and OpenCode never leaves
  `127.0.0.1`.
- **Pairing** uses a device link: the QR code holds only an ephemeral public key. Your signed-in device seals the account
  pointer to that key. The computer then mints a random 32-byte **secret** for this pairing and does two things with it:
  - stores it in `~/.witbitz/code/pairings.json` (mode 0600);
  - publishes it into the account's sealed `computers` registry, which every signed-in device reads.
- **Keys:** the relay channel id and two direction keys (page→computer and computer→page, AES-256-GCM) are derived from
  the secret with HKDF-SHA256. A frame reflected back at its sender doesn't decrypt.
- **Every frame is sealed.** The relay forwards ciphertext it can't read, and the clear header (sender id, sequence
  number) is authenticated. Receivers drop replays. Large bodies are split into parts below the relay's message size cap.
- **Replays across restarts:** each time the connector's socket opens, it announces a fresh random nonce inside its
  sealed hello. Every request and subscription must carry that nonce, so a request recorded before a restart or
  reconnect is refused (409) and never reaches OpenCode.
- **The connector only forwards what the Code page itself calls:** list and read sessions, send a message, abort, answer
  a permission prompt, rename and delete. Every other request gets a 403 without touching OpenCode. OpenCode can run shell
  commands, so a leaked secret must not unlock more than the page can do. The live event stream is forwarded only while
  a device is watching.
- **The OpenCode password** lives in `~/.opencode-server.env` (created 0600 on first pair). The connector adds it to local
  calls, and it never leaves the computer.

**What is encrypted, and what isn't.** Requests, responses and events travel end to end. The relay operator sees a
pseudonymous channel id, IP addresses, connection times, and frame sizes and timing. That's the same class of metadata
the Spaces room store sees. Anyone holding a pairing secret can drive OpenCode within the allowlist until you run
`rotate`.

Design: `docs/opencode-relay.md` in the Witbitz repository.

## Files and environment

| | default | override |
|---|---|---|
| pairings | `~/.witbitz/code/pairings.json` | `WITBITZ_CODE_PAIRINGS` |
| OpenCode password | `~/.opencode-server.env` (`OPENCODE_SERVER_PASSWORD=`) | `OPENCODE_ENV_FILE` |
| pairing QR, as SVG | `~/.witbitz-rc.link.svg` | |
| account API | `https://api.witbitz.chat/v1/space` | `RC_BASE`, `RC_ORIGIN` |
| device-link origins | `https://spaces.witbitz.chat,https://witbitz-spaces.pages.dev` | `RC_LINK_ORIGIN` |

## Development

```sh
pip install -e '.[test]'
python -m pytest tests -q
```

The tests hold this package to the JavaScript reference implementation. They run the modules in `spaces/public/` and
`tools/` under `node` (22 or newer), and they cover:

- the pinned HKDF vectors;
- frames sealed on either side opening on the other;
- chunking through surrogate pairs;
- the device-link reply and the backup keys;
- the registry merge rules, compared byte for byte;
- the pairing file in both directions;
- the gzip wrap of account docs;
- a connector of each language driven by a client of the other, through a local fake relay and a fake OpenCode.

Without the repository checkout (`WITBITZ_REPO`) or `node`, the cross-implementation tests are skipped.
