# Code ↔ your computer over a sealed WebSocket relay

**Status: BUILT and LIVE (2026-09-13)** — relay `code-relay.witbitz.chat` (78fc3070), codec + connector (eb34044a), page
transport + `computers` registry + pairing + single-file download (b77c4e84, 7e9be914), public page
[witbitz.chat/docs/opencode.md](https://witbitz.chat/docs/opencode.md). **Transition done:** the owner paired over the relay and
confirmed Code works; `SPACE_OPENCODE_ORIGINS` and its warnings are deleted — a deploy needs no variable. Python package
(5b) built, not published. Where the build differs from the design below, it says so inline (**as built**). Owner decisions, 2026-09-13: *"maybe we should connect to the server
through the witbitz platform and make the relay there"* → *"No tailscale"* → *"I think it should be a websocket"*.
Replaces the Tailscale transport the Code section ships today. Context: [`spaces/public/opencode.html`](../spaces/public/opencode.html)
+ `opencodeApp.js` (the section), `tools/opencode-pair.mjs` (pairing), `relay/relay.mjs` (the relay this reuses).

---

## 1. Why the current transport has to go

Today the Code page `fetch`es the owner's OpenCode server directly at its tailnet address
(`https://<machine>.<tailnet>.ts.net`). That works for exactly one person:

| Problem | Effect |
|---|---|
| The page CSP must name the server in `connect-src` | Only the owner's host is listed (`SPACE_OPENCODE_ORIGINS`, per deploy). Any other user's server is blocked — installing everything still ends in "Load failed". |
| The variable is per-deploy | A deploy that forgot it (20442c2b, 2026-09-13) took Code down for everyone; it looked like a Tailscale outage. |
| Opening it to all users | Would mean `connect-src https://*.ts.net` — and Tailscale **Funnel** makes `*.ts.net` hosts public, so a compromised page script could exfiltrate to an attacker's Funnel host *through* the egress lock. |
| The user must run Tailscale on every device | Plus `tailscale serve`, CORS flags, a server password on the network. |

## 2. The shape

```
 phone / desktop (Code page, app.witbitz.chat)            your computer
 ┌──────────────────────────┐                             ┌──────────────────────────────────┐
 │ opencodeApp.js           │                             │ opencode serve  (127.0.0.1:4096) │
 │   transport: relay       │                             │        ▲ plain HTTP + SSE, local │
 │   seal ▸ frames ◂ open   │                             │        │                         │
 └───────────┬──────────────┘                             │ opencode-connector.mjs           │
             │ wss (dial OUT)                             │   seal ▸ frames ◂ open           │
             ▼                                            └───────────┬──────────────────────┘
      ┌───────────────────────────────────────┐                       │ wss (dial OUT)
      │ code-relay.witbitz.chat  /c/<channel> │◂──────────────────────┘
      │ Cloudflare Durable Object, one per    │
      │ channel: forwards bytes it cannot read│
      └───────────────────────────────────────┘
```

- **Both ends dial out** to a first-party `wss://` origin. No inbound port, no Tailscale, no CORS, works on cellular.
- **OpenCode never leaves localhost.** Its password stays in `~/.opencode-server.env` and is used only by the connector.
- **The relay is content-blind:** every frame is sealed end-to-end with a key the relay never receives. It sees a
  pseudonymous channel id, IP addresses, timing and sizes — the same class of metadata the room store sees today.
- **The page CSP gains one first-party host, baked permanently** (`wss://code-relay.witbitz.chat`) and loses the
  per-deploy third-party one. The egress lock gets *tighter*: no host outside witbitz.

`relay/relay.mjs` already is this relay — built 2026-08-12 for the (parked) browse room: WebSocket hibernation,
broadcast-to-other-sockets, an unsealed `{t:'peers',n}` count. **It is not deployed any more**: its old address
on `workers.dev` answers Cloudflare `error code: 1042` (checked 2026-09-13). Phase 1
deploys it fresh on a first-party hostname with hardening (§6); the forwarding model is unchanged.

## 3. Keys, and how every device gets them

**One 32-byte secret `S` per (computer, account) pairing.** Minted by the pairing tool on the computer, stored there,
and published to the account in a sealed **computers registry** that every signed-in device reads.

### 3.1 The registry: a NEW sealed doc, not new fields

The account index room gains one `op:'state'` doc, **`computers`**, sealed with the index room key exactly like
`index`/`index2`:

```json
{ "v": 1,
  "computers": {
    "<computerId: 16 random bytes b64url>": {
      "name": "desk",                              // editable label; default = hostname
      "relay": "wss://code-relay.witbitz.chat",
      "secret": "<b64url(S)>",
      "pairedAt": 1789250000000,
      "mod": 1789250000000,                         // last-writer-wins PER ENTRY
      "removed": false                              // tombstone, so an unpair propagates instead of being re-added
    }
  },
  "at": 1789250000000 }
```

⚠ **Why a separate doc and not new fields in `index2.code`:** `normCodeSettings` keeps only the four known strings
(`base`, `pass`, `model`, `agent`). A device still running an older build would read `index2`, drop an unknown
`computers` field, and write it back on its next push — silently unpairing every computer. Older builds never read or
write a doc named `computers`, so it is immune, and it holds any number of entries (the owner: *"we will eventually need
more than one connection"*). `index2.code` keeps `model`/`agent` (and `base`/`pass` for direct mode, §3.3).

**Writes** follow the index rules that already protect contacts: read first, refuse unless the read was a definitive 200,
merge per entry by `mod` (a tombstone with a newer `mod` wins), write the whole doc, gzip-wrap above 24 KB. Writers: the
pairing tool (add, rotate, unpair) and the app (rename, remove a computer from Settings).

### 3.2 Derivation (WebCrypto, identical in the browser and Node ≥ 22)

```
channel = base64url( HKDF-SHA256(S, salt="witbitz-code-relay-v1", info="channel", 32 bytes) )   // 43 chars → /c/<channel>
kC2S    = HKDF-SHA256(S, salt="witbitz-code-relay-v1", info="client-to-computer", 32) → AES-256-GCM
kS2C    = HKDF-SHA256(S, salt="witbitz-code-relay-v1", info="computer-to-client", 32) → AES-256-GCM
```

Direction-separated keys mean a frame reflected back at its sender does not decrypt. The channel id reveals nothing about
`S`, the computer or the account.

**Rotation / unpair:** `--rotate` mints a new `S` for that entry (new channel; clients pick it up on their next sync);
`--unpair` tombstones the entry. Both are per computer, per account.

### 3.3 Direct mode (kept for development)

Owner decision: keep direct HTTP to a local server for development and tests only. It stays expressed as today —
`index2.code.base` = `http://127.0.0.1:4096` (or a dev URL), `pass` = the server password — and is hidden from users. The
page uses the registry when it has a computer, and direct mode only when `base` is set and the registry is empty.

## 4. Wire protocol

### 4.1 Frame

Every WebSocket text message the peers exchange (i.e. everything except the relay's own `peers` count):

```json
{ "v": 1, "s": "<sender id: 12 random bytes, b64url, new per socket>", "q": 42, "n": "<12-byte IV b64url>", "c": "<AES-GCM ciphertext b64url>" }
```

- **AAD** = `wbcr1|<v>|<s>|<q>` — the clear header is authenticated; tampering with `s`/`q` fails decryption.
- **Replay:** receivers keep the highest `q` per `s` and drop anything ≤ it. A new socket gets a new `s`.
- **Replay across restarts** (*as built*, after review): the window above lives in memory, so a request recorded earlier could be
  re-sent after the connector restarts. Each connector socket therefore announces a fresh nonce `k` inside its sealed
  `hello`, and every `req`/`sub`/`unsub`/`cancel` must carry the current one. A recording from before a restart or
  redial carries a nonce the connector no longer accepts (`409`, never forwarded). The page re-asks reads under a new
  nonce; mutations are never re-sent.
- A frame that fails to open is dropped silently (wrong channel collision, an old key after rotation, junk).

### 4.2 Plaintext messages (JSON inside `c`)

| from | `t` | fields | meaning |
|---|---|---|---|
| computer | `hello` | `ver`, `name`, `computerId`, `k` (nonce), `ts` | "I'm here" — on connect, on a `ping`, when the peer count rises, and every 20 s while a client is present. **`k` is a fresh random nonce per connector socket** (see Replay below) |
| client | `req` | `id` (random, ≤ 64 chars), `k` (the current nonce), `m` (method), `p` (path + query), `b` (JSON body, optional) | one OpenCode API call — refused with 409 when `k` is not the current nonce, 400 when `id` is longer than 64 |
| computer | `res` | `id`, `st` (status), `b` (body text), `part`/`of` when chunked | the response, possibly in parts |
| client | `sub` | `c` (client id), `k`, `p` (`/event?directory=…`) | start (or renew) this client's interest in that event stream; OpenCode scopes events by project directory. The stream is shared per path and closes when its LAST client leaves or expires (TTL 75 s; pages renew every 30 s) |
| computer | `evts` | `p` (the stream), `b` (JSON array of raw SSE `data` strings) | **as built:** events are BATCHED every ~120 ms — the relay allows 200 messages per 10 s per socket, and token deltas alone exceed that |
| client | `cancel` | `id`, `k` | abandon a pending `req` (the connector aborts its local fetch; `res 499`) |
| client | `ping` | — | **as built:** asks for a `hello` now (sent on connect and when the peer count rises) |
| client | `unsub` | `c`, `k`, `p` | this client stops watching `p` |
| computer | `progress` | `sessionID`, `label`, `phase` (waiting · answering · writing · checking · retrying · end), `attempt`, `tool`/`subject`/`chars` while writing, `ts` | what the confidential-model proxy is doing for a session (§13) — shown on the working line, never passed to OpenCode |

**Multiple devices at once** (phone + desktop): the relay broadcasts, so every client receives every `res` and `evt`.
Clients ignore `res` whose `id` they did not send; everyone applies `evt`, which is exactly the shared-live-session
behaviour the section has today over SSE.

### 4.3 Chunking

Cloudflare caps a WebSocket message at 1 MiB. Bodies over **192 KiB** (a sealed frame is ~4/3 of its plaintext) (long transcripts from `GET /session/:id/message`,
file parts in `POST …/message`) are split into `res`/`req` parts `{part:i, of:n}` and reassembled by id, with a total cap
of **32 MiB** per message and a 60 s reassembly timeout.

### 4.4 The API surface the connector will serve (allowlist)

Only what the section calls — enumerated from `opencodeApp.js`. Anything else → `res {st: 403}` without touching OpenCode.
OpenCode can run shell commands on the computer; a leaked `S` must not unlock more than the page itself can do.

```
GET    /experimental/session            (query: archived)        GET  /agent        GET /api/model
GET    /config/providers  GET /config    → ANSWERED THROUGH A PROJECTION (below), never passed through
GET    /session/:id/message                                       POST /session
POST   /session/:id/message             POST /session/:id/abort   POST /session/:id/permissions/:permID
PATCH  /session/:id                     DELETE /session/:id
GET    /path                            GET  /file                         (New session's folder picker)
GET    /permission                      POST /permission/:permID/reply     (pending asks, so a card survives a session
                                                                            switch or reload; a Deny with a message)
GET    /witbitz/attachment · GET /witbitz/output   → ANSWERED BY THE CONNECTOR, never forwarded: a saved attachment,
                                                   and a file a reply produced (docs/code-attachments.md §8)
GET    /event                           → never proxied as HTTP; `sub` starts the connector's own local SSE read
```

The `directory` query parameter passes through (sessions are project-scoped).

**Keys never leave the computer — the two projected answers** (found 2026-09-13, while testing a freshly set-up machine).
Measured on opencode 1.18: `GET /config` returns the provider options with every `{env:…}` RESOLVED — the owner's
TrustedRouter key came back in plain text — and `GET /config/providers` returns each connected provider's stored API key
in `key`. Until then the connector forwarded `/config` as-is, so each catalog load carried the key, sealed, to the page.
The connector now rebuilds both answers from an allowlist of fields (`codeRelay.js projectResponse`, mirrored by
`relay.project_response`): `/config` → `{model, small_model, provider: {id: {name, models: {id: {name}}}}}`;
`/config/providers` → `{providers: [{id, name, source, models: {id: {name, status, input}}}], default}`. A failed or
unparseable answer goes back as a plain error, never the raw body. The page builds its model menu from
`/config/providers` (what is CONNECTED — `/api/model` lists what OpenCode merely knows about: 61 dead OpenAI models on one
box, none of the logged-in providers on another). Against a connector that predates this (403) the page falls back to
`/api/model` and does NOT ask for `/config` through the relay. The chosen model is remembered per computer, on the device,
and is no longer an account-synced setting once a computer is paired.

**The folder picker** (added 2026-09-13, owner: "the default should be ~/"). New session opens a sheet at the
computer's home (`GET /path` → `home`) and creates the session with `POST /session?directory=<chosen>`. Browsing is
`GET /file?directory=<home>&path=<relative>` — always rooted at home, so the computer keeps ONE OpenCode project
instance for it instead of one per folder looked at, and OpenCode itself refuses to list above that root ("Path escapes
the location"). Folders of recent sessions are offered as one tap, which also covers anything outside home. `/file`
returns names only; `/file/content` stays off the list. Neither route raises the ceiling: a session the page can
already create may `read`/`list` without asking. A connector that predates these routes answers 403, and the page then
creates the session where the server decides and says to update witbitz-code.

### 4.5 Presence, reconnect, timeouts

- **Online** = the relay reports `peers ≥ 2` **and** a `hello` opened within the last 30 s. Otherwise the page shows
  *"Your computer is offline — start it with `bash tools/opencode-serve.sh`"* instead of "Load failed".
- **Reconnect:** exponential backoff 0.5 s → 15 s, reset on success; on `visibilitychange → visible` reconnect at once
  (iOS kills sockets of a backgrounded app). After reconnect the page re-sends `sub` and re-reads the open session.
- **Requests:** 30 s timeout (`POST …/message` exempt: it returns when the model finishes; the live view rides `evt`).
  GETs are retried once after a reconnect; mutating calls are never auto-retried.
- **Keep-alive:** the connector says `hello` every 20 s while a client is present; a page whose socket stays "open" with a
  peer but hears no hello for 50 s treats the path as dead and redials. Durable Object hibernation keeps idle channels ~free.

## 5. Components and file plan

| component | file | notes |
|---|---|---|
| Frame codec (shared) | `spaces/public/codeRelay.js` | HKDF, seal/open frames, replay window, chunk/reassemble. Pure WebCrypto → the same module runs in the page and in Node. Unit-tested in node. |
| Page transport | `spaces/public/opencodeApp.js` | `api()` and `watch()` go through a `transport` object: `direct` (today's fetch + SSE) or `relay` (socket). The rest of the section is unchanged. |
| Connector | `tools/opencode-connector.mjs` | Reads its pairings from `~/.witbitz/code/pairings.json` (0600): one entry per account → `{computerId, secret, opencodePort}`; one socket per entry; serves the allowlist against that entry's local OpenCode; forwards SSE as `evt` while any client is present (`peers ≥ 2`). The OpenCode password stays in `~/.opencode-server.env`. |
| Launcher | `tools/opencode-serve.sh` | Starts OpenCode (no `--cors`, no Tailscale) **and** the connector; `--pair` unchanged in spirit. |
| Pairing | `tools/opencode-pair.mjs` | QR ritual as today; **adds** an entry to the scanning account's `computers` registry (§3.1) instead of replacing `base`/`pass`; drops `tailscale serve` detection and the CSP check. |
| Registry sync | `spaces/public/store.js`, `roomSync.js` | Read-merge-write the `computers` doc beside `index2`; hand the list to Code (`codeView.js` → frame) like the settings are handed today. |
| Computer picker | `opencodeApp.js` | A computer row at the top of the drawer when there is more than one; sessions list per computer; Settings can rename or remove a computer. |
| Relay | `relay/relay.mjs`, `relay/wrangler.toml` | Custom domain + hardening (§6). |
| CSP | `spaces/tools/gen-space-csp.mjs` | Bake `wss://code-relay.witbitz.chat` into `connect-src`; delete `SPACE_OPENCODE_ORIGINS`, its warnings, and the CLAUDE.md / runbook notes added 2026-09-13. |

## 6. Relay changes

1. **First-party hostname** `code-relay.witbitz.chat` (Workers custom domain on the Cloudflare `witbitz.chat` zone).
   `relay.witbitz.chat` is taken by the OHTTP relay (`infra/ohttp-relay`). The browse room can keep the workers.dev name.
2. **Channel id** must match `^[A-Za-z0-9_-]{43}$` for the code relay path (`/c/…` today accepts 16–128).
3. **Socket cap** 16 per channel → a 17th gets `close(1013)`. Stops a stranger who guessed nothing but spams connects.
4. **Rate limit** per socket: 200 messages / 10 s, then `close(1008)`.
5. **Origin check:** a browser socket must carry `Origin` ∈ {`https://app.witbitz.chat`, `https://witbitz-spaces.pages.dev`,
   `https://spaces.witbitz.chat`, `https://preview.witbitz-spaces.pages.dev`}; a socket with **no** Origin (the Node
   connector) is allowed. Defense in depth only — the key is the real gate.
6. **Deploy prerequisite:** deploying needs a Workers-scoped Cloudflare token (a Pages-only token cannot deploy Workers).

## 7. Threat model

| who | sees | can do | cannot |
|---|---|---|---|
| Witbitz / Cloudflare (relay operator) | channel id, IPs, connect times, frame sizes and timing | drop or delay frames; count sockets | read or forge any request, response or event |
| A stranger without `S` | nothing unless they know the channel id; then ciphertext | occupy socket slots (capped), be rate-limited | read, inject (AEAD), replay (per-sender `q`) |
| A signed-in device of the account | everything the section shows | drive OpenCode within the allowlist | anything outside the allowlist |
| Someone who steals `S` (compromised device) | as above | as above, until rotation | survive `--rotate` |
| Other processes on the computer | OpenCode on 127.0.0.1 | call it if they have the local password | — (unchanged from today) |

Replay, as built (two review rounds): requests toward the computer — the direction that can run commands — are bound to
the connector's current nonce, which rotates on every connector socket and whenever a page sender leaves its replay
window; a recording from before any of those is refused. Two accepted limits: (1) toward the PAGE, a relay that forces
reconnects can re-deliver old *display* frames (stale events, an old `res` for an id nobody waits on); an old `hello` is
ignored by its timestamp. Nothing executes and nothing is revealed. (2) A nonce rotation fails a mutation that was already
in flight with a visible 409 (reads are re-asked) — it needs 64+ page reconnects, so it is rare.

Honest residuals: metadata (who is online, when, how much) is visible to the operator — the same property as the room
store. OpenCode's own power (shell, file edits) is inherent to the product; the permission prompts it raises still flow
to the page as `evt` and are answered with the existing `POST …/permissions/:id`.

## 8. Rollout

| phase | scope | done when |
|---|---|---|
| 0 | this doc | owner approves |
| 1 | relay: custom domain, channel regex, caps, rate limit, Origin check; `relay/test` with the Workers runtime (Miniflare) | hardening tests green; `wss://code-relay.witbitz.chat/health` live |
| 2 | `codeRelay.js` + `opencode-connector.mjs`; node tests against a local fake relay + a fake OpenCode (round-trip, chunking, replay, wrong key, allowlist, SSE forwarding, two clients) | tests green; connector drives the real local OpenCode through the live relay from a node client |
| 3 | page transport switch + presence UI; browser tests with the fake relay (send a prompt, stream deltas, permission ask, offline banner, reconnect after `visibilitychange`) | Code section suite green; owner confirms on iPhone over cellular with Tailscale off |
| 4 | `computers` registry (§3.1) + pairing writes it; computer picker when > 1; CSP bakes the relay host; remove `SPACE_OPENCODE_ORIGINS` + the Tailscale path and docs | a deploy without any env var serves a working Code section; two paired computers both reachable from one phone |
| 5 | **single-file download** (connector + pairing bundled into one `.mjs`, needs only Node ≥ 22); public docs page `witbitz.chat/docs/opencode.md` with every install step | a fresh machine goes from nothing to a working Code section by following the page |
| 5b | **Python install** (`pipx install witbitz-code`): a second implementation of the connector, frame codec and pairing, held to the JS one by shared test vectors (§4.1 frames, §3.2 derivation, the device-link reply) | the same fresh-machine walkthrough passes with Python only |

## 9. Decisions (owner, 2026-09-13)

1. **Hostname:** `code-relay.witbitz.chat`.
2. **Direct mode:** kept, for development and tests only (§3.3).
3. **Distribution:** a single-file download, or a Python install — phase 5 ships the single file (it reuses the exact
   codec the page runs); 5b adds the Python package against shared test vectors, so the two cannot drift.
4. **More than one computer:** needed eventually → the registry (§3.1) supports N from day one; the picker UI arrives
   when a second computer is paired (phase 4).

## 10. More than one account on one computer

Possible — the owner asked whether it is. **Each pairing is independent:** scanning the QR with a second account adds a
second entry to `~/.witbitz/code/pairings.json` and a second entry to *that* account's registry, with its own `S` and
channel. The connector opens one socket per pairing. Nothing in the relay or the crypto links the two accounts.

**The real question is isolation, and it depends on whose accounts they are:**

| case | setup | why |
|---|---|---|
| one person, two of their own accounts (work + personal) | both pairings → the **same** OpenCode server | OpenCode has no users: every paired account sees every session, the same files, the same shell. That is fine when it is all you. |
| two different people | one OpenCode **instance per account** — a separate port and a separate data directory per pairing (`opencodePort` in the pairing entry) | otherwise each person can read the other's sessions and run commands in the other's projects. For real separation, run the second instance as a different OS user. |

**As built:** the pairing tool does not ask — it pairs, and when another account already reaches the same OpenCode it says
so plainly (they share sessions, files and shell) and points to `--opencode-url` / `--port` for a separate instance.
`serve --port N` (and `opencode-serve.sh` with `PORT=N`, and `opencode-connector.mjs --port N`) serves ONLY the pairings
pointed at that OpenCode, so two instances never answer the same channel (which would double every streamed event). (Phase 2 must verify how OpenCode separates
its data per instance, e.g. an `XDG_DATA_HOME` per port, before this is offered.)

**What changes versus today:** `tools/rc-link.mjs` keeps ONE account in `~/.witbitz-rc.account.json` (the `/rc` tools
depend on that). Code pairings move to their own multi-entry file, so pairing a second account for Code no longer
"moves" the machine off the first — the current `pairPlan` switching behaviour is replaced by *add*.

## 11. Distribution decisions (owner, 2026-09-13)

1. **Picker:** a computer row at the top of the drawer, shown once there is more than one computer.
2. **Python package: `witbitz-code` on PyPI**, installed with `pipx install witbitz-code`, one command
   `witbitz-code` (`pair`, `serve`, `unpair`, `status`). Names checked free on 2026-09-13: `witbitz-code`, `witbitz`,
   `witbitz-connector`.
   - **PyPI, not a download from the site:** `pipx upgrade` delivers security fixes (a site download would sit stale
     on every machine); dependencies (`cryptography`, `websockets`) resolve on install; and PyPI **Trusted Publishing**
     from a public GitHub Actions workflow attaches build provenance, so anyone can check the package was built from the
     published source — the same verifiable-build posture as `/cert.json`.
   - **Also register `witbitz`** as an empty placeholder on PyPI, so nobody else can publish under the brand name.
   - Needs a public source repo for the package (Trusted Publishing builds from it) and a PyPI account for the org.
   - The single-file Node download (phase 5) stays, served from the site next to the docs page, for machines that
     already have Node.

## 12. Local fast path — deferred (owner, 2026-09-13: "Keep relay for now")

Every call rides the relay, even when the page and OpenCode share a machine or a LAN. Measured from the owner's machine:
**~140 ms** added per request round trip (four legs to the Cloudflare edge; ~89 ms for one HTTPS round trip to it), about
half that per streamed event batch — small next to model latency, and privacy is unchanged (the frames are sealed either
way). Considered and parked:

- **Same machine:** the connector also listens on `ws://127.0.0.1:<port>` with the same sealed protocol; the page tries it
  first and falls back to the relay; the CSP gains only a loopback origin. Cheap; caveats are Chrome's Local Network
  Access prompt and Safari's handling of `ws://127.0.0.1` from an HTTPS page.
- **Same LAN (a phone on home Wi-Fi):** an HTTPS page can only open `wss://`, and a LAN address has no public
  certificate — the workable design is a WebRTC data channel signalled over the relay. Substantially more work.

Revisit if the ~140 ms is felt in daily use (the same-machine path first) or if offline LAN use becomes a requirement.

## 13. Confidential models — enforced on the computer (built 2026-09-13)

Owner: "· confidential" in Code was only a label (OpenCode called TrustedRouter directly: no `min_privacy`, no receipt
check), and a confidential model that cannot see images should get them through Tinfoil, **paid with the user's own
Tinfoil key**. `tools/code-confidential.mjs` is a TrustedRouter proxy on `127.0.0.1:<OpenCode port + 100>`, started by the
connector (`opencode-serve.sh`) and by `witbitz-code serve`; OpenCode's TrustedRouter `baseURL` points at it
(`opencode-config.mjs --proxy-port` / `OPENCODE_CONFIG_CONTENT`, never writing the user's opencode.json).

- **Not confidential in the catalog** (`agent/modelCatalog.mjs` tiers) → passed through byte for byte.
- **Confidential** → the room's own checks, reused: gateway attestation (`gatewayAttest.mjs`) before sending; the body
  floor `provider.min_privacy=confidential` + forced streaming + receipt nonce; the answer's text streams live but tool
  calls / finish / usage / `[DONE]` are HELD until `inferenceReceipt.mjs` verifies the receipt for these exact bytes — a
  failure ends the step with an SSE error, so OpenCode runs no tool. Measured live: DeepSeek V4 Flash and Kimi K3 verify.
- **Images / documents for a text-only confidential model** → Tinfoil's attested enclaves (`tinfoilAttest.mjs` +
  `attestedTool.mjs` pinning + `tinfoilVision.mjs` / `tinfoilDocRead.mjs`), with `TINFOIL_API_KEY` from the env or
  `~/.opencode-server.env` (read per request; `witbitz-code tinfoil-key` stores it). Converted text is cached by content
  (OpenCode re-sends the conversation every step). No key / no attestation / rejected key ⇒ the turn is refused with a plain
  reason; the file is never sent elsewhere. Those models are declared `attachment: true` so OpenCode passes the image on.
- **The lapsed proof (2026-09-14, owner: "I sometimes get this").** TrustedRouter proves the model's enclave on a 900 s
  cycle, takes that proof when a call STARTS and signs the receipt when it ENDS — so any call still running when its proof
  expires fails `receipt_verification_window` (both logged cases: signed 2 s and 74 s past the end). It is the one reason
  asked again (`agent/attestedRetry.mjs`), with a fresh nonce and the whole check: (a) nothing had reached OpenCode →
  asked again unseen; an answer that starts within 90 s of the last proof's end is held back whole for that; (b) words
  already shown AND `verifyInferenceReceipt(…, { explainLapse: true })` says every other check held → asked again held
  back, and only the new answer's tool calls / finish / usage are passed on (its words would repeat the screen). No tool
  call of a refused answer ever reaches OpenCode; a second lapse, or any other fault, refuses for real.
- **Progress** (`onProgress` → connector → `{ t: 'progress', sessionID, label, phase, attempt, tool?, subject?, chars? }`
  → `codeProgress.js`): waiting for the first word, writing a tool call (name, the file it names, size — never contents),
  checking the receipt, asking again. Sent beside OpenCode, not through it: 1.18.30's AI SDK (`openai-compatible`
  `flush()`) emits a `tool-call` for EVERY tool call still open when a stream closes, so a tool call's start forwarded
  early would run a tool from a refused answer. OpenCode names the session on provider calls (`X-Session-Id`).
- Honest limits: text already streamed before a failing receipt stays visible (it is marked failed and never acted on,
  and after a lapse-only retry it stays as the answer's words); the Python connector has no proxy yet.
