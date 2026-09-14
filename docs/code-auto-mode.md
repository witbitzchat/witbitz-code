# Code · Auto mode — a classifier for OpenCode's permission asks

**Status: phases 1–4 BUILT (2026-09-13) — core, connector loop, page, and the Python twin
(`packages/witbitz-code-py`: `auto.py`, `auto_runner.py`). Both connectors hold to the shared vectors, and a node parity test
runs thousands of generated inputs through both. Phase 5 (a sealed ledger) is later.** Owner: *"We need this auto mode because now it is asking too much but
removing these asks is too dangerous. So let's write the classifier."* Decisions taken with the owner:

| question | decision |
|---|---|
| where it runs | **on the computer, in the connector** — asks raised while every phone is closed are still decided |
| which model judges | **the session's own model**, through OpenCode (no new key, no new provider) |
| where verdicts go | **a local log first** (`~/.witbitz/code/auto-log.jsonl`); a sealed room ledger is a later step |

There is **no ledger on the Code path** (`opencodeApp.js` header: "NO ROOM IS INVOLVED"). The `/rc` path has one — its Auto
verdicts are sealed as signed turns (`tools/rc-verdict-ledger.mjs`). This design keeps that as the model for phase 4.

## 1. What changes for the person

- A session is switched to **Auto** from the composer's mode chip — **Manual · Accept edits · Plan · Auto**, in Claude
  Code's order, or Shift+Tab in the message box (per session, remembered on the computer). The other modes turn it off.
  Accept edits is not this classifier: it is OpenCode's own permission rules on the session (`spaces/public/codeModes.js`) —
  edits pass, protected files (.env, keys, .git/) and every other kind of ask still come to you.
- In Auto, every permission ask OpenCode raises goes through the classifier first. It **allows** routine work, **denies**
  what must not run (telling the agent why, so it tries something safer), and **leaves the rest for you** — the approval
  card on the phone, exactly as today. Nothing is ever granted `always`.
- The transcript shows a short 🛡 line for each automatic decision ("Auto allowed · bash · npm test"; a refusal in red,
  with its reason), so nothing happens silently.
- An ask in an Auto session waits ~2.5 s on the page for its verdict before the card appears, so what Auto settles at once
  never flashes up. A card that does appear says "Auto is checking…" or "Auto left this for you — <why>", and the person
  can always answer first.
- Off (the default): unchanged — every ask is a card.

## 2. The flow (connector, per pairing)

```
permission asked (GET /permission?directory=D, polled ~1 s for each directory with an Auto session)
  │  not an Auto session → ignore (the phone card handles it)
  ▼
① deterministic HARD DENY   catastrophic, never context-dependent (rm -rf / ~ $HOME, mkfs, dd to a device, fork bomb…)
  │                           → reply reject + reason
  ▼
② deterministic FAST ALLOW  no model call: read-only shell (ls, pwd, git status/log/diff/show, grep/rg/find without
  │                           -exec/-delete…) whose every argument stays in the project — no $VAR, ~, .., absolute path
  │                           outside it, or sensitive file — and no writing option (sort -o, uniq IN OUT, tree -o,
  │                           date -s, file -C, git grep -O); and edits INSIDE the session's project that touch no
  │                           sensitive path (.env*, .git/, *.pem/*.key, id_*, secrets*)
  ▼
③ REVIEWER                  the session's model, in a throw-away session whose rules DENY every tool; system prompt =
  │                           the policy (§3); input = the request + the last user messages (bounded) + the project dir
  ▼
   verdict {decision: allow|deny|ask, severity 0-100, rule, reason}
     allow (severity < 70) → reply once            deny → reply reject + reason
     ask / allow ≥ 70 / unparseable / timeout / any error → LEAVE IT for the human (fail-safe = ask, never allow)
```

The reviewer session is deleted after each decision. Its title carries a marker so the page never lists it.

## 3. The policy (ours — structured like Claude Code's auto-mode rules, not copied from it)

- **allow**: work that plainly serves the user's latest request inside the project — builds, tests, linters, formatters,
  package installs from the project's own manifest, local git that does not rewrite published history.
- **soft deny** (deny unless the user's recent messages clearly asked for exactly this): network uploads or fetches to
  hosts the task does not need, `curl … | sh`, deleting outside build/cache dirs, `git push` (esp. `--force`), history
  rewrites, deploy/publish/release commands, touching credentials or secret stores, changing system config, `sudo`,
  anything outside the project directory, long-running servers bound beyond localhost.
- **hard deny** (always): data exfiltration (sending code, secrets or env to an outside destination), destroying the home
  directory or the filesystem, disabling security controls.
- **environment**: the session's project directory is the trust boundary; per-computer additions later
  (`~/.witbitz/code/auto-policy.json`: trusted domains, protected paths).
- **the agent's scratch directory** (2026-09-14): `/tmp/opencode` is allowed without a model (`fast:agent-scratch`) — an
  `external_directory` ask whose patterns and `metadata.filepath`/`parentDir` all lie inside it, or an edit/write whose
  precise targets do; sensitive names (`.ssh/`, keys, `.env`, secret/credential) still go to the reviewer. Measured: an
  agent reading scanned PDFs rendered pages there with `pdftoppm` and opened them one by one — 22 identical asks, which
  the reviewer answered allow 20 times and "ask" twice, telling the person "a write" about a read. The runner acts on the
  rule only when the disk agrees (`scratchOnDisk`): the directory is a real one this user owns, and no target resolves
  through a link outside it (a dangling link counts as outside). The rest of `/tmp` is still the reviewer's.
- **what the reviewer sees**: besides the command or targets, the TOOL that raised the ask (found by its `callID` in the
  owner's transcript — a subagent's call is not there, so no line) and the ask's own `file` — an `external_directory` ask
  alone does not say whether the agent reads or writes.

## 4. Records

Each automatic decision appends one line to `~/.witbitz/code/auto-log.jsonl`: time, session, permission type, decision,
severity, rule, stage (`hard-deny` / `fast-allow` / `reviewer`), model, duration, and a **sha256 digest** of the request —
never the command text or file content. The connector also sends the verdict to open pages as a sealed message (`autoverdict`)
for the 🛡 line.

## 5. Wire additions (relay)

- page → computer: `{ t:'auto', k, sid, dir, on }` (nonce-checked like every request) — switch a session.
- computer → page: `hello` gains `caps:['auto']` and `auto:[sid…]`; `{ t:'autoverdict', id, sessionID, permission, detail,
  action, severity, rule, reason, stage, answered, ts }` after each automatic decision (`detail` = the command or first
  pattern, ≤300 chars — for the person's own page, sealed like the ask itself; never in the log). A connector without
  `auto` in caps → the page hides the switch.

## 6. Phases

1. **Pure module** `tools/code-auto.mjs` (hard deny, fast allow, prompt, verdict parsing, log record) + shared test vectors.
2. **Connector** loop: Auto state file, polling, reviewer session, replies, log, `autoverdict`; tests against a fake OpenCode.
3. **Page**: the Auto switch in the composer and the 🛡 lines.
4. **Python twin** (`packages/witbitz-code-py`) held to the same vectors; the single-file download rebuilt.
5. Later: verdicts sealed to a room ledger (the `/rc` model).
