# Code attachments — staged on the computer, read by the agent

**Status: BUILT (2026-09-13)** — connector `1f6ad6b6` (Node + Python twin), page `ad539f5b`. Owner decisions: Tinfoil text
copies for ALL models, a Download button, 30-day prune + delete with the session. As built, the permission rule is per SESSION
(`<root>/<session>/*`, security review) and a turn for a session OpenCode does not have saves nothing; all saved files are
capped at 2 GB. Owner: "What does Claude Code do with attachments?" → do it that way.
Touches the connector (`tools/opencode-connector.mjs`, the Python twin), `tools/code-confidential.mjs`'s Tinfoil reader,
`tools/opencode-config.mjs`, and the page (`opencodeApp.js`). Additive; the confidential proxy keeps its job.

## 1. Today (measured on opencode 1.18.30, 2026-09-13)

| Attachment | What happens |
|---|---|
| Image | Works: a vision model sees it; a confidential text-only model gets Tinfoil's description (the proxy). |
| PDF | TrustedRouter answers 502 for a PDF file part, so the page extracts the text in the browser and sends that. The file never leaves the phone → no preview after sending. A confidential model is declared `text,image`, so OpenCode strips a PDF before the proxy could read it ("this model doesn't support PDF file input"). |
| Excel, Word, other | **Broken for every model.** OpenCode refuses the part before any request: `'file part media type …spreadsheetml.sheet' functionality not supported`. |

Tinfoil's attested document reader (`/v1/convert/file`) reads them all: the owner's 2-page PDF in 8 s, an Excel sheet as a
table in 4 s, a Word memo in 3 s.

## 2. What Claude Code does

Every attachment is saved to disk and the agent gets the path: `~/.claude/uploads/<session>/<id>-<name>`, mode 600,
**outside** the working directory. Its Read tool opens images and PDFs; anything else is read with the shell (ffmpeg,
python, pandoc). Nothing is converted up front and nothing is refused at the door. (`/rc` rooms stage inside the project
instead, `<cwd>/.rc-attachments/`, pruned after 7 days.)

## 3. The design

**Staging.** On `POST /session/:id/message` the connector (which already forwards it) writes every `data:` file part to
`~/.witbitz/code/attachments/<sessionID>/<sha8>-<safe name>` (folder 700, files 600, name sanitized, per-file and
per-session size caps) and replaces the part with a text part the model reads:
`Attached: budget.xlsx (6 KB) at /home/…/attachments/ses_…/3f9a1c2e-budget.xlsx — text copy: …budget.xlsx.md`.
Image parts also stay inline for models that can see images (that already works).

**Reading.** Beside each document the connector writes a text copy (`.md`) made by Tinfoil's attested reader with the
user's `TINFOIL_API_KEY` (the proxy's existing `makeTinfoilReader`). No key → no copy, and the agent falls back to the
shell like Claude Code (which asks in Manual mode). The copy is made once per file, not per turn.

**Permission.** Reading outside the project asks `external_directory` (pattern `<file's folder>/*`). Measured: a session
rule `{permission: 'external_directory', pattern: '~/.witbitz/code/attachments/*' (absolute), action: 'allow'}` removes
that ask, and a file elsewhere in home still asks. New sessions get it in `ocPermissionRuleset`; existing sessions → see §5.

**Preview on every device.** The connector serves a staged file itself on a route it owns — `GET
/witbitz/attachments/<sessionID>/<file>` — answered from the folder, never forwarded to OpenCode. The page turns the
`Attached:` line into a chip: page 1 for a PDF, the picture for an image, the name for anything else.

**Page.** When the connector's hello carries `caps: ['attachments']`, the page sends files as they are (no in-browser PDF
extraction). Against an older connector it keeps today's behaviour.

**Retention.** A session's folder is deleted when the session is (`DELETE /session/:id` passes through the connector);
folders untouched for 30 days are pruned at start-up.

**Python twin.** Same staging, rule, preview route and line format, held by shared vectors. It has no attested Tinfoil
client yet, so its v1 makes no text copies (the agent uses the shell).

## 4. Security

A relay secret could already send files in a message; what is new is that they land on disk — only inside the
attachments folder, under caps, never executed, and served back only from that folder. The rule allows reading there,
nothing else: edits and shell still ask. Files go to Tinfoil only when a key is set and Tinfoil's attestation verifies.

## 5. Measure before building

1. Does a config-level `external_directory` allow (opencode.json) apply to sessions created with our own ruleset? If not,
   the connector answers those asks itself when the path is inside the folder (the Auto loop already answers asks).
2. The `Attached:` line: do DeepSeek V4 Flash and Kimi K3 read the `.md` copy unprompted?
3. Tinfoil's limits on a large workbook, and how long the copy takes.

## 6. Phases

1. Staging + `Attached:` line + permission + retention (JS connector), with tests against a fake OpenCode.
2. Tinfoil text copies.
3. Preview route + page chips + `caps` switch (in-browser PDF extraction becomes the fallback).
4. Python twin.

## 7. Owner decisions

1. Retention: 30 days (proposed), or delete-with-session only?
2. Text copies through Tinfoil for **regular** models too (more private than TrustedRouter; costs Tinfoil credits — on
   this computer that is the shared production key), or only for confidential models?

## 8. The other direction — files a reply PRODUCED, previewed under it (built 2026-09-14)

The owner, after an agent fixed a PDF and, asked to "upload it here", answered that a PDF cannot be shown in the chat:
*"I think the user should automatically see a preview"*. Its answer had named the file's full path all along.

**Which files** (`spaces/public/codeOutputs.js`, pure, shared cases in `spaces/test/codeOutputs.vectors.json`): a file the
reply WROTE or EDITED (completed write/edit tools), or one its answer NAMES (a `code span`, a full path under the
session's folder — matched from the folder itself, so "תיקייה 1" is not cut at its space — or a bare token). Never one it only
read, never a path in the user's prompt, only inside the session's folder, never a secret-looking name, at most 6.
Kinds: PDF (page 1), picture, table/text (first lines) preview; office files, archives, media → a chip; code → nothing.

**Route** — connector-owned, never forwarded: `GET /witbitz/output?session=&path=[&stat=1]` (`tools/code-outputs.mjs`,
Python `outputs.py`). The folder is the one OpenCode reports for the session (`GET /session/:id`), never one the page
names. By name first (absolute, one line, inside, kind, not secret — so it cannot probe what exists elsewhere), then by
disk (real path still inside, still not secret, a regular file), then size (20 MB, one relay message; `stat` answers
without the bytes). Each answer is logged in `~/.witbitz/code/output-log.jsonl` as a digest of the path. The hello carries
`caps: [..., 'outputs']`; without it (a direct server, an older connector) the page draws no cards.

**Page**: cards under the answer once the reply has finished. The latest reply's files are fetched at once, older ones
when their card scrolls into view; a PDF's page is rendered once into a picture and kept; a turn ending in that session
drops the cache. A file whose mtime is past the reply's end says "changed since this reply"; a gone one says so. Tap →
the sheet, large, with Download (share on a phone). No copies are kept: the file is read where it is.

**What it grants**: the agent reads these files without asking; this carries one to its owner's phone, sealed end to end.
