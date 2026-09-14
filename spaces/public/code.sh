#!/usr/bin/env bash
# witbitz-code installer — the one line the Code guide gives (the owner: the curl -o download "is really complicated
# for a non technical user"):
#
#   curl -fsSL https://app.witbitz.chat/code.sh | bash
#   curl -fsSL https://app.witbitz.chat/code.sh | bash -s uninstall      (the same download, then `uninstall`)
#
# It checks for Node.js 22+, downloads witbitz-code.mjs into your home folder, checks the file against the app's asset
# manifest (the list of file hashes the app's signed build certificate covers — docs: witbitz.chat/docs/verify), and
# starts `node witbitz-code.mjs setup`, which asks before it installs or changes anything. Read it first if you like:
# this file is all it runs. Nothing is installed system-wide and nothing needs sudo.
set -euo pipefail

APP="${WITBITZ_APP:-https://app.witbitz.chat}"
DEST="${WITBITZ_CODE_FILE:-$HOME/witbitz-code.mjs}"

say() { printf '%s\n' "$*" >&2; }

# Everything runs from main(), called on the last line: if the download of this script is cut off mid-way, bash reads an
# unfinished function and runs nothing.
main() {
  # which command to hand over to: setup (the default) or uninstall — anything else goes to setup as its arguments
  local cmd=setup
  case "${1:-}" in setup|uninstall) cmd="$1"; shift ;; esac
  if ! command -v node >/dev/null 2>&1; then
    say "witbitz-code needs Node.js 22 or newer, and this computer does not have Node.js."
    say "Install it from https://nodejs.org (the LTS download), open a new terminal window, and paste the same line again."
    exit 1
  fi
  if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)'; then
    say "witbitz-code needs Node.js 22 or newer; this computer has $(node --version)."
    say "Install the current LTS from https://nodejs.org, open a new terminal window, and paste the same line again."
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then say "curl is missing — install curl and try again."; exit 1; fi

  tmp="$(mktemp "${DEST}.download.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  say "Downloading witbitz-code from ${APP} …"
  if ! curl -fsSL "${APP}/downloads/witbitz-code.mjs" -o "$tmp"; then
    say "The download failed. Check your internet connection and paste the line again."
    exit 1
  fi

  # The manifest's hash for this file, and the file's own hash — both computed with Node (shasum/sha256sum differ by system).
  want="$(curl -fsSL "${APP}/assets-manifest.json" | node -e 'let s = ""; process.stdin.on("data", (c) => { s += c }).on("end", () => { try { process.stdout.write(String(JSON.parse(s).files["downloads/witbitz-code.mjs"] || "")) } catch { } })' || true)"
  got="$(node -e 'process.stdout.write(require("crypto").createHash("sha256").update(require("fs").readFileSync(process.argv[1])).digest("hex"))' "$tmp")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    say "The downloaded file does not match the app's manifest, so it was not used."
    say "This can happen for a minute right after an update — wait a minute and paste the line again."
    exit 1
  fi
  chmod 644 "$tmp"
  mv -f "$tmp" "$DEST"
  trap - EXIT
  say "✓ Downloaded witbitz-code and checked it against the app's manifest (sha256 ${got:0:16}…)"
  say "  Saved as ${DEST}"
  say ""

  # `curl … | bash` gives this script the download as its input, so setup's questions read the keyboard from /dev/tty.
  if { : </dev/tty; } 2>/dev/null; then
    exec node "$DEST" "$cmd" ${1+"$@"} </dev/tty
  fi
  say "Now run:  node \"${DEST}\" ${cmd}"
}

main ${1+"$@"}
