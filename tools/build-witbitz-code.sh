#!/usr/bin/env bash
# Build the single-file witbitz-code download (docs/opencode-relay.md phase 5).
#
#   bash tools/build-witbitz-code.sh          → spaces/public/downloads/witbitz-code.mjs
#
# The output lives under spaces/public so it ships with the app and is covered by the signed build certificate
# (/cert.json frontend manifest): the connector a user downloads is verifiably the one built from this commit.
# tools/witbitz-code.test.mjs rebuilds it and fails when the committed file is stale.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-spaces/public/downloads/witbitz-code.mjs}"
mkdir -p "$(dirname "$OUT")"
# --preserve-symlinks: the same bytes wherever this runs. A clean clone or export whose node_modules is a symlink otherwise
# gets esbuild path comments through the link's real target (`// ../../../home/<user>/witbitz/node_modules/…`) — a
# different file, and the builder's home directory published in the download (found by tools/public-scrub.mjs, 09-15).
node_modules/.bin/esbuild tools/witbitz-code.mjs \
  --bundle --platform=node --format=esm --target=node22 \
  --define:process.env.WITBITZ_CODE_BUNDLED='"1"' \
  --banner:js='#!/usr/bin/env node
// witbitz-code — built from tools/witbitz-code.mjs (github.com/witbitzchat/witbitz-code). Run: node witbitz-code.mjs --help' \
  --legal-comments=none --log-level=warning \
  --preserve-symlinks \
  --outfile="$OUT"
chmod 644 "$OUT"
echo "built $OUT ($(wc -c < "$OUT") bytes)"
