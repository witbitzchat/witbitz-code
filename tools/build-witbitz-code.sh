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
node_modules/.bin/esbuild tools/witbitz-code.mjs \
  --bundle --platform=node --format=esm --target=node22 \
  --define:process.env.WITBITZ_CODE_BUNDLED='"1"' \
  --banner:js='#!/usr/bin/env node
// witbitz-code — built from tools/witbitz-code.mjs (github.com/witbitzchat/witbitz-code). Run: node witbitz-code.mjs --help' \
  --legal-comments=none --log-level=warning \
  --outfile="$OUT"
chmod 644 "$OUT"
echo "built $OUT ($(wc -c < "$OUT") bytes)"
