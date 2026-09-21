#!/usr/bin/env bash
# build-package.sh — produce a deployment zip whose contents EXACTLY match
# the oracle/manifest hashed set plus runtime assets.
#
# THE RULE that makes networks consistent: every file the manifest lists
# must be inside the zip, and no hashable (.js/.json/.ts) file may ship
# that the manifest does not list. The oracle live-scans the runtime dir
# at boot — any hashable extra or missing file forks the network
# fingerprint. `archive/` IS hashed (it is not in the oracle's exclude
# list) — do NOT exclude it from the package.
#
# Usage: scripts/build-package.sh [out.zip]
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
OUT="${1:-/tmp/yakmesh-package.zip}"
STAGE=$(mktemp -d /tmp/yakmesh-pkg.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

echo "== staging committed tree"
git archive HEAD | tar -x -C "$STAGE"

echo "== adding ignored runtime files"
cp yakmesh.config.js "$STAGE/"
cp -r models "$STAGE/" 2>/dev/null || true
cp -r public/c2c "$STAGE/" 2>/dev/null || true
cp -r templates "$STAGE/" 2>/dev/null || true

echo "== generating manifest over the shipped tree"
node deploy-packages/generate-manifest.js --root "$STAGE" | tail -3

echo "== zipping (excludes are non-runtime/non-hashed dirs only)"
cd "$STAGE"
rm -f "$OUT"
zip -qr "$OUT" . \
  -x 'node_modules/*' '.git*' 'CONFIDENTIAL/*' 'deploy-packages/*' \
     'docs/*' 'website/*' 'copilot-memories/*' 'data/*' 'downloads/*'
# manifest.json is build metadata that must ride the package
zip -q "$OUT" data/manifest.json

echo "== verifying every manifest file ships in the zip"
node - "$STAGE" "$OUT" <<'EOF'
const fs = require('fs');
const { execSync } = require('child_process');
const [stage, zip] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(`${stage}/data/manifest.json`, 'utf8'));
const shipped = new Set(
  execSync(`unzip -Z1 ${zip}`).toString().trim().split('\n')
);
const missing = manifest.files.filter(f => !shipped.has(f));
if (missing.length) {
  console.error(`PACKAGE INCONSISTENT: ${missing.length} manifest files missing from zip:`);
  missing.slice(0, 10).forEach(f => console.error('  -', f));
  process.exit(1);
}
console.log(`OK: all ${manifest.files.length} manifest files present in zip`);
EOF

sha256sum "$OUT" | awk '{print "== package: " $1 "  " $2}'
