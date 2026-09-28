#!/usr/bin/env bash
# build-c2c-bundle.sh — build a complete yakmesh-node + c2c dist for a
# remote node, following the yakmesh-attest-dist-* convention on the
# share: a FULL tree (node_modules included — koffi and onnxruntime-node
# ship all-platform binaries, so the Linux-installed tree is portable)
# plus the Windows keystore/pq-bridge binaries and the canonical
# START-YAKMESH launcher contract.
#
# Layout:
#   <dist>/yakmesh-node/   — complete node runtime (supervisor, bridge,
#                            keystore, bats) — oracle-hashed config intact
#   <dist>/c2c/            — server + shared + client/dist + package files
#                            (NO node_modules — better-sqlite3/bcrypt are
#                             real natives, npm install runs on target;
#                             NO model weights — 15G ONNX payload lives in
#                             c2c/server/npu/models/, ship separately with
#                             --models)
#   <dist>/START-YAKMESH.BAT — dismounts stale processes, remounts
#                            key-share + pq-bridge, starts both windows
#   <dist>/START-NODE.SH   — Linux equivalent
#
# c2c imports ../../yakmesh-node/{server/darbar,security/prahari}.js at
# runtime — the sibling layout is mandatory, do not flatten it.
#
# Usage:  ./deploy-packages/build-c2c-bundle.sh OUT_DIR [--models]
#   e.g.  ./deploy-packages/build-c2c-bundle.sh /mnt/lan-share/yakmesh-c2c-dist
set -euo pipefail

NODE_SRC="$(cd "$(dirname "$0")/.." && pwd)"          # yakmesh-node/
C2C_SRC="$(cd "$NODE_SRC/../c2c" && pwd)"            # sibling c2c/
OUT="${1:?usage: build-c2c-bundle.sh OUT_DIR [--models]}"
WITH_MODELS=0
[ "${2:-}" = "--models" ] && WITH_MODELS=1

STAGE="$(mktemp -d /tmp/c2c-dist.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

echo "[dist] staging yakmesh-node+c2c → $OUT"
mkdir -p "$STAGE/yakmesh-node" "$STAGE/c2c"

# ── yakmesh-node: the complete attest-dist tree ───────────────────────────
# Same content class as yakmesh-attest-dist-*: all runtime source, config
# (byte-identical — oracle-hashed), node_modules (portable all-platform
# binaries), keystore + pq-bridge binaries for Windows AND Linux, bats/vbs.
rsync -a \
  --exclude 'node_modules/.cache' \
  --exclude '.git' \
  --exclude '.env' \
  --exclude '.env.*' \
  --exclude '/data/' \
  --exclude '/data.windows-side/' \
  --exclude '/server/data/' \
  --exclude 'logs/' \
  --exclude 'CONFIDENTIAL/' \
  --exclude 'copilot-memories/' \
  --exclude 'TrainingBooks/' \
  --exclude 'yakbot/' \
  --exclude 'archive/' \
  --exclude 'coverage/' \
  --exclude 'deploy-packages/' \
  --exclude 'tests/' \
  --exclude 'test-nodes/' \
  --exclude '__tests__/' \
  --exclude 'handoff.md' \
  --exclude 'memory-bank/' \
  --exclude '*.tgz' \
  --exclude '*.log' \
  --exclude '/file.txt' \
  --exclude '/api_response.txt' \
  --exclude '/test-*.mjs' \
  --exclude '/test-*.js' \
  --exclude '/php-timing-test.php' \
  --exclude '/annex-probe.mjs' \
  "$NODE_SRC/" "$STAGE/yakmesh-node/"

# node identity must bootstrap fresh on the target — never ship ours.
# EXCEPTION: data/manifest.json is the network-wide codebase attestation
# (same buildNonce on every node — not secret). Without it the target
# derives a DIFFERENT network identity and cannot peer (JHILKE warn).
rm -rf "$STAGE/yakmesh-node/server/data" "$STAGE/yakmesh-node/data" \
  "$STAGE/yakmesh-node/data.windows-side"
mkdir -p "$STAGE/yakmesh-node/data"
cp -a "$NODE_SRC/data/manifest.json" "$STAGE/yakmesh-node/data/manifest.json"

# ── NPU payload (Windows XDNA): bridge exe + shim DLLs + kernel assets ──
# pq-bridge spawns yakos-npu-bridge.exe from its own dir; that exe links
# yak_xrt_shim.dll + xrt_coreutil.dll and resolves kernels/models from
# exe-adjacent npu-assets/ + npu-models/. superkitty is same Hawk Point NPU.
NPU_EMBED=/home/abl/YakForge-build/rust-embed
NPU_WIN_EXE="$NPU_EMBED/target/x86_64-pc-windows-gnu/release/yakos-npu-bridge.exe"
SHIM=/home/abl/Desktop/YakOS/npu-shim-win
if [ -f "$NPU_WIN_EXE" ]; then
  cp -a "$NPU_WIN_EXE" "$STAGE/yakmesh-node/yakos-npu-bridge.exe"
  cp -a "$SHIM/yak_xrt_shim.dll" "$SHIM/xrt_coreutil.dll" "$STAGE/yakmesh-node/"
  mkdir -p "$STAGE/yakmesh-node/npu-assets"
  rsync -a --exclude='*.partial' /home/abl/.npu/cache/fused_xclbin/ \
      "$STAGE/yakmesh-node/npu-assets/fused_xclbin/"
  cp -a /home/abl/mlir-aie/aie_kernels/aie2/ntt_pq.cc "$STAGE/yakmesh-node/npu-assets/" 2>/dev/null || true
  rsync -a /home/abl/Desktop/YakOS/yakos-dna-spiral/models/ \
      "$STAGE/yakmesh-node/npu-models/"
  echo "  + NPU payload: bridge exe, XRT shim DLLs, fused kernels, models"
else
  echo "  ! no windows npu-bridge build — NPU lane will report absent on target"
fi

# Fresh Rust pq-bridge replaces the stale Windows exe — dated-deploy
# convention: yakmesh-run.js prefers the newest yakos-pq-bridge-YYYYMMDD
# binary, so competing stale dated binaries must not survive in the tree.
DATED_TS=$(date -r /home/abl/Desktop/YakOS/yakos-pq-bridge/target/release/yakos-pq-bridge +%Y%m%d 2>/dev/null || date +%Y%m%d)
PQ_WIN=/home/abl/Desktop/YakOS/yakos-pq-bridge/target/x86_64-pc-windows-gnu/release/yakos-pq-bridge.exe
if [ -f "$PQ_WIN" ]; then
  cp -a "$PQ_WIN" "$STAGE/yakmesh-node/yakos-pq-bridge.exe"
  cp -a "$PQ_WIN" "$STAGE/yakmesh-node/yakos-pq-bridge-$DATED_TS.exe"
  find "$STAGE/yakmesh-node" -maxdepth 1 -name "yakos-pq-bridge-*.exe" \
      ! -name "yakos-pq-bridge-$DATED_TS.exe" -delete
  echo "  + fresh pq-bridge $DATED_TS (dated + undated; older dated removed)"
fi

# ── c2c: server + shared + built client (weights are a separate payload) ──
rsync -a --exclude '__tests__' --exclude 'npu/models/' --exclude 'data' \
  --exclude 'node_modules' --exclude '.env' --exclude '.env.*' \
  "$C2C_SRC/server/" "$STAGE/c2c/server/"
# models/ holds code too (registry.js) — keep JS, drop weights/data only
mkdir -p "$STAGE/c2c/server/npu/models"
find "$C2C_SRC/server/npu/models" -maxdepth 1 -name '*.js' \
  -exec cp -a {} "$STAGE/c2c/server/npu/models/" \;
rsync -a --exclude '__tests__' "$C2C_SRC/shared/" "$STAGE/c2c/shared/"
mkdir -p "$STAGE/c2c/client"
rsync -a "$C2C_SRC/client/dist/" "$STAGE/c2c/client/dist/"
cp -a "$C2C_SRC/package.json" "$C2C_SRC/package-lock.json" "$STAGE/c2c/"
cp -a "$C2C_SRC/.env.example" "$STAGE/c2c/.env.example" 2>/dev/null || true

# ── START-YAKMESH.BAT — the canonical entry (Windows) ─────────────────────
# Delegates to yakmesh-node\start-yakmesh.bat, which does the real work:
# kill stale node/supervisor/pq-bridge (its pattern catches c2c's
# server\index.js too), provision key-share, start pq-bridge, run the
# supervisor. Then c2c gets its own window after the node has bound.
cat > "$STAGE/START-YAKMESH.BAT" <<'BATEOF'
@echo off
REM ============================================================
REM START-YAKMESH (c2c node) — yakmesh node + Core2Cosmos server
REM   1. yakmesh-node\start-yakmesh.bat: dismount stale processes,
REM      key-share, pq-bridge, supervisor — the canonical contract
REM   2. c2c deps install on first run (better-sqlite3/bcrypt are
REM      platform-native — cannot be shipped from a Linux build)
REM   3. c2c launches in its own window once the node has had a
REM      moment to bind :3080 and the scheduler pipe
REM ============================================================
cd /d %~dp0

if not exist c2c\node_modules (
    echo [start] installing c2c dependencies ^(first run^)...
    pushd c2c
    call npm ci --omit=dev --legacy-peer-deps
    popd
)
if not exist c2c\.env (
    for /f %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set JWT=%%i
    (echo PORT=3091& echo NODE_ENV=production& echo JWT_SECRET=%JWT%) > c2c\.env
    echo [start] c2c\.env generated
)

echo [start] launching yakmesh node ^(supervisor + pq-bridge + keyshare^)...
start "YAKMESH-NODE" cmd /k "cd /d %~dp0yakmesh-node && start-yakmesh.bat"
timeout /t 8 /nobreak >nul
echo [start] launching c2c on :3091...
start "C2C" cmd /k "cd /d %~dp0c2c && node server\index.js"
echo [start] both launched — leave the two windows running
BATEOF

# ── START-NODE.SH — Linux equivalent ──────────────────────────────────────
cat > "$STAGE/START-NODE.SH" <<'SHEOF'
#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
if [ ! -d c2c/node_modules ]; then
  (cd c2c && npm ci --omit=dev --legacy-peer-deps)
fi
if [ ! -f c2c/.env ]; then
  JWT=$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')
  printf 'PORT=3091\nNODE_ENV=production\nJWT_SECRET=%s\n' "$JWT" > c2c/.env
fi
(cd yakmesh-node && exec bash start-yakmesh.sh) &
sleep 6
(cd c2c && exec node server/index.js) &
wait
SHEOF
chmod +x "$STAGE/START-NODE.SH"

cat > "$STAGE/README-c2c-node.md" <<'RDEOF'
# yakmesh node + c2c dist

Two windows started by START-YAKMESH.BAT (Windows) / START-NODE.SH (Linux):

- yakmesh node — canonical launcher (dismount stale procs, key-share,
  pq-bridge, supervisor). yakmesh.config.js is oracle-hashed — identical
  on every node, never edit it.
- c2c on :3091 — heartbeats into the node's Lighthouse directory; over
  YAK-TUN the host is 10.199.<sha256(nodeId)[0..1]>:3091, derived from
  nodeId — no DNS needed.

c2c/server/npu/models ships empty (registry.js only) — the 15G ONNX
payload is optional; ONNX/NPU lanes report absent honestly without it.
RDEOF

# ── safety gate: refuse to ship node identity, DBs, or real env files ────
LEAKS=$(find "$STAGE" \( -name 'node-key.json' -o -name 'machine-seed.json' \
  -o -name 'yakmesh.db' -o -name '.env' \) | grep -v '.env.example' || true)
if [ -n "$LEAKS" ]; then
  echo "[dist] REFUSING — sensitive files in staging:" >&2
  echo "$LEAKS" >&2
  exit 1
fi

# ── copy to destination ───────────────────────────────────────────────────
# --copy-links: CIFS targets can't hold symlinks (npm .bin unix shims are
# inert on Windows anyway — the .cmd/.ps1 wrappers ship as regular files)
mkdir -p "$OUT"
rsync -a --copy-links --delete "$STAGE/" "$OUT/"
echo "[dist] wrote $OUT ($(du -sh "$OUT" | cut -f1))"

if [ "$WITH_MODELS" = "1" ]; then
  MTAR="$(dirname "$OUT")/c2c-models-$(date +%Y%m%d).tar.gz"
  tar -C "$C2C_SRC/server/npu" --exclude='models/__pycache__' -czf "$MTAR" models
  echo "[dist] wrote $MTAR ($(du -h "$MTAR" | cut -f1)) — untar into c2c/server/npu/ on target"
fi
