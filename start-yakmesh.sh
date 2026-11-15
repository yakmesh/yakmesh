#!/usr/bin/env bash
# ============================================================
# start-yakmesh — canonical Linux launcher (ports START-YAKMESH.BAT)
#   1. Gracefully stops a running node (SIGTERM → supervisor drains,
#      SIGKILL only on timeout) — the bat's "clean slate" contract
#   2. Provisions the hardware-bound keystore if missing
#      (pq-bridge exits 'os error 3' without it)
#   3. Ensures pq-bridge is healthy on :9995 (systemd-resident here;
#      the bat spawns a bundled binary on Windows)
#   4. Launches the supervisor — the ONLY supported node entry
#      (applies staged ACT swaps, manages the bridge, respawns)
# NOTE: never copy yakmesh.config.production.js over yakmesh.config.js —
# config.js is oracle-hashed; overwriting it changes the network id.
# ============================================================
set -u
cd "$(dirname "$0")"

log() { echo "[start-yakmesh] $*"; }

# --- 1. clean slate: stop stale node + supervisor (SIGTERM first) -----------
pids=$(pgrep -f 'yakmesh-run\.js|yakmesh-node.*/server/index\.js' || true)
if [ -n "$pids" ]; then
    log "stopping stale yakmesh processes: $pids"
    echo "$pids" | xargs -r kill -TERM 2>/dev/null
    for _ in 1 2 3 4 5; do
        pgrep -f 'yakmesh-run\.js|yakmesh-node.*/server/index\.js' >/dev/null || break
        sleep 1
    done
    pgrep -f 'yakmesh-run\.js|yakmesh-node.*/server/index\.js' | xargs -r kill -KILL 2>/dev/null || true
fi

mkdir -p logs data
[ -d node_modules ] || { log "installing dependencies"; npm install --omit=dev; }

# --- 2. keystore — hardware-bound identity; bridge needs it -----------------
export YAKOS_KEYSTORE_PATH="${YAKOS_KEYSTORE_PATH:-$HOME/.local/share/yakos/keystore.json}"
if [ -f "$YAKOS_KEYSTORE_PATH" ]; then
    log "keystore present: $YAKOS_KEYSTORE_PATH"
else
    log "keystore missing — canon attestation will stay down until provisioned"
    # On YakOS the keystore is OS-managed (yakos-keystore systemd path);
    # a packaged node would init via the bundled binary. Warn, don't fake.
fi

# --- 3. pq-bridge — healthy on :9995 or nothing ------------------------------
if curl -sf --max-time 2 http://127.0.0.1:9995/health >/dev/null 2>&1; then
    log "pq-bridge healthy on :9995"
else
    log "pq-bridge not answering — trying systemd unit"
    systemctl --user start yakos-pq-bridge 2>/dev/null \
        || sudo systemctl start yakos-pq-bridge 2>/dev/null \
        || log "WARNING: bridge unavailable — attestation idle"
fi

# --- 4. staged ACT swap hint -------------------------------------------------
[ -f data/pending-update/package.zip ] && \
    log "staged ACT package present — supervisor applies it on launch"

# --- 5. supervisor — the only supported entry --------------------------------
log "launching supervisor (relay + seva + attestation on)"
log "console → logs/yakmesh-run-console.log"
exec node scripts/yakmesh-run.js 2>&1 | tee -a logs/yakmesh-run-console.log
