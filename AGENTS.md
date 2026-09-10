# AGENTS — YakMesh Node

## Project
YakMesh is the networking and identity layer for the YakMesh suite. This is the Node.js package (`yakmesh-node`) that maps to GitHub at `github.com/yakmesh/yakmesh`.

## Repository
- Remote: `https://github.com/yakmesh/yakmesh.git`
- This is the ONLY sub-project under `C:\Users\ABL\Desktop\Yakmesh\` that has a GitHub remote
- All other Yakmesh sub-projects are proprietary and local-only

## YakForge Agent-Safe File I/O (v2.1.0+)

YakForge daemon (port 9998) provides HTTP endpoints for file operations that bypass PowerShell's encoding/escaping traps. **Use these when dealing with non-ASCII content or when PowerShell escaping causes issues.**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/file/read?path=...` | GET | Read file as UTF-8 JSON |
| `/api/file/write` | POST | Write file (UTF-8, `create_dirs` option) |
| `/api/file/list?path=...&pattern=...` | GET | List directory (with glob filter) |
| `/api/file/grep` | POST | Regex search → structured JSON results |
| `/api/file/edit` | POST | Exact string replacement (Unicode-safe) |
| `/api/file/stat?path=...` | GET | File metadata |
| `/api/file/mkdir` | POST | Create directories |
| `/api/file/delete` | POST | Delete file |

**Dynamo model manager** — embedding models load on demand:
- Always-on: `code` + `general`
- On-demand: `multilingual` (5 min idle) + `deep` (2 min idle)
- Auto-router detects language and code intent, routes queries automatically
- `GET /api/models/status` — check model states, cache stats, RAM
- `POST /api/models/load {"role":"deep"}` — manually load
- `POST /api/models/unload {"role":"deep"}` — manually unload (free RAM)

## YakForge v2.1.0 — Agent Capability Discovery & Safety Tools

**FIRST STEP: Call GET http://localhost:9998/api/capabilities to discover all 43 endpoints.** The API describes itself — no need to read documentation.

### New in v2.1.0:

- **Checkpoint API** (/api/checkpoint/*): Snapshot workspace state before risky changes. Diff and restore.
- **Verification Gate** (/api/verify/*): Run commands and get the REAL exit code + output. Kill verification theater — the daemon reports ground truth, not the agent's claim. Register named gates that persist across sessions.
- **Clean Shell Exec** (POST /api/exec): Run shell commands → clean JSON with ANSI stripped, UTF-8 enforced. No noise pollution.
- **Drift Detector** (POST /api/drift/check): Check AGENTS.md instructions against actual repo state. Catches package manager mismatches, stale file references, test command conflicts.
- **Model Refusal Auto-Rerouting**: If a model fails, queries automatically fall back to alternative models.
