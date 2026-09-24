# AGENTS — YakMesh Node

## FIRST STEP FOR ANY AGENT
**Call `GET http://localhost:9998/api/capabilities` to discover all available YakForge tools.**
**Call `GET http://localhost:9998/api/mind?path=C:\Users\ABL\Desktop\Yakmesh\yakmesh-node` to discover full workspace context.**

## Project
YakMesh is the networking and identity layer for the YakMesh suite. This is the Node.js package (`yakmesh-node`) that maps to GitHub at `github.com/yakmesh/yakmesh`.

## Repository
- Remote: `https://github.com/yakmesh/yakmesh.git`
- This is the ONLY sub-project under `C:\Users\ABL\Desktop\Yakmesh\` that has a GitHub remote
- All other Yakmesh sub-projects are proprietary and local-only

## CONFIDENTIAL/ — The ONLY Place Research Lives (HARD RULE)
- ALL research documents, specs, audit reports, experiments, designs, and internal
  artifacts MUST be created inside `CONFIDENTIAL/` at the repo root — never anywhere else.
- `CONFIDENTIAL/` is gitignored. Its contents must NEVER be committed, published,
  pushed to any remote, or copied into tracked paths.
- This repo is PUBLIC. Treat every tracked path as published to the world.
- If `CONFIDENTIAL/` does not exist when you need to produce research, create it.

## Deployment (HARD RULE)
- **Always run via `node scripts/yakmesh-run.js`** (the supervisor) — never `node server/index.js`
  under PM2/process managers directly. Direct launch hangs in module evaluation under PM2
  (observed on Hostinger, 2026-09-24); the supervisor's stdio-inherit spawn is the supported path
  and is what consumes staged ACT/in-place upgrades.
- Shared-hosting deploys use the 443 relay: `YAKMESH_HTTP_PORT=3000`, `YAKMESH_SELF_ENDPOINT`,
  `YAKMESH_RELAY_ENDPOINT` env vars — PHP bridges in `deploy-packages/php-bridge/` forward to
  `127.0.0.1:3000`. Never edit `yakmesh.config.js` per-host (oracle-hashed, must stay byte-identical).

## Full Details
YakForge file I/O, model manager, and v2.1.0 feature details are in **mind.md**.
