🏔️ *YAKMESH v3.5.10 — The mesh is real now.*

Not a roadmap. Not a promise. A post-quantum mesh that runs, verifies itself, and proves it.

*Post-quantum from genesis:* ML-DSA-65 signatures on every identity. ML-KEM transport on every handshake. JHILKE chirp → ANNEX session → gossip — the whole handshake chain is live code, not a spec.

*Identity that can't be faked:* hardware-bound machine seeds mint 162T ternary persistentIds. A foreign seed can't be injected — it simply won't decrypt; the node quarantines it and heals itself. Your identity is 33 words across machines. `yakmesh identity show|reset`.

*A codebase that guards itself:* the Validation Oracle seals every source file into the network-id at boot. FileGuardian locks identity files on disk. Tamper → the node *reports* `compromised`, doesn't die. Byte-identical source is the consensus boundary — same code, same network.

*Trust is earned on-chain, not assumed:* SAKSHI witnesses observe behavior → KARMA scores it → rates, routes, and update-announcer rights follow. Sybil inflation can't buy standing.

*Time you can trust:* Meinberg GPS-disciplined clock, AGUWA Kuramoto phase sync — nodes oscillate to the same beat because the code-hash derives the same natural frequency.

*Compute for everyone — the Triad:* SEVA mesh compute is on by default. AMD XDNA NPU detection on Linux *and* Windows (xdna1/xdna2 aware). AMD GPUs — RX 5700-class and up — now execute real ONNX inference through WebGPU/DirectML. No CUDA required. No tensor cores required. Old hardware is a compute node again.

*Reachable anywhere:* SHERPA discovery over HTTPS beacons + an HTTP relay for firewalled nodes — the seed node at yakmesh.dev literally runs behind it on shared hosting. If we can reach the mesh through port 443 on a budget web host, so can you.

*Upgrades that don't eat your identity:* `yakmesh upgrade <pkg>` overlays code, preserves everything in `data/`, backs up every touched file for rollback. `yakmesh migrate` carries identity forward. Dashboard can stage and apply — restart handled by the supervisor.

*985 tests passing* — 258 oracle protocol + 727 security/trust.

`npm install yakmesh` · github.com/yakmesh/yakmesh · `v3.5.10`

Sturdy & Secure. 🦬
