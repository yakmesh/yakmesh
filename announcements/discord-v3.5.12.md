🏔️ *YAKMESH v3.5.12 — the mountain speaks*

Last release we stopped building wider and started building *true*. This one, the whole mountain learned to speak — and to answer for what it says.

It started with a browser that couldn't tell the truth. Through our gate's proxy tunnel it would only admit to HTTP/1.1 while every real browser spoke h2 — and the old world's gatekeepers score that confession. No human can out-click a transport fingerprint. So the gate learned to *speak*: one port, two dialects — CONNECT and SOCKS5 — and for those who want the deeper cut, `YAKGATE_MITM` ends the tunnel at the gate itself: per-host certs minted by a CA that lives only on your machine, a uniform h2 voice for every node on the mesh, and a CA your node *declares itself* — signed by its ML-DSA-65 identity at `/gate/ca`. Trust anchored in the mesh, not in a certificate authority. The site that challenged us forever now clears itself.

But a mountain that speaks must also answer for itself. The new **attestation pipeline** makes package integrity honest and visible — claims measured, not reported. The **job pipeline** runs end to end: deposits land, epochs claim them, every byte audited exact. **Lighthouse** grew a directory — per-service entries with persistent-id personhood ops, so a node can vouch for *what* it is, not just *that* it is.

The NPU climbed too — a **prover tier** running our own IRON xclbin through `yak_xrt_shim`, plus the qdq-u8 VitisAI attempt for XDNA1. Ports orchestrated into a reliability pass. And the small things that decide whether software survives the real world: exec bits that died on every staging run now persist, and the deployment rule is written down at last — the supervisor is the only way up.

`npm install yakmesh` · v3.5.12 · github.com/yakmesh/yakmesh

Sturdy & Secure. 🦬
