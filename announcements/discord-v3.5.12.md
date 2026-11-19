🏔️ *YAKMESH v3.5.12 — the gate release*

A yak does not imitate the mountain. It *is* the mountain's voice.

Our gate was a pipe: the browser's TLS went through it byte-for-byte, and whatever the browser's library was willing to say, the world heard. Turned out our browser's library was shy — through a proxy tunnel it would only admit to HTTP/1.1, while every real browser speaks h2. The old world's gatekeepers score that confession, and no human can out-click a transport fingerprint.

So we taught the gate to *speak*.

One port now hears two dialects — HTTP CONNECT as always, and SOCKS5 for the clients that only tell the truth when asked differently. The tunnel never takes the first answer as final: it walks every address a name resolves to, finds the IPv4 hiding inside Cloudflare's IPv6-only names, and remembers what it learned instead of asking again.

And for those who want the deeper cut: `YAKGATE_MITM` opens the boundary entirely — browser TLS ends at the gate on certs minted per-host by a CA that lives only on your machine, while the gate speaks upstream with one uniform fingerprint for every node on the mesh. Your node declares that CA itself — signed by its ML-DSA-65 identity at `/gate/ca`. Trust anchored in the mesh, not in a certificate authority.

The site that challenged us forever now clears itself. Quietly — the way infrastructure should.

Also along for the climb: an attestation pipeline that makes package integrity honest and visible, the job pipeline from deposits to byte-exact audit, lighthouse directory entries, an NPU prover tier, and the deployment rule written down at last — the supervisor is the only way up.

`npm install yakmesh` · v3.5.12 · github.com/yakmesh/yakmesh

Sturdy & Secure. 🦬
