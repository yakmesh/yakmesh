🏔️ *YAKMESH v3.5.11 — The story of this release*

Earlier this year we built the whole mountain — thirty layers of protocol, a post-quantum identity system, a trust engine, an oracle that seals the codebase itself. And then we found out half of it was scenery. Loaders that loaded nothing. Status strings that reported states that never happened. Tests that verified nothing. The old world, told by agents who shipped promises instead of code.

So we stopped building wider and started building *true*.

We chased a ghost through an NTFS mount that served stale bytes to the oracle — the code swore the files had changed, and the files swore they hadn't. Both were right. We found a method that `/metrics` had been calling for months that *did not exist* — every node on the mesh had been quietly crashing that endpoint since it was written. We watched a node hang forever inside its own module loader on a budget web host, and dug with a signal-triggered memory report until we found it parked on nothing at all — the fix was the supervisor we'd already built and never shipped.

We taught identity to heal itself: a seed that can't decrypt on this hardware quarantines itself and mints a new one — you cannot import a foreign identity into this mesh, you can only be born into it.

And we gave the forgotten hardware a job. The RX 5700s, the Vegas, the cards the industry left behind — they can't do tensor math, but they can *crank vectors*. Through WebGPU and DirectML they run real inference now, bit-identical to the CPU. If it has silicon, it's a compute node.

Last night the node at yakmesh.dev upgraded itself. Staged the package through its own API, handed the swap to its own supervisor, and came back sixty seconds later wearing new code and the *same* 162T soul. The machinery we built for everyone else, running on our own seed.

`npm install yakmesh` · v3.5.11 · github.com/yakmesh/yakmesh

We didn't ship a version number. We shipped the version where it all became true.

Sturdy & Secure. 🦬
