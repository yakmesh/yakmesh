# YAKMESH Documentation

> **📚 Full documentation available at [yakmesh.dev](https://yakmesh.dev)**

## Quick Links

| Topic | Web | Specification |
|-------|-----|---------------|
| Getting Started | [yakmesh.dev/docs/getting-started](https://yakmesh.dev/docs/getting-started) | — |
| Configuration | [yakmesh.dev/docs/configuration](https://yakmesh.dev/docs/configuration) | — |
| API Reference | [yakmesh.dev/docs/api](https://yakmesh.dev/docs/api) | — |
| CLI Reference | [yakmesh.dev/docs/cli](https://yakmesh.dev/docs/cli) | — |
| NAMCHE Gateway | [yakmesh.dev/docs/namche](https://yakmesh.dev/docs/namche) | [NAMCHE-SPEC.md](NAMCHE-SPEC.md) |
| TATTVA Oracle | [yakmesh.dev/docs/tattva](https://yakmesh.dev/docs/tattva) | — |
| SURAKSHA Security | [yakmesh.dev/docs/trust-security](https://yakmesh.dev/docs/trust-security) | — |
| Time Sources | [yakmesh.dev/docs/time-sources](https://yakmesh.dev/docs/time-sources) | — |
| Mesh Networking | [yakmesh.dev/docs/mesh](https://yakmesh.dev/docs/mesh) | — |
| SHERPA Discovery | [yakmesh.dev/docs/sherpa](https://yakmesh.dev/docs/sherpa) | — |
| NAKPAK Routing | [yakmesh.dev/docs/nakpak](https://yakmesh.dev/docs/nakpak) | — |
| ANNEX Channels | [yakmesh.dev/docs/annex](https://yakmesh.dev/docs/annex) | — |
| YAK:// Protocol | [yakmesh.dev/docs/yak-protocol](https://yakmesh.dev/docs/yak-protocol) | — |
| Geographic Proof | [yakmesh.dev/docs/geo-proof](https://yakmesh.dev/docs/geo-proof) | — |

## Protocols (v3.3.0)

| Protocol | Purpose | Docs |
|----------|---------|------|
| **STUPA** | State consensus | [yakmesh.dev/docs/stupa](https://yakmesh.dev/docs/stupa) |
| **LAMA** | Lightweight messaging | [yakmesh.dev/docs/lama](https://yakmesh.dev/docs/lama) |
| **MANI** | Metrics & analytics | [yakmesh.dev/docs/mani](https://yakmesh.dev/docs/mani) |
| **KARMA** | Trust reputation | [yakmesh.dev/docs/karma](https://yakmesh.dev/docs/karma) |
| **MANDALA** | Topology management | [yakmesh.dev/docs/mandala](https://yakmesh.dev/docs/mandala) |

## Specifications & Research

These documents provide deep technical details for implementers:

| Document | Description |
|----------|-------------|
| [WHITEPAPER.md](WHITEPAPER.md) | Full technical whitepaper |
| [NAMCHE-SPEC.md](NAMCHE-SPEC.md) | NAMCHE gateway specification |
| [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md) | Cryptographic algorithm choices |
| [TME-FAQ.md](TME-FAQ.md) | Temporal Matrix Encoding FAQ |
| [MTLS-RESEARCH.md](MTLS-RESEARCH.md) | mTLS integration research |
| [PRECISION-DISCLOSURE.md](PRECISION-DISCLOSURE.md) | Precision timing disclosure |

## Roadmaps

| Version | Status |
|---------|--------|
| [ROADMAP-3.3.0.md](ROADMAP-3.3.0.md) | ✅ Released |
| [ROADMAP-2.5.0.md](ROADMAP-2.5.0.md) | ✅ Released |
| [ROADMAP-2.4.0.md](ROADMAP-2.4.0.md) | ✅ Released |

## GRANTH: Embedded Documentation Bundle

YAKMESH includes an embedded documentation bundle (**GRANTH**) that ships with the npm package. This enables offline-first, hash-verified documentation access.

```javascript
// Access embedded docs programmatically
import { BUNDLE_HASH, BUNDLE_VERSION, FILES } from 'yakmesh/embedded-docs/bundle.js';

console.log(`Docs v${BUNDLE_VERSION} - Hash: ${BUNDLE_HASH.slice(0, 16)}...`);
```

The bundle contains the same documentation as yakmesh.dev, verified by SHA3-256 hashes. This ensures:
- **Offline access**: Docs work without internet
- **Integrity**: Hash verification prevents tampering
- **Consistency**: Same docs across all nodes running same version

---

<div align="center">
  <strong><a href="https://yakmesh.dev">yakmesh.dev</a></strong>
  <br><br>
  <sub>© 2026 YAKMESH™ Project. Sturdy & Secure.</sub>
</div>
