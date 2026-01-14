<![CDATA[# Contributing to YAKMESH 🏔️

![YAKMESH](https://img.shields.io/badge/YAKMESH-Sturdy%20%26%20Secure-2D5A27?style=for-the-badge)
![Post-Quantum](https://img.shields.io/badge/Security-Quantum--Resistant-blueviolet?style=flat-square)
![Timing](https://img.shields.io/badge/Timing-Atomic%20Clock%20Compatible-yellow?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Thank you for your interest in contributing to **YAKMESH** — the **Yielding Atomic Kernel Modular Encryption Secured Hub**.

We are building a "Sturdy & Secure" foundation for the post-quantum era.

---

## 📋 Before You Contribute

1. **Read the documentation** at [yakmesh.dev](https://yakmesh.dev)
2. **Check existing issues** to avoid duplicates
3. **Follow our code of conduct** — be respectful and constructive

---

## 🔐 Engineering Standards

### Cryptographic Requirements

All contributions involving cryptographic primitives **MUST**:

- ✅ Use **NIST-standardized Post-Quantum Cryptography** (ML-DSA-65 / FIPS 204)
- ✅ Use libraries from the `@noble` family (`@noble/hashes`, `@noble/post-quantum`)
- ❌ **NO legacy ECDSA/RSA** in security-critical paths
- ❌ **NO `Math.random()`** for security-sensitive operations (use `randomBytes()`)

### Timing & Synchronization

Changes to the timing/oracle layer must:

- Support precision hardware timestamps (PCIe atomic clocks, PTP, GPS)
- Maintain backward compatibility with NTP-only deployments
- Include tests for phase epoch calculations

### Code Quality

- All PRs must pass existing tests (`npm test`)
- Include tests for new functionality
- Follow existing code style (ES modules, async/await)
- Document public APIs with JSDoc comments

---

## 🏷️ Branding & Trademark

**YAKMESH** is a trademark of the YAKMESH Project (PeerQuanta).

### If You Fork This Project

| ❌ You MUST | ✅ You MAY |
|-------------|------------|
| Remove the official YAKMESH logo | State "Based on YAKMESH technology" |
| Remove YAKMESH branding | State "Powered by YAKMESH" |
| Rename your software | Use the "Powered by" badge below |

### "Powered by YAKMESH" Badge

```markdown
![Powered by YAKMESH](https://img.shields.io/badge/Powered%20by-YAKMESH-2D5A27?style=for-the-badge)
```

Full policy: [yakmesh.dev/docs/trademark-policy.html](https://yakmesh.dev/docs/trademark-policy.html)

---

## 🚨 Security Vulnerabilities

**Please do NOT open public issues for security flaws.**

Instead, email **security@peerquanta.com** directly so we can coordinate a responsible disclosure and hardened patch.

We follow a 90-day disclosure policy and will credit researchers in our security acknowledgments.

---

## 📝 Pull Request Process

1. **Fork** the repository
2. **Create a branch** (`git checkout -b feature/my-feature`)
3. **Make your changes** following the standards above
4. **Test** your changes (`npm test`)
5. **Commit** with clear messages
6. **Push** and open a Pull Request

### PR Title Format

```
[category] Brief description

Examples:
[oracle] Add GPS time source detection
[mesh] Fix WebSocket reconnection logic
[docs] Update API reference
[security] Patch hash exposure in /status endpoint
```

---

## 💬 Questions?

- **General:** Open a GitHub Discussion
- **Security:** security@peerquanta.com
- **Legal/Trademark:** legal@peerquanta.com

---

<div align="center">
  <sub>Built with quantum principles. Secured by math.</sub>
  <br><br>
  <strong><a href="https://yakmesh.dev">yakmesh.dev</a></strong>
  <br><br>
  <sub>© 2026 YAKMESH Project. Sturdy & Secure.</sub>
</div>
]]>