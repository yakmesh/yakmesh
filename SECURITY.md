# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously at YAKMESH™. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email**: security@yakmesh.dev

**Do NOT**:
- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before we've had a chance to address it

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days (depending on severity)

### Recognition

We appreciate responsible disclosure and will:
- Credit you in the security advisory (unless you prefer anonymity)
- Work with you to understand and resolve the issue
- Not take legal action for good-faith security research

## Security Features

YAKMESH implements multiple layers of security:

- **Post-Quantum Cryptography**: ML-DSA-65 signatures (NIST FIPS 204)
- **Authenticated Encryption**: XChaCha20-Poly1305
- **Replay Protection**: Phase-epoch based message validation
- **Code Integrity**: Self-verifying oracle with module sealing

## Known Limitations

- NTP time sources are not suitable for oracle operations (use GPS/PTP/Atomic)
- Community edition does not include WebSocket authentication (see Pro)

---

YAKMESH™ is a trademark of PeerQuanta (USPTO Serial No. 99594620)
