# Yakmesh Release Checklist

This checklist ensures releases are complete, accurate, and secure.

## Pre-Release Checklist

### 1. Code Quality

- [ ] **All tests pass** - Run `npm test` and verify 0 failures
- [ ] **No lint errors** - Run `npm run lint` if available
- [ ] **No TODO/FIXME in critical paths** - Search security code for unfinished work
  ```powershell
  Get-ChildItem -Recurse -Filter "*.js" security,oracle,mesh,identity | Select-String -Pattern "TODO|FIXME"
  ```

### 2. Cryptographic API Verification

**ML-DSA-65 (Post-Quantum Signatures):**
- [ ] All `ml_dsa65.sign()` calls use `sign(message, secretKey)` order
- [ ] All `ml_dsa65.verify()` calls use `verify(signature, message, publicKey)` order

**ML-KEM-768 (Post-Quantum Key Exchange):**
- [ ] All `ml_kem768.encapsulate()` calls use `encapsulate(publicKey)` order
- [ ] All `ml_kem768.decapsulate()` calls use `decapsulate(ciphertext, secretKey)` order

**Verification command:**
```powershell
Get-ChildItem -Recurse -Filter "*.js" | Select-String -Pattern "ml_dsa65\.(sign|verify)|ml_kem768\.(encapsulate|decapsulate)"
```

### 3. Exports Verification

- [ ] **All exports exist** - Every path in `package.json exports` resolves to a real file
  ```powershell
  # Run from yakmesh-node directory
  node -e "const pkg = require('./package.json'); Object.values(pkg.exports).flat().forEach(p => { const fs = require('fs'); const path = p.replace('./', ''); if (!fs.existsSync(path)) console.log('MISSING:', path); })"
  ```

### 4. Documentation

- [ ] **README.md is accurate** - All features, APIs, and examples are current
- [ ] **API documentation matches implementation** - Check function signatures
- [ ] **CHANGELOG.md updated** - Version, date, and all changes documented
- [ ] **Migration guide** (if breaking changes) - Clear upgrade path for users

### 5. Version Management

- [ ] **Version bumped** in `package.json`
- [ ] **Version tag matches** - `npm version` output matches intended release
- [ ] **No debug code** - Remove `console.log` from production paths
- [ ] **Dependencies updated** - Run `npm audit` and address critical issues

## Post-Release Verification

### 1. Installation Test

```powershell
# Create a test directory
mkdir test-install && cd test-install
npm init -y
npm install yakmesh-node@<version>

# Test basic import
node -e "const yk = require('yakmesh-node'); console.log('Import successful')"
```

### 2. Smoke Tests

- [ ] Can generate node identity
- [ ] Can create and verify signatures
- [ ] Can establish encrypted channels
- [ ] Core mesh operations work

### 3. Documentation Deployment

- [ ] Website updated with new version
- [ ] API docs regenerated
- [ ] Release notes published

## Critical Files to Review

| File | Purpose | Priority |
|------|---------|----------|
| `security/doko-identity.js` | Identity signatures | HIGH |
| `security/namche-gateway.js` | Gateway security | HIGH |
| `oracle/module-sealer.js` | Module attestation | HIGH |
| `mesh/nakpak-routing.js` | Packet signing | HIGH |
| `identity/node-key.js` | Node authentication | HIGH |

## Known Pitfalls

### ML-DSA-65 Argument Order
The noble-post-quantum library uses:
- `sign(message, secretKey)` - **message FIRST**
- `verify(signature, message, publicKey)` - **signature FIRST**

This is opposite to some other crypto libraries (e.g., sodium). Always verify against the [noble-post-quantum documentation](https://github.com/paulmillr/noble-post-quantum).

### JSON Serialization for Signing
When creating signable bytes from objects:
- Use stable/deterministic JSON serialization
- Sort keys recursively (not just top-level)
- Use a helper function like `stableStringify()` for nested objects

## Release Types

| Type | Version | When to Use |
|------|---------|-------------|
| Major | X.0.0 | Breaking changes, major features |
| Minor | 0.X.0 | New features, backward compatible |
| Patch | 0.0.X | Bug fixes, security patches |

---

*Last updated: 2026-01-18 (v2.0.1 preparation)*
