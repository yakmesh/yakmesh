// YakMesh security audit regression tests — exercises each critical fix directly
// Run: node tests/security-audit-regression.mjs
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const base = join(dirname(fileURLToPath(import.meta.url)), '..');
let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name}`); }
}

// ── 1. Path traversal — embedded-docs/serve.js ─────────────────────────
console.log('\n[1] Path traversal (embedded-docs)');
const serveCode = readFileSync(join(base, 'embedded-docs/serve.js'), 'utf8');
check('serve.js rejects .. in path', serveCode.includes("normalizedPath.includes('..')"));
check('serve.js checks resolved root', serveCode.includes('resolved.startsWith(docsRoot)') || serveCode.includes('resolvedAssets.startsWith(assetsRoot)'));
check('serve.js rejects absolute paths', serveCode.includes('normalizedPath.startsWith'));

// ── 2. Path traversal — content/store.js ───────────────────────────────
console.log('\n[2] Path traversal (content store)');
const { isTritAddress } = await import('../content/store.js');
check('rejects ../traversal', !isTritAddress('../../../etc/passwd'));
check('rejects empty', !isTritAddress(''));
check('rejects hex injection', !isTritAddress('deadbeef/../../etc/shadow'));
check('rejects slash', !isTritAddress('T0/T1'));

// ── 3. Auth bypass — tribhuj ratchet ───────────────────────────────────
console.log('\n[3] TribhujRatchet external-key bypass');
const { TribhujRatchet } = await import('../identity/tribhuj-ratchet.js');
const ratchet = new TribhujRatchet();
await ratchet.initialize();
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const attackerKp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
const { mlDsa65Sign } = await import('../utils/accel.js');
const { bytesToHex } = await import('@noble/hashes/utils.js');
const msg = new TextEncoder().encode('forged message');
const attackerSig = mlDsa65Sign(msg, attackerKp.secretKey);
const res = ratchet.verify(msg, bytesToHex(attackerSig), bytesToHex(attackerKp.publicKey));
check('unknown key rejected', res.valid === false && res.keyState === 'external');
const ownSig = ratchet.sign('hello');
const res2 = ratchet.verify('hello', ownSig.signature, ownSig.publicKey);
check('own current key verifies', res2.valid === true && res2.keyState === 'current');

// ── 4. Gateway attestation — pinned keys ───────────────────────────────
console.log('\n[4] Gateway attestation pinned-key check');
const { GatewayAttestation } = await import('../identity/tribhuj-ratchet.js');
const gwRatchet = new TribhujRatchet();
await gwRatchet.initialize();
const gw = new GatewayAttestation('node-gw', gwRatchet);
const att = gw.attest('msg-1', 'node-signer');
const noKeys = gw.verifyAttestation(att);
check('attestation without pinned keys fails', noKeys.valid === false);
const wrongKeys = gw.verifyAttestation(att, { current: 'ff'.repeat(1952), previous: null });
check('attestation with wrong pinned keys fails', wrongKeys.valid === false);
const rightKeys = gw.verifyAttestation(att, { current: bytesToHex(gwRatchet._current.publicKey), previous: null });
check('attestation with pinned key passes', rightKeys.valid === true);

// ── 5. Regex DoS — SafeJsonParser ──────────────────────────────────────
console.log('\n[5] Regex DoS resistance');
const { SafeJsonParser } = await import('../mesh/message-validator.js');
const parser = new SafeJsonParser();
const evil = 'constructor'.repeat(50000) + 'prototype'.repeat(50000);
const t0 = Date.now();
parser.parse(evil);
const elapsed = Date.now() - t0;
check('adversarial input completes <100ms', elapsed < 100);
const proto = parser.parse('{"__proto__": {"x": 1}}');
check('__proto__ rejected', proto.success === false);
const legit = parser.parse('{"a": 1}');
check('legit JSON parses', legit.success === true);

// ── 6. Mnemonic export — password protection ───────────────────────────
console.log('\n[6] Mnemonic export password protection');
const seedCode = readFileSync(join(base, 'identity/machine-seed.js'), 'utf8');
check('password export deletes plaintext words', seedCode.includes('delete result.words'));
check('password export returns encrypted blob', seedCode.includes('result.encrypted'));

// ── 7. ANNEX forward secrecy ───────────────────────────────────────────
console.log('\n[7] ANNEX bootstrap->KEM upgrade');
const annexCode = readFileSync(join(base, 'mesh/annex.js'), 'utf8');
check('openChannel upgrades bootstrap sessions', annexCode.includes('session.bootstrapped') && annexCode.includes('forward secrecy'));
check('KEM exchange no longer ignored for bootstrap', !annexCode.includes('Ignoring KEM exchange — JHILKE bootstrap session active'));
check('tie-break prevents crossing exchanges', annexCode.includes('localId > remoteNodeId'));

// ── 8. HELLO/WELCOME PoP — source inspection ───────────────────────────
console.log('\n[8] Handshake proof-of-possession');
const netCode = readFileSync(join(base, 'mesh/network.js'), 'utf8');
check('HELLO proof binds nodeId+timestamp+tribhujKey', netCode.includes('YAKMESH:HELLO:${nodeId}:${timestamp}:${tribhujPubKey'));
check('WELCOME proof binds nodeId+timestamp+tribhujKey', netCode.includes('YAKMESH:WELCOME:${ourNodeId}:${welcomeTimestamp}:${ourTribhuj'));
check('HELLO handler verifies proof', netCode.includes('PROOF_OF_POSSESSION_FAILED'));
check('identity binding checked', netCode.includes('generateNodeId(hexToBytes(claimedPubKey))'));
check('timestamp freshness enforced', netCode.includes('Stale handshake timestamp'));
check('ratchet keys pinned on storage', netCode.includes('tribhujKeys'));
check('rotation cert supported', netCode.includes('YAKMESH:TRIBHUJ-KEY'));

console.log(`\n========== ${pass} passed, ${fail} failed ==========`);
process.exit(fail ? 1 : 0);
