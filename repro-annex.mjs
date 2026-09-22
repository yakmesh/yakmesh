// Reproduce the bootstrap-session decrypt failure seen live between rc11 nodes.
import Annex, { AnnexSession } from './mesh/annex.js';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';

const fakeIdentity = (id) => ({ identity: { nodeId: id }, sign: () => 'x'.repeat(64), verify: () => true });

const A = 'node-einstein-heisen-layer-pq-YG22';
const B = 'node-einstein-heisen-layer-pq-Rwd1';

// Simulate jhilke.deriveBootstrapKey — symmetric by construction
const ikm = randomBytes(32); // shared codeHash+buildNonce product
const sorted = [A, B].sort();
const { sha3_256 } = await import('@noble/hashes/sha3.js');
const { hkdf } = await import('@noble/hashes/hkdf.js');
const { utf8ToBytes } = await import('@noble/hashes/utils.js');
const salt = utf8ToBytes(`yakmesh-jhilke-bootstrap:${sorted[0]}:${sorted[1]}`);
const pairKey = Buffer.from(hkdf(sha3_256, ikm, salt, utf8ToBytes('bootstrap'), 32));

const annexA = new Annex({ identity: fakeIdentity(A) });
const annexB = new Annex({ identity: fakeIdentity(B) });

const sessA = annexA.bootstrapSession(B, pairKey);
const sessB = annexB.bootstrapSession(A, pairKey);

console.log('sessionIds:', sessA.sessionId.slice(0,8), sessB.sessionId.slice(0,8), 'equal:', sessA.sessionId === sessB.sessionId);
console.log('keys equal:', Buffer.compare(sessA.encryptionKey, sessB.encryptionKey) === 0);

const msg = sessA.encrypt('hello from A');
try {
  const out = sessB.decrypt(msg, msg.sequence);
  console.log('BOOTSTRAP DECRYPT OK:', out);
} catch (e) {
  console.log('BOOTSTRAP DECRYPT FAIL:', e.message);
}
