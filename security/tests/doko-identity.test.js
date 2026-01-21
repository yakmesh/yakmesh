/**
 * DOKO Identity Tests
 * 
 * Tests for DOKO (Decentralized On-chain Key Ownership) identity system.
 * Verifies iO obfuscation, identity generation, and verification.
 * 
 * @version 2.2.0
 */

import { describe, test, expect, beforeEach } from 'vitest';
import {
  DOKODocument,
  DOKOGenerator,
  DOKO_TYPES,
} from '../doko-identity.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

// ═══════════════════════════════════════════════════════════════════════════
// DOKO DOCUMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('DOKODocument', () => {
  let mockPublicKey;
  
  beforeEach(() => {
    // Create a mock public key (ML-DSA-65 keys are large, so we'll use a hash for testing)
    mockPublicKey = new Uint8Array(32);
    crypto.getRandomValues(mockPublicKey);
  });

  describe('Document Creation', () => {
    test('creates document with correct type', () => {
      const doc = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockPublicKey),
      });
      
      expect(doc.type).toBe(DOKO_TYPES.NODE);
      expect(doc.created).toBeDefined();
      expect(doc.publicKey).toBe(bytesToHex(mockPublicKey));
    });

    test('supports all DOKO types', () => {
      const types = Object.values(DOKO_TYPES);
      expect(types.length).toBeGreaterThan(0);
      
      for (const type of types) {
        const doc = new DOKODocument({
          type,
          publicKey: bytesToHex(mockPublicKey),
        });
        expect(doc.type).toBe(type);
      }
    });
  });

  describe('iO Obfuscation - computeDokoId (CRITICAL)', () => {
    test('computeDokoId returns iO-obfuscated identifier', () => {
      const id = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.NODE);
      
      // MUST start with "doko-" prefix
      expect(id.startsWith('doko-')).toBe(true);
      
      // MUST NOT contain raw hash (64+ hex chars in sequence)
      expect(id).not.toMatch(/[0-9a-f]{32,}/i);
      
      // Should be human-readable format
      expect(id.length).toBeLessThan(60);
    });

    test('iO-obfuscated ID is deterministic', () => {
      const id1 = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.NODE);
      const id2 = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.NODE);
      
      expect(id1).toBe(id2);
    });

    test('different types produce different iO IDs', () => {
      const nodeId = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.NODE);
      const traderId = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.TRADER);
      
      expect(nodeId).not.toBe(traderId);
    });

    test('different keys produce different iO IDs', () => {
      const otherKey = new Uint8Array(32);
      crypto.getRandomValues(otherKey);
      
      const id1 = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.NODE);
      const id2 = DOKODocument.computeDokoId(otherKey, DOKO_TYPES.NODE);
      
      expect(id1).not.toBe(id2);
    });

    test('DOKO ID format is doko-<type>-<name>-<shortId>', () => {
      const id = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.TRADER);
      
      // Should match format: doko-trader-word-word-pq-xxxx (shortId can have mixed case)
      expect(id).toMatch(/^doko-trader-[a-z]+-[a-z]+-pq-[a-zA-Z0-9]+$/);
    });
  });

  describe('Serialization', () => {
    test('toJSON preserves all fields', () => {
      const doc = new DOKODocument({
        type: DOKO_TYPES.TRADER,
        publicKey: bytesToHex(mockPublicKey),
        claims: { reputation: 100 },
      });
      doc.dokoId = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.TRADER);
      
      const json = doc.toJSON();
      
      expect(json.dokoId).toBe(doc.dokoId);
      expect(json.type).toBe(DOKO_TYPES.TRADER);
      expect(json.claims.reputation).toBe(100);
    });

    test('fromJSON reconstructs document', () => {
      const original = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockPublicKey),
      });
      original.dokoId = DOKODocument.computeDokoId(mockPublicKey, DOKO_TYPES.NODE);
      
      const restored = DOKODocument.fromJSON(original.toJSON());
      
      expect(restored.dokoId).toBe(original.dokoId);
      expect(restored.type).toBe(original.type);
      expect(restored.publicKey).toBe(original.publicKey);
    });
  });

  describe('Expiration', () => {
    test('isExpired returns false for valid document', () => {
      const doc = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockPublicKey),
      });
      
      expect(doc.isExpired()).toBe(false);
    });

    test('isExpired returns true for expired document', () => {
      const doc = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockPublicKey),
        created: Date.now() - 400 * 24 * 60 * 60 * 1000, // 400 days ago
        expires: Date.now() - 35 * 24 * 60 * 60 * 1000, // Expired 35 days ago
      });
      
      expect(doc.isExpired()).toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DOKO GENERATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('DOKOGenerator', () => {
  describe('generate()', () => {
    test('generates DOKO with iO-obfuscated ID', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.NODE });
      
      expect(result.doko).toBeInstanceOf(DOKODocument);
      expect(result.doko.dokoId).toBeDefined();
      expect(result.doko.dokoId.startsWith('doko-')).toBe(true);
      expect(result.doko.dokoId).not.toMatch(/[0-9a-f]{32,}/i);
    });

    test('generated DOKO is signed', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.TRADER });
      
      expect(result.doko.signature).toBeDefined();
      expect(result.doko.signature.length).toBeGreaterThan(0);
    });

    test('generated DOKO has valid keys', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      
      expect(result.publicKey).toBeDefined();
      expect(result.secretKey).toBeDefined();
      expect(result.publicKeyHex).toBeDefined();
      expect(result.secretKeyHex).toBeDefined();
    });

    test('generates different DOKOs for different types', () => {
      const node = DOKOGenerator.generate({ type: DOKO_TYPES.NODE });
      const trader = DOKOGenerator.generate({ type: DOKO_TYPES.TRADER });
      
      expect(node.doko.dokoId).not.toBe(trader.doko.dokoId);
      expect(node.doko.type).toBe(DOKO_TYPES.NODE);
      expect(trader.doko.type).toBe(DOKO_TYPES.TRADER);
    });
  });

  describe('generateTrader()', () => {
    test('creates trader DOKO with PeerQuanta claims', () => {
      const result = DOKOGenerator.generateTrader({
        username: 'test_user',
        userId: '12345',
      });
      
      expect(result.doko.type).toBe(DOKO_TYPES.TRADER);
      expect(result.doko.claims.platform).toBe('peerquanta');
      expect(result.doko.claims.username).toBe('test_user');
      expect(result.doko.claims.userId).toBe('12345');
    });

    test('trader DOKO has trading capabilities', () => {
      const result = DOKOGenerator.generateTrader({});
      
      expect(result.doko.extensions.capabilities).toContain('trade');
      expect(result.doko.extensions.capabilities).toContain('escrow');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DOKO TYPES TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('DOKO Types', () => {
  test('DOKO_TYPES contains required types', () => {
    expect(DOKO_TYPES.NODE).toBeDefined();
    expect(DOKO_TYPES.TRADER).toBeDefined();
    expect(DOKO_TYPES.USER).toBeDefined();
    expect(DOKO_TYPES.SERVICE).toBeDefined();
    expect(DOKO_TYPES.DEVICE).toBeDefined();
    expect(DOKO_TYPES.MERCHANT).toBeDefined();
  });

  test('all types are strings', () => {
    for (const [key, value] of Object.entries(DOKO_TYPES)) {
      expect(typeof value).toBe('string');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// iO SECURITY TESTS (CRITICAL)
// ═══════════════════════════════════════════════════════════════════════════

describe('iO Security Verification', () => {
  test('DOKO IDs never expose raw hashes (fingerprint protection)', () => {
    // Generate many DOKO IDs and verify none expose raw hashes
    for (let i = 0; i < 10; i++) {
      const key = new Uint8Array(32);
      crypto.getRandomValues(key);
      
      for (const type of Object.values(DOKO_TYPES)) {
        const id = DOKODocument.computeDokoId(key, type);
        
        // Critical security check: no raw hashes in output
        expect(id).not.toMatch(/[0-9a-f]{16,}/i);
        
        // Must have human-readable format
        expect(id.startsWith('doko-')).toBe(true);
      }
    }
  });

  test('iO obfuscation is irreversible (cannot derive key from DOKO ID)', () => {
    const secretKey = new Uint8Array(32);
    // Fill with a pattern
    for (let i = 0; i < 32; i++) {
      secretKey[i] = i * 7;
    }
    
    const id = DOKODocument.computeDokoId(secretKey, DOKO_TYPES.NODE);
    
    // The key bytes should not appear anywhere in the DOKO ID
    const keyHex = bytesToHex(secretKey);
    expect(id.toLowerCase()).not.toContain(keyHex.slice(0, 8));
  });

  test('DOKO IDs are consistent (same input = same output)', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    
    const ids = [];
    for (let i = 0; i < 5; i++) {
      ids.push(DOKODocument.computeDokoId(key, DOKO_TYPES.NODE));
    }
    
    // All IDs should be identical
    expect(new Set(ids).size).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SSL/TLS CERTIFICATE BINDING TESTS
// ═══════════════════════════════════════════════════════════════════════════

import { DOKOCertBinding } from '../doko-identity.js';

describe('DOKOCertBinding', () => {
  let mockCertDER;
  let mockPEM;
  
  beforeEach(() => {
    // Create mock certificate data (just random bytes for testing)
    mockCertDER = new Uint8Array(256);
    crypto.getRandomValues(mockCertDER);
    
    // Create mock PEM format
    mockPEM = `-----BEGIN CERTIFICATE-----
${Buffer.from(mockCertDER).toString('base64')}
-----END CERTIFICATE-----`;
  });

  describe('Fingerprint Computation', () => {
    test('computes fingerprint from DER bytes', () => {
      const fp = DOKOCertBinding.computeFingerprint(Buffer.from(mockCertDER));
      
      // Should be 64 hex characters (SHA-256)
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    test('computes fingerprint from PEM string', () => {
      const fp = DOKOCertBinding.computeFingerprint(mockPEM);
      
      // Should be 64 hex characters
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    test('PEM and DER produce same fingerprint', () => {
      const fpDER = DOKOCertBinding.computeFingerprint(Buffer.from(mockCertDER));
      const fpPEM = DOKOCertBinding.computeFingerprint(mockPEM);
      
      expect(fpDER).toBe(fpPEM);
    });

    test('fingerprint is deterministic', () => {
      const fp1 = DOKOCertBinding.computeFingerprint(mockPEM);
      const fp2 = DOKOCertBinding.computeFingerprint(mockPEM);
      
      expect(fp1).toBe(fp2);
    });

    test('different certs produce different fingerprints', () => {
      const otherCert = new Uint8Array(256);
      crypto.getRandomValues(otherCert);
      
      const fp1 = DOKOCertBinding.computeFingerprint(Buffer.from(mockCertDER));
      const fp2 = DOKOCertBinding.computeFingerprint(Buffer.from(otherCert));
      
      expect(fp1).not.toBe(fp2);
    });
  });

  describe('Binding Creation', () => {
    test('creates binding with required fields', () => {
      const fp = DOKOCertBinding.computeFingerprint(mockPEM);
      
      const binding = DOKOCertBinding.createBinding({
        domain: 'example.com',
        fingerprint: fp,
      });
      
      expect(binding.domain).toBe('example.com');
      expect(binding.fingerprint).toBe(fp);
      expect(binding.boundAt).toBeDefined();
      expect(binding.verified).toBe(false);
    });

    test('creates binding with optional fields', () => {
      const fp = DOKOCertBinding.computeFingerprint(mockPEM);
      const now = Date.now();
      
      const binding = DOKOCertBinding.createBinding({
        domain: 'example.com',
        fingerprint: fp,
        issuer: "Let's Encrypt",
        validFrom: now,
        validTo: now + 90 * 24 * 60 * 60 * 1000, // 90 days
      });
      
      expect(binding.issuer).toBe("Let's Encrypt");
      expect(binding.validFrom).toBe(now);
      expect(binding.validTo).toBeGreaterThan(now);
    });

    test('throws on missing required fields', () => {
      expect(() => DOKOCertBinding.createBinding({})).toThrow();
      expect(() => DOKOCertBinding.createBinding({ domain: 'test.com' })).toThrow();
    });

    test('normalizes domain to lowercase', () => {
      const binding = DOKOCertBinding.createBinding({
        domain: 'EXAMPLE.COM',
        fingerprint: 'abc123',
      });
      
      expect(binding.domain).toBe('example.com');
    });
  });

  describe('Binding Management', () => {
    let doko;
    let binding;
    
    beforeEach(() => {
      const mockKey = new Uint8Array(32);
      crypto.getRandomValues(mockKey);
      
      doko = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockKey),
      });
      
      const fp = DOKOCertBinding.computeFingerprint(mockPEM);
      binding = DOKOCertBinding.createBinding({
        domain: 'test.yakmesh.com',
        fingerprint: fp,
      });
    });

    test('adds binding to DOKO document', () => {
      DOKOCertBinding.addBinding(doko, binding);
      
      const bindings = DOKOCertBinding.getBindings(doko);
      expect(bindings.length).toBe(1);
      expect(bindings[0].domain).toBe('test.yakmesh.com');
    });

    test('invalidates signature when adding binding', () => {
      doko.signature = 'fake-signature';
      DOKOCertBinding.addBinding(doko, binding);
      
      expect(doko.signature).toBeNull();
    });

    test('updates existing binding for same domain', () => {
      DOKOCertBinding.addBinding(doko, binding);
      
      const newBinding = DOKOCertBinding.createBinding({
        domain: 'test.yakmesh.com',
        fingerprint: 'new-fingerprint',
      });
      DOKOCertBinding.addBinding(doko, newBinding);
      
      const bindings = DOKOCertBinding.getBindings(doko);
      expect(bindings.length).toBe(1);
      expect(bindings[0].fingerprint).toBe('new-fingerprint');
    });

    test('retrieves binding for specific domain', () => {
      DOKOCertBinding.addBinding(doko, binding);
      
      const found = DOKOCertBinding.getBindingForDomain(doko, 'test.yakmesh.com');
      expect(found).toBeDefined();
      expect(found.domain).toBe('test.yakmesh.com');
      
      const notFound = DOKOCertBinding.getBindingForDomain(doko, 'other.com');
      expect(notFound).toBeNull();
    });

    test('removes binding by domain', () => {
      DOKOCertBinding.addBinding(doko, binding);
      expect(DOKOCertBinding.getBindings(doko).length).toBe(1);
      
      const removed = DOKOCertBinding.removeBinding(doko, 'test.yakmesh.com');
      expect(removed).toBe(true);
      expect(DOKOCertBinding.getBindings(doko).length).toBe(0);
    });

    test('removeBinding returns false for non-existent domain', () => {
      const removed = DOKOCertBinding.removeBinding(doko, 'nonexistent.com');
      expect(removed).toBe(false);
    });
  });

  describe('Binding Verification', () => {
    test('verifyBinding passes for matching cert', () => {
      const fp = DOKOCertBinding.computeFingerprint(mockPEM);
      const binding = DOKOCertBinding.createBinding({
        domain: 'example.com',
        fingerprint: fp,
      });
      
      const result = DOKOCertBinding.verifyBinding(binding, mockPEM);
      expect(result.valid).toBe(true);
      expect(result.reason).toBe('FINGERPRINT_MATCH');
    });

    test('verifyBinding fails for non-matching cert', () => {
      const fp = DOKOCertBinding.computeFingerprint(mockPEM);
      const binding = DOKOCertBinding.createBinding({
        domain: 'example.com',
        fingerprint: fp,
      });
      
      const otherCert = new Uint8Array(256);
      crypto.getRandomValues(otherCert);
      
      const result = DOKOCertBinding.verifyBinding(binding, Buffer.from(otherCert));
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('FINGERPRINT_MISMATCH');
    });
  });

  describe('Bindings Validation', () => {
    test('validateBindings returns valid for good bindings', () => {
      const mockKey = new Uint8Array(32);
      crypto.getRandomValues(mockKey);
      
      const doko = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockKey),
      });
      
      const now = Date.now();
      const binding = DOKOCertBinding.createBinding({
        domain: 'example.com',
        fingerprint: 'abc123',
        validFrom: now - 1000,
        validTo: now + 1000000,
      });
      
      DOKOCertBinding.addBinding(doko, binding);
      
      const result = DOKOCertBinding.validateBindings(doko);
      expect(result.valid).toBe(true);
      expect(result.count).toBe(1);
    });

    test('validateBindings detects expired certificates', () => {
      const mockKey = new Uint8Array(32);
      crypto.getRandomValues(mockKey);
      
      const doko = new DOKODocument({
        type: DOKO_TYPES.NODE,
        publicKey: bytesToHex(mockKey),
      });
      
      const now = Date.now();
      const binding = DOKOCertBinding.createBinding({
        domain: 'expired.com',
        fingerprint: 'abc123',
        validTo: now - 1000, // Already expired
      });
      
      DOKOCertBinding.addBinding(doko, binding);
      
      const result = DOKOCertBinding.validateBindings(doko);
      expect(result.valid).toBe(false);
      expect(result.bindings[0].reason).toBe('CERTIFICATE_EXPIRED');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DOKO TRANSFER TESTS
// ═══════════════════════════════════════════════════════════════════════════

import { DOKOTransfer } from '../doko-identity.js';

describe('DOKOTransfer', () => {
  describe('Transfer Request Creation', () => {
    test('creates transfer request with required fields', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'yakmesh.yak',
        fromDoko: 'doko-node-alpha-beta-pq-1234',
        toDoko: 'doko-node-gamma-delta-pq-5678',
      });
      
      expect(request.type).toBe(DOKOTransfer.TYPES.DOMAIN);
      expect(request.assetId).toBe('yakmesh.yak');
      expect(request.fromDoko).toBe('doko-node-alpha-beta-pq-1234');
      expect(request.toDoko).toBe('doko-node-gamma-delta-pq-5678');
      expect(request.state).toBe(DOKOTransfer.STATES.PENDING);
      expect(request.requestId).toMatch(/^xfer-[a-f0-9]{16}$/);
    });

    test('request ID includes timestamp for uniqueness', () => {
      const options = {
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'test.yak',
        fromDoko: 'doko-a',
        toDoko: 'doko-b',
      };
      
      const req1 = DOKOTransfer.createRequest(options);
      // Small delay to ensure different timestamp
      const start = Date.now();
      while (Date.now() === start) { /* spin until next ms */ }
      const req2 = DOKOTransfer.createRequest(options);
      
      // Different timestamps = different IDs (prevents replay attacks)
      expect(req1.requestId).not.toBe(req2.requestId);
      // Both should have valid format
      expect(req1.requestId).toMatch(/^xfer-[a-f0-9]{16}$/);
      expect(req2.requestId).toMatch(/^xfer-[a-f0-9]{16}$/);
    });

    test('throws on missing required fields', () => {
      expect(() => DOKOTransfer.createRequest({})).toThrow();
      expect(() => DOKOTransfer.createRequest({ type: 'domain' })).toThrow();
    });

    test('sets default expiration to 7 days', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'test.yak',
        fromDoko: 'doko-a',
        toDoko: 'doko-b',
      });
      
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      expect(request.expiresAt - request.requestedAt).toBe(sevenDays);
    });

    test('allows custom expiration', () => {
      const oneDay = 24 * 60 * 60 * 1000;
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'test.yak',
        fromDoko: 'doko-a',
        toDoko: 'doko-b',
        expiresIn: oneDay,
      });
      
      expect(request.expiresAt - request.requestedAt).toBe(oneDay);
    });
  });

  describe('Transfer States', () => {
    let request;
    
    beforeEach(() => {
      request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'state-test.yak',
        fromDoko: 'doko-owner',
        toDoko: 'doko-newowner',
      });
    });

    test('authorize changes state to AUTHORIZED', () => {
      const mockSignature = new Uint8Array(32);
      crypto.getRandomValues(mockSignature);
      
      const authorized = DOKOTransfer.authorize(request, mockSignature, 'node-owner');
      
      expect(authorized.state).toBe(DOKOTransfer.STATES.AUTHORIZED);
      expect(authorized.authorization.signature).toBeDefined();
      expect(authorized.authorization.fromNodeId).toBe('node-owner');
    });

    test('reject changes state to REJECTED', () => {
      const rejected = DOKOTransfer.reject(request, 'Not authorized by me');
      
      expect(rejected.state).toBe(DOKOTransfer.STATES.REJECTED);
      expect(rejected.rejection.reason).toBe('Not authorized by me');
    });

    test('cancel changes state to CANCELLED', () => {
      const cancelled = DOKOTransfer.cancel(request);
      
      expect(cancelled.state).toBe(DOKOTransfer.STATES.CANCELLED);
      expect(cancelled.cancelledAt).toBeDefined();
    });

    test('cannot authorize already rejected transfer', () => {
      const rejected = DOKOTransfer.reject(request, 'No');
      
      expect(() => {
        DOKOTransfer.authorize(rejected, new Uint8Array(32), 'node');
      }).toThrow();
    });

    test('cannot cancel already authorized transfer', () => {
      const authorized = DOKOTransfer.authorize(request, new Uint8Array(32), 'node');
      
      expect(() => {
        DOKOTransfer.cancel(authorized);
      }).toThrow();
    });
  });

  describe('Transfer Completion', () => {
    test('completes authorized transfer with proof', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'complete-test.yak',
        fromDoko: 'doko-old',
        toDoko: 'doko-new',
      });
      
      const authorized = DOKOTransfer.authorize(request, new Uint8Array(32), 'node-old');
      const completed = DOKOTransfer.complete(authorized, 'node-new');
      
      expect(completed.state).toBe(DOKOTransfer.STATES.COMPLETED);
      expect(completed.completion.toNodeId).toBe('node-new');
      expect(completed.completion.proofHash).toMatch(/^[a-f0-9]{64}$/);
    });

    test('cannot complete pending transfer', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'test.yak',
        fromDoko: 'doko-a',
        toDoko: 'doko-b',
      });
      
      expect(() => {
        DOKOTransfer.complete(request, 'node-b');
      }).toThrow();
    });
  });

  describe('Transfer Proof', () => {
    test('creates transfer proof from completed transfer', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.WEBSITE,
        assetId: 'abc123hash',
        fromDoko: 'doko-publisher',
        toDoko: 'doko-newpublisher',
      });
      
      const authorized = DOKOTransfer.authorize(request, new Uint8Array(64), 'node-pub');
      const completed = DOKOTransfer.complete(authorized, 'node-newpub');
      const proof = DOKOTransfer.createProof(completed);
      
      expect(proof.type).toBe('DOKO_TRANSFER_PROOF');
      expect(proof.version).toBe('1.0');
      expect(proof.assetId).toBe('abc123hash');
      expect(proof.fromDoko).toBe('doko-publisher');
      expect(proof.toDoko).toBe('doko-newpublisher');
    });

    test('validates well-formed proof', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'valid.yak',
        fromDoko: 'doko-a',
        toDoko: 'doko-b',
      });
      
      const authorized = DOKOTransfer.authorize(request, new Uint8Array(32), 'node-a');
      const completed = DOKOTransfer.complete(authorized, 'node-b');
      const proof = DOKOTransfer.createProof(completed);
      
      const result = DOKOTransfer.validateProof(proof);
      
      expect(result.valid).toBe(true);
      expect(result.checks.every(c => c.valid)).toBe(true);
    });

    test('invalidates proof with missing fields', () => {
      const invalidProof = {
        type: 'DOKO_TRANSFER_PROOF',
        requestId: 'xfer-123',
        // Missing other required fields
      };
      
      const result = DOKOTransfer.validateProof(invalidProof);
      
      expect(result.valid).toBe(false);
    });

    test('cannot create proof for non-completed transfer', () => {
      const request = DOKOTransfer.createRequest({
        type: DOKOTransfer.TYPES.DOMAIN,
        assetId: 'test.yak',
        fromDoko: 'doko-a',
        toDoko: 'doko-b',
      });
      
      expect(() => {
        DOKOTransfer.createProof(request);
      }).toThrow();
    });
  });

  describe('Transfer Types', () => {
    test('supports domain transfer type', () => {
      expect(DOKOTransfer.TYPES.DOMAIN).toBe('domain');
    });

    test('supports website transfer type', () => {
      expect(DOKOTransfer.TYPES.WEBSITE).toBe('website');
    });

    test('supports asset transfer type', () => {
      expect(DOKOTransfer.TYPES.ASSET).toBe('asset');
    });
  });
});

// ============================================================
// DOKO REVOCATION TESTS (v2.2.0)
// ============================================================

import { DOKORevocation, REVOCATION_REASONS } from '../doko-identity.js';

describe('DOKORevocation', () => {
  // Create test keys for each test
  let testKeypair;
  let testDoko;
  
  beforeEach(() => {
    // Clear revocations between tests
    DOKORevocation._clear();
    
    // Generate test keypair
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    testKeypair = ml_dsa65.keygen(seed);
    
    // Create test DOKO document
    testDoko = {
      dokoId: 'doko-test-' + Date.now(),
      type: 'user',
      publicKey: bytesToHex(testKeypair.publicKey),
    };
  });
  
  describe('REVOCATION_REASONS', () => {
    test('exports key_compromised reason', () => {
      expect(REVOCATION_REASONS.KEY_COMPROMISED).toBe('key_compromised');
    });
    
    test('exports doko_superseded reason', () => {
      expect(REVOCATION_REASONS.DOKO_SUPERSEDED).toBe('doko_superseded');
    });
    
    test('exports identity_retired reason', () => {
      expect(REVOCATION_REASONS.IDENTITY_RETIRED).toBe('identity_retired');
    });
    
    test('exports lost_access reason', () => {
      expect(REVOCATION_REASONS.LOST_ACCESS).toBe('lost_access');
    });
    
    test('exports affiliation_ended reason', () => {
      expect(REVOCATION_REASONS.AFFILIATION_ENDED).toBe('affiliation_ended');
    });
  });
  
  describe('Self-Revocation', () => {
    test('creates self-revocation certificate', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.KEY_COMPROMISED
      );
      
      expect(cert).toBeDefined();
      expect(cert.version).toBe('1.0');
      expect(cert.type).toBe('self');
      expect(cert.dokoId).toBe(testDoko.dokoId);
      expect(cert.reason).toBe(REVOCATION_REASONS.KEY_COMPROMISED);
      expect(cert.revokedAt).toBeDefined();
      expect(cert.signature).toMatch(/^[a-f0-9]+$/);
      expect(cert.signatureAlgorithm).toBe('ML-DSA-65');
    });
    
    test('stores revocation after creation', () => {
      DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.IDENTITY_RETIRED
      );
      
      const status = DOKORevocation.isRevoked(testDoko.dokoId);
      expect(status.revoked).toBe(true);
      expect(status.reason).toBe(REVOCATION_REASONS.IDENTITY_RETIRED);
    });
    
    test('includes optional message', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.DOKO_SUPERSEDED,
        { message: 'Replaced with quantum-resistant key' }
      );
      
      expect(cert.message).toBe('Replaced with quantum-resistant key');
    });
    
    test('includes successor DOKO ID', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.DOKO_SUPERSEDED,
        { successorDokoId: 'doko-new-12345' }
      );
      
      expect(cert.successorDokoId).toBe('doko-new-12345');
    });
  });
  
  describe('Emergency Revocation', () => {
    test('generates emergency certificate', () => {
      const emergencyCert = DOKORevocation.generateEmergencyCertificate(
        testDoko,
        testKeypair.secretKey
      );
      
      expect(emergencyCert).toBeDefined();
      expect(emergencyCert.dokoId).toBe(testDoko.dokoId);
      expect(emergencyCert.emergencyToken).toMatch(/^[a-f0-9]{64}$/);
      expect(emergencyCert.signature).toBeDefined();
      expect(emergencyCert._warning).toContain('STORE THIS OFFLINE');
    });
    
    test('activates emergency revocation', () => {
      const emergencyCert = DOKORevocation.generateEmergencyCertificate(
        testDoko,
        testKeypair.secretKey
      );
      
      const activated = DOKORevocation.activateEmergencyRevocation(emergencyCert);
      
      expect(activated.type).toBe('emergency');
      expect(activated.dokoId).toBe(testDoko.dokoId);
      expect(activated.reason).toBe(REVOCATION_REASONS.KEY_COMPROMISED);
      expect(activated.activatedAt).toBeDefined();
    });
    
    test('marks DOKO as revoked after emergency activation', () => {
      const emergencyCert = DOKORevocation.generateEmergencyCertificate(
        testDoko,
        testKeypair.secretKey
      );
      
      DOKORevocation.activateEmergencyRevocation(emergencyCert);
      
      const status = DOKORevocation.isRevoked(testDoko.dokoId);
      expect(status.revoked).toBe(true);
    });
    
    test('rejects invalid emergency certificate', () => {
      expect(() => {
        DOKORevocation.activateEmergencyRevocation(null);
      }).toThrow('Invalid emergency certificate');
      
      expect(() => {
        DOKORevocation.activateEmergencyRevocation({});
      }).toThrow('Invalid emergency certificate');
    });
  });
  
  describe('Verification', () => {
    test('verifies valid self-revocation', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.KEY_COMPROMISED
      );
      
      const result = DOKORevocation.verify(cert, testDoko.publicKey);
      expect(result.valid).toBe(true);
    });
    
    test('rejects certificate without signature', () => {
      const result = DOKORevocation.verify({}, testDoko.publicKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('MISSING_SIGNATURE');
    });
    
    test('rejects tampered certificate', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.KEY_COMPROMISED
      );
      
      // Tamper with the certificate
      cert.reason = REVOCATION_REASONS.LOST_ACCESS;
      
      const result = DOKORevocation.verify(cert, testDoko.publicKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('INVALID_SIGNATURE');
    });
    
    test('rejects certificate with wrong public key', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.KEY_COMPROMISED
      );
      
      // Use a different keypair
      const seed2 = new Uint8Array(32);
      crypto.getRandomValues(seed2);
      const otherKeypair = ml_dsa65.keygen(seed2);
      
      const result = DOKORevocation.verify(cert, bytesToHex(otherKeypair.publicKey));
      expect(result.valid).toBe(false);
    });
  });
  
  describe('Revocation Status', () => {
    test('returns not revoked for unknown DOKO', () => {
      const status = DOKORevocation.isRevoked('unknown-doko-id');
      expect(status.revoked).toBe(false);
      expect(status.certificate).toBeNull();
    });
    
    test('returns revocation details for revoked DOKO', () => {
      DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.KEY_COMPROMISED
      );
      
      const status = DOKORevocation.isRevoked(testDoko.dokoId);
      expect(status.revoked).toBe(true);
      expect(status.certificate).toBeDefined();
      expect(status.reason).toBe(REVOCATION_REASONS.KEY_COMPROMISED);
      expect(status.revokedAt).toBeDefined();
    });
  });
  
  describe('Add Revocation', () => {
    test('adds valid revocation from external source', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.IDENTITY_RETIRED
      );
      
      // Clear and re-add
      DOKORevocation._clear();
      
      const result = DOKORevocation.addRevocation(cert, testDoko.publicKey);
      expect(result.success).toBe(true);
      
      const status = DOKORevocation.isRevoked(testDoko.dokoId);
      expect(status.revoked).toBe(true);
    });
    
    test('rejects invalid revocation', () => {
      const result = DOKORevocation.addRevocation({
        dokoId: 'fake-doko',
        signature: 'invalid',
      }, testDoko.publicKey);
      
      expect(result.success).toBe(false);
    });
  });
  
  describe('List and Export', () => {
    test('lists all revocations', () => {
      // Create multiple test DOKOs and revoke them
      const doko2 = { dokoId: 'doko-test-2', type: 'trader', publicKey: testDoko.publicKey };
      
      DOKORevocation.createSelfRevocation(testDoko, testKeypair.secretKey, REVOCATION_REASONS.KEY_COMPROMISED);
      DOKORevocation.createSelfRevocation(doko2, testKeypair.secretKey, REVOCATION_REASONS.IDENTITY_RETIRED);
      
      const list = DOKORevocation.listRevocations();
      expect(list.length).toBe(2);
    });
    
    test('exports revocations for sync', () => {
      DOKORevocation.createSelfRevocation(testDoko, testKeypair.secretKey, REVOCATION_REASONS.KEY_COMPROMISED);
      
      const exported = DOKORevocation.export();
      expect(Array.isArray(exported)).toBe(true);
      expect(exported.length).toBe(1);
      expect(exported[0].dokoId).toBe(testDoko.dokoId);
    });
  });
  
  describe('Import Revocations', () => {
    test('imports revocations with verification', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.LOST_ACCESS
      );
      
      // Clear and import
      DOKORevocation._clear();
      
      const result = DOKORevocation.import(
        [cert],
        { [testDoko.dokoId]: testDoko.publicKey }
      );
      
      expect(result.imported).toBe(1);
      expect(result.failed).toBe(0);
    });
    
    test('fails import without public key', () => {
      const cert = DOKORevocation.createSelfRevocation(
        testDoko,
        testKeypair.secretKey,
        REVOCATION_REASONS.KEY_COMPROMISED
      );
      
      DOKORevocation._clear();
      
      const result = DOKORevocation.import([cert], {});
      expect(result.failed).toBe(1);
    });
  });
  
  describe('Statistics', () => {
    test('returns revocation statistics', () => {
      DOKORevocation.createSelfRevocation(testDoko, testKeypair.secretKey, REVOCATION_REASONS.KEY_COMPROMISED);
      
      const stats = DOKORevocation.getStats();
      expect(stats.total).toBe(1);
      expect(stats.byReason[REVOCATION_REASONS.KEY_COMPROMISED]).toBe(1);
      expect(stats.byType['self']).toBe(1);
    });
    
    test('returns empty stats when no revocations', () => {
      const stats = DOKORevocation.getStats();
      expect(stats.total).toBe(0);
    });
  });
  
  describe('Clear', () => {
    test('clears all revocations', () => {
      DOKORevocation.createSelfRevocation(testDoko, testKeypair.secretKey, REVOCATION_REASONS.KEY_COMPROMISED);
      expect(DOKORevocation.listRevocations().length).toBe(1);
      
      DOKORevocation._clear();
      expect(DOKORevocation.listRevocations().length).toBe(0);
    });
  });
});