/**
 * TLS Binding Tests
 * 
 * Tests for DOKO-to-X.509 certificate binding and mTLS support.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { DOKOCertificateGenerator, TLSVerifier, TLSCapabilityAdvertiser } from '../tls-binding.js';

// ═══════════════════════════════════════════════════════════════════════════
// TEST UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a mock node identity
 */
function createMockIdentity(nodeId = 'node-yakmesh-abc123def456') {
  return {
    identity: {
      nodeId,
      publicKey: `pk-${nodeId}`,
    },
  };
}

/**
 * Create a mock DOKO
 */
function createMockDoko(nodeId = 'node-yakmesh-abc123def456') {
  return {
    version: '1.0',
    type: 'DOKO',
    nodeId,
    publicKey: `pk-${nodeId}`,
    networkName: 'yakmesh',
    issuedAt: Date.now(),
    expiresAt: Date.now() + (365 * 24 * 60 * 60 * 1000),
    signature: 'sig-valid',
  };
}

/**
 * Create a mock NAMCHE gateway
 */
function createMockGateway(verifyResult = { passed: true, gatesChecked: 7 }) {
  return {
    verify: vi.fn().mockResolvedValue(verifyResult),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// DOKO CERTIFICATE GENERATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('DOKOCertificateGenerator', () => {
  let identity;
  let doko;
  let generator;

  beforeEach(() => {
    identity = createMockIdentity();
    doko = createMockDoko();
    generator = new DOKOCertificateGenerator(identity, doko);
  });

  describe('Certificate Generation', () => {
    test('generates valid X.509 certificate', async () => {
      const result = await generator.generate();
      
      expect(result.certificate).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.fingerprint).toBeDefined();
      expect(result.nodeId).toBe(doko.nodeId);
    });

    test('certificate contains PEM format data', async () => {
      const result = await generator.generate();
      
      expect(result.certificate).toContain('-----BEGIN CERTIFICATE-----');
      expect(result.certificate).toContain('-----END CERTIFICATE-----');
      expect(result.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
    });

    test('generates correct fingerprint format', async () => {
      const result = await generator.generate();
      
      expect(result.fingerprint).toMatch(/^sha256:[a-f0-9]+$/);
    });

    test('certificate has correct validity period', async () => {
      const beforeGen = Date.now();
      const result = await generator.generate();
      const afterGen = Date.now();
      
      expect(result.issuedAt).toBeGreaterThanOrEqual(beforeGen);
      expect(result.issuedAt).toBeLessThanOrEqual(afterGen);
      
      // Default 365 days validity
      const expectedExpiry = result.issuedAt + (365 * 24 * 60 * 60 * 1000);
      expect(result.expiresAt).toBeCloseTo(expectedExpiry, -3);  // Within 1 second
    });

    test('includes DOKO hash in certificate', async () => {
      const result = await generator.generate();
      
      expect(result.dokoHash).toBeDefined();
      expect(result.dokoHash).toHaveLength(64);  // SHA3-256 hex
    });
  });

  describe('Certificate Renewal', () => {
    test('needsRenewal returns true before generation', () => {
      expect(generator.needsRenewal()).toBe(true);
    });

    test('needsRenewal returns false after generation', async () => {
      await generator.generate();
      expect(generator.needsRenewal()).toBe(false);
    });

    test('needsRenewal returns true within renewal threshold', async () => {
      // Generate with very short validity
      generator.config.certValidityDays = 1;
      generator.config.certRenewalThreshold = 1;  // Renew 1 day before (always)
      
      await generator.generate();
      
      // Should need renewal since we're within threshold
      expect(generator.needsRenewal()).toBe(true);
    });
  });

  describe('TLS Options', () => {
    test('getTLSServerOptions returns correct structure', async () => {
      await generator.generate();
      const options = generator.getTLSServerOptions();
      
      expect(options.key).toBeDefined();
      expect(options.cert).toBeDefined();
      expect(options.requestCert).toBe(true);
      expect(options.rejectUnauthorized).toBe(false);
    });

    test('getTLSClientOptions returns correct structure', async () => {
      await generator.generate();
      const options = generator.getTLSClientOptions();
      
      expect(options.key).toBeDefined();
      expect(options.cert).toBeDefined();
      expect(options.rejectUnauthorized).toBe(false);
    });

    test('throws if options requested before generation', () => {
      expect(() => generator.getTLSServerOptions()).toThrow('Certificate not generated');
      expect(() => generator.getTLSClientOptions()).toThrow('Certificate not generated');
    });
  });

  describe('DOKO TLS Binding', () => {
    test('toDokoTLSBinding returns correct structure', async () => {
      await generator.generate();
      const binding = generator.toDokoTLSBinding();
      
      expect(binding.certFingerprint).toBeDefined();
      expect(binding.certIssuedAt).toBeDefined();
      expect(binding.certExpiresAt).toBeDefined();
      expect(binding.supports).toEqual({
        tls13: true,
        mlkem: false,
        hybridKeyExchange: false,
        mTLS: true,
      });
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// TLS VERIFIER TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('TLSVerifier', () => {
  let gateway;
  let verifier;
  let generator;
  let doko;

  beforeEach(async () => {
    gateway = createMockGateway();
    verifier = new TLSVerifier(gateway);
    
    doko = createMockDoko();
    generator = new DOKOCertificateGenerator(createMockIdentity(), doko);
    await generator.generate();
  });

  describe('Certificate Verification', () => {
    test('verifies valid certificate against DOKO', async () => {
      const result = await verifier.verify(generator.certificate, doko);
      
      expect(result.verified).toBe(true);
      expect(result.nodeId).toBe(doko.nodeId);
    });

    test('fails if DOKO verification fails', async () => {
      gateway.verify.mockResolvedValue({ passed: false, reason: 'Invalid signature' });
      
      const result = await verifier.verify(generator.certificate, doko);
      
      expect(result.verified).toBe(false);
      expect(result.stage).toBe('doko-verification');
    });

    test('fails if nodeId mismatch', async () => {
      const wrongDoko = createMockDoko('node-different-xyz789');
      
      const result = await verifier.verify(generator.certificate, wrongDoko);
      
      expect(result.verified).toBe(false);
      expect(result.stage).toBe('nodeid-match');
    });

    test('tracks verification statistics', async () => {
      await verifier.verify(generator.certificate, doko);
      await verifier.verify(generator.certificate, doko);
      
      const stats = verifier.getStats();
      
      expect(stats.verificationsPerformed).toBe(2);
      expect(stats.verificationsPassed).toBe(2);
    });
  });

  describe('Certificate Pinning', () => {
    test('pins certificate after first verification', () => {
      verifier.pin(doko.nodeId, generator.certificate, doko);
      
      const stats = verifier.getStats();
      expect(stats.pinnedNodes).toBe(1);
    });

    test('checkPin returns firstContact for unknown nodes', () => {
      const result = verifier.checkPin('unknown-node', generator.certificate);
      
      expect(result.ok).toBe(true);
      expect(result.firstContact).toBe(true);
    });

    test('checkPin succeeds for matching pinned certificate', () => {
      verifier.pin(doko.nodeId, generator.certificate, doko);
      
      const result = verifier.checkPin(doko.nodeId, generator.certificate);
      
      expect(result.ok).toBe(true);
      expect(result.pinned).toBe(true);
    });

    test('checkPin fails for non-matching certificate', async () => {
      verifier.pin(doko.nodeId, generator.certificate, doko);
      
      // Generate a different certificate
      const otherGenerator = new DOKOCertificateGenerator(
        createMockIdentity(), 
        createMockDoko()
      );
      await otherGenerator.generate();
      
      const result = verifier.checkPin(doko.nodeId, otherGenerator.certificate);
      
      expect(result.ok).toBe(false);
      expect(result.error).toContain('fingerprint');
    });

    test('unpin removes certificate pin', () => {
      verifier.pin(doko.nodeId, generator.certificate, doko);
      expect(verifier.getStats().pinnedNodes).toBe(1);
      
      verifier.unpin(doko.nodeId);
      expect(verifier.getStats().pinnedNodes).toBe(0);
    });
  });

  describe('Persistence', () => {
    test('serializes and restores pins', async () => {
      verifier.pin(doko.nodeId, generator.certificate, doko);
      
      const serialized = verifier.serializePins();
      
      expect(serialized.version).toBe(1);
      expect(serialized.pins.length).toBe(1);
      
      // Create new verifier and restore
      const newVerifier = new TLSVerifier(gateway);
      newVerifier.restorePins(serialized);
      
      expect(newVerifier.getStats().pinnedNodes).toBe(1);
    });
  });

  describe('Utility Functions', () => {
    test('extractNodeId extracts from PEM certificate', () => {
      const nodeId = verifier.extractNodeId(generator.certificate);
      expect(nodeId).toBe(doko.nodeId);
    });

    test('computeCertFingerprint returns consistent hash', () => {
      const fp1 = verifier.computeCertFingerprint(generator.certificate);
      const fp2 = verifier.computeCertFingerprint(generator.certificate);
      
      expect(fp1).toBe(fp2);
      expect(fp1).toMatch(/^sha256:/);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// TLS CAPABILITY ADVERTISER TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('TLSCapabilityAdvertiser', () => {
  test('returns TLS info for beacon', async () => {
    const doko = createMockDoko();
    const generator = new DOKOCertificateGenerator(createMockIdentity(), doko);
    await generator.generate();
    
    const advertiser = new TLSCapabilityAdvertiser(generator);
    const info = advertiser.getBeaconTLSInfo();
    
    expect(info.tlsEnabled).toBe(true);
    expect(info.mtlsSupported).toBe(true);
    expect(info.certFingerprint).toBeDefined();
    expect(info.features.tls13).toBe(true);
  });

  test('returns disabled when no certificate', () => {
    const doko = createMockDoko();
    const generator = new DOKOCertificateGenerator(createMockIdentity(), doko);
    // Don't generate certificate
    
    const advertiser = new TLSCapabilityAdvertiser(generator);
    const info = advertiser.getBeaconTLSInfo();
    
    expect(info.tlsEnabled).toBe(false);
    expect(info.mtlsSupported).toBe(false);
  });
});
