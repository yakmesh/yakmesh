/**
 * TLS Binding - DOKO-to-X.509 Certificate Management for mTLS
 * 
 * Provides functionality to:
 * 1. Generate X.509 certificates bound to DOKO identities
 * 2. Verify TLS certificates against known DOKOs
 * 3. Manage certificate pinning
 * 4. Support optional mTLS for WebSocket connections
 * 
 * Implementation of mTLS Research Phase 1 & 2:
 * - Phase 1: Optional TLS for transport
 * - Phase 2: TLS certificates bound to DOKOs
 * 
 * Security Philosophy:
 * - DOKO proves identity mathematically
 * - mTLS protects the transport layer
 * - Together they provide defense-in-depth
 * 
 * @module security/tls-binding
 * @version 1.0.0
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { EventEmitter } from 'events';
import crypto from 'crypto';
import forge from 'node-forge';

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  // Certificate validity
  certValidityDays: 365,                    // X.509 cert valid for 1 year
  certRenewalThreshold: 30,                  // Renew 30 days before expiry

  // Key settings (for X.509 wrapper - actual auth is via DOKO)
  keyType: 'RSA',                           // RSA for X.509 compatibility
  keySize: 4096,                            // RSA key size

  // Pinning
  enablePinning: true,
  pinGracePeriod: 24 * 60 * 60 * 1000,      // 24 hours for key rotation

  // TLS options
  minTLSVersion: 'TLSv1.2',
  preferredCipherSuites: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
  ],
};

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * DOKOCertificateGenerator - Creates X.509 certificates bound to DOKO identity
 * 
 * The certificate binds to the DOKO through:
 * 1. Subject containing nodeId
 * 2. Custom extension containing DOKO hash
 * 3. Signature that can be verified against DOKO public key
 * ═══════════════════════════════════════════════════════════════════════════
 */
export class DOKOCertificateGenerator {
  constructor(nodeIdentity, doko, config = {}) {
    this.identity = nodeIdentity;
    this.doko = doko;
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Generated certificate and key
    this.certificate = null;
    this.privateKey = null;
    this.publicKey = null;
    this.fingerprint = null;

    // Certificate metadata
    this.issuedAt = null;
    this.expiresAt = null;
  }

  /**
   * Generate a new X.509 certificate bound to the DOKO
   * 
   * @returns {Object} Certificate and private key in PEM format
   */
  async generate() {
    // Generate RSA keypair for X.509 (for compatibility)
    // Note: The actual authentication is via DOKO's ML-DSA signature
    const keys = forge.pki.rsa.generateKeyPair({ bits: this.config.keySize });

    // Create certificate
    const cert = forge.pki.createCertificate();

    // Set serial number (random)
    cert.serialNumber = bytesToHex(crypto.randomBytes(16));

    // Set validity (ms arithmetic avoids DST boundary drift from setDate)
    const now = new Date();
    const expiry = new Date(now.getTime() + this.config.certValidityDays * 24 * 60 * 60 * 1000);

    cert.validity.notBefore = now;
    cert.validity.notAfter = expiry;

    this.issuedAt = now.getTime();
    this.expiresAt = expiry.getTime();

    // Compute DOKO hash for binding
    const dokoHash = this.computeDokoHash();

    // Set subject (contains nodeId)
    const attrs = [
      { shortName: 'CN', value: this.doko.nodeId },
      { shortName: 'O', value: 'YAKMESH' },
      { shortName: 'OU', value: 'Node Certificate' },
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);  // Self-signed

    // Set public key
    cert.publicKey = keys.publicKey;

    // Add extensions
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: false,
      },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true,
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
      },
      {
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: `${this.doko.nodeId}.yakmesh.local` },
        ],
      },
      // Custom extension: DOKO binding
      {
        id: '1.3.6.1.4.1.99999.1.1',  // Custom OID for YAKMESH
        critical: false,
        value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false,
          JSON.stringify({
            dokoHash,
            networkName: this.doko.networkName,
            dokoVersion: this.doko.version || '1.0',
          })
        ),
      },
    ]);

    // Sign certificate with RSA private key
    cert.sign(keys.privateKey, forge.md.sha384.create());

    // Store generated data
    this.certificate = forge.pki.certificateToPem(cert);
    this.privateKey = forge.pki.privateKeyToPem(keys.privateKey);
    this.publicKey = forge.pki.publicKeyToPem(keys.publicKey);
    this.fingerprint = this.computeCertFingerprint(this.certificate);

    return {
      certificate: this.certificate,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      fingerprint: this.fingerprint,
      issuedAt: this.issuedAt,
      expiresAt: this.expiresAt,
      dokoHash,
      nodeId: this.doko.nodeId,
    };
  }

  /**
   * Compute DOKO hash for binding
   */
  computeDokoHash() {
    const payload = JSON.stringify({
      version: this.doko.version,
      type: this.doko.type,
      nodeId: this.doko.nodeId,
      publicKey: this.doko.publicKey,
      networkName: this.doko.networkName,
      issuedAt: this.doko.issuedAt,
      expiresAt: this.doko.expiresAt,
    });
    return bytesToHex(sha3_256(utf8ToBytes(payload)));
  }

  /**
   * Compute certificate fingerprint
   */
  computeCertFingerprint(certPem) {
    const hash = crypto.createHash('sha256').update(certPem).digest();
    return 'sha256:' + hash.toString('hex');
  }

  /**
   * Check if certificate needs renewal
   */
  needsRenewal() {
    if (!this.expiresAt) return true;

    const renewalTime = this.expiresAt - (this.config.certRenewalThreshold * 24 * 60 * 60 * 1000);
    return Date.now() > renewalTime;
  }

  /**
   * Get TLS options for WebSocket server
   */
  getTLSServerOptions() {
    if (!this.certificate || !this.privateKey) {
      throw new Error('Certificate not generated yet');
    }

    return {
      key: this.privateKey,
      cert: this.certificate,
      minVersion: this.config.minTLSVersion,
      cipherSuites: this.config.preferredCipherSuites.join(':'),
      requestCert: true,           // Request client cert (mTLS)
      rejectUnauthorized: false,    // We verify manually via DOKO
    };
  }

  /**
   * Get TLS options for WebSocket client
   */
  getTLSClientOptions() {
    if (!this.certificate || !this.privateKey) {
      throw new Error('Certificate not generated yet');
    }

    return {
      key: this.privateKey,
      cert: this.certificate,
      minVersion: this.config.minTLSVersion,
      rejectUnauthorized: false,    // We verify manually via DOKO
    };
  }

  /**
   * Serialize certificate data for DOKO.tls field
   */
  toDokoTLSBinding() {
    return {
      certFingerprint: this.fingerprint,
      certIssuedAt: this.issuedAt,
      certExpiresAt: this.expiresAt,
      supports: {
        tls13: true,
        mlkem: false,  // Future: when Node.js supports
        hybridKeyExchange: false,  // Future
        mTLS: true,
      },
    };
  }
}

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * TLSVerifier - Verifies TLS certificates against DOKOs
 * ═══════════════════════════════════════════════════════════════════════════
 */
export class TLSVerifier extends EventEmitter {
  constructor(namcheGateway, config = {}) {
    super();
    this.gateway = namcheGateway;
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Pinned certificates (nodeId -> pin data)
    this.pins = new Map();

    // Verification stats
    this.stats = {
      verificationsPerformed: 0,
      verificationsPassed: 0,
      verificationsFailed: 0,
      pinHits: 0,
      pinMisses: 0,
    };
  }

  /**
   * Verify a peer's TLS certificate against their DOKO
   * 
   * @param {Object} peerCert - The peer's X.509 certificate (from TLS handshake)
   * @param {Object} peerDoko - The peer's DOKO certificate
   * @returns {Object} Verification result
   */
  async verify(peerCert, peerDoko) {
    this.stats.verificationsPerformed++;

    try {
      // 1. Verify DOKO via NAMCHE gateway
      const dokoResult = await this.gateway.verify(peerDoko);
      if (!dokoResult.passed) {
        this.stats.verificationsFailed++;
        return {
          verified: false,
          error: `DOKO verification failed: ${dokoResult.reason}`,
          stage: 'doko-verification',
        };
      }

      // 2. Extract nodeId from certificate
      const certNodeId = this.extractNodeId(peerCert);
      if (certNodeId !== peerDoko.nodeId) {
        this.stats.verificationsFailed++;
        return {
          verified: false,
          error: `NodeId mismatch: cert=${certNodeId}, doko=${peerDoko.nodeId}`,
          stage: 'nodeid-match',
        };
      }

      // 3. Verify DOKO hash binding if present
      const dokoBinding = this.extractDokoBinding(peerCert);
      if (dokoBinding) {
        const expectedHash = this.computeDokoHash(peerDoko);
        if (dokoBinding.dokoHash !== expectedHash) {
          this.stats.verificationsFailed++;
          return {
            verified: false,
            error: 'Certificate DOKO hash does not match actual DOKO',
            stage: 'doko-binding',
          };
        }
      }

      // 4. Check certificate fingerprint if specified in DOKO
      if (peerDoko.tls?.certFingerprint) {
        const actualFingerprint = this.computeCertFingerprint(peerCert);
        if (actualFingerprint !== peerDoko.tls.certFingerprint) {
          this.stats.verificationsFailed++;
          return {
            verified: false,
            error: 'Certificate fingerprint does not match DOKO.tls',
            stage: 'fingerprint-match',
          };
        }
      }

      // 5. Check certificate validity
      const now = Date.now();
      const certValidity = this.getCertValidity(peerCert);

      if (certValidity.notBefore > now) {
        this.stats.verificationsFailed++;
        return {
          verified: false,
          error: 'Certificate not yet valid',
          stage: 'temporal',
        };
      }

      if (certValidity.notAfter < now) {
        this.stats.verificationsFailed++;
        return {
          verified: false,
          error: 'Certificate expired',
          stage: 'temporal',
        };
      }

      // 6. Check pinning
      const pinResult = this.checkPin(peerDoko.nodeId, peerCert);
      if (!pinResult.ok) {
        this.stats.verificationsFailed++;
        return {
          verified: false,
          error: pinResult.error,
          stage: 'pinning',
        };
      }

      // Success!
      this.stats.verificationsPassed++;

      this.emit('verification-passed', {
        nodeId: peerDoko.nodeId,
        certFingerprint: this.computeCertFingerprint(peerCert),
      });

      return {
        verified: true,
        nodeId: peerDoko.nodeId,
        pinned: pinResult.pinned,
        dokoGates: dokoResult.gatesChecked,
      };

    } catch (error) {
      this.stats.verificationsFailed++;
      return {
        verified: false,
        error: error.message,
        stage: 'exception',
      };
    }
  }

  /**
   * Extract nodeId from certificate subject CN
   */
  extractNodeId(cert) {
    // Handle both PEM string and parsed certificate
    if (typeof cert === 'string') {
      const parsed = forge.pki.certificateFromPem(cert);
      const cn = parsed.subject.getField('CN');
      return cn ? cn.value : null;
    }

    // Node.js TLS socket peer cert format
    if (cert.subject?.CN) {
      return cert.subject.CN;
    }

    // Forge certificate format
    if (cert.subject?.getField) {
      const cn = cert.subject.getField('CN');
      return cn ? cn.value : null;
    }

    return null;
  }

  /**
   * Extract DOKO binding from certificate extension
   */
  extractDokoBinding(cert) {
    try {
      const parsed = typeof cert === 'string'
        ? forge.pki.certificateFromPem(cert)
        : cert;

      // Look for our custom OID
      const ext = parsed.extensions?.find(e => e.id === '1.3.6.1.4.1.99999.1.1');
      if (ext && ext.value) {
        return JSON.parse(ext.value);
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Compute DOKO hash
   */
  computeDokoHash(doko) {
    const payload = JSON.stringify({
      version: doko.version,
      type: doko.type,
      nodeId: doko.nodeId,
      publicKey: doko.publicKey,
      networkName: doko.networkName,
      issuedAt: doko.issuedAt,
      expiresAt: doko.expiresAt,
    });
    return bytesToHex(sha3_256(utf8ToBytes(payload)));
  }

  /**
   * Compute certificate fingerprint
   */
  computeCertFingerprint(cert) {
    const pem = typeof cert === 'string' ? cert : forge.pki.certificateToPem(cert);
    const hash = crypto.createHash('sha256').update(pem).digest();
    return 'sha256:' + hash.toString('hex');
  }

  /**
   * Get certificate validity period
   */
  getCertValidity(cert) {
    const parsed = typeof cert === 'string'
      ? forge.pki.certificateFromPem(cert)
      : cert;

    return {
      notBefore: parsed.validity.notBefore.getTime(),
      notAfter: parsed.validity.notAfter.getTime(),
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PINNING
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Pin a certificate for a nodeId
   */
  pin(nodeId, cert, doko) {
    const fingerprint = this.computeCertFingerprint(cert);
    const dokoHash = this.computeDokoHash(doko);

    this.pins.set(nodeId, {
      fingerprint,
      dokoHash,
      pinnedAt: Date.now(),
      expiresAt: this.getCertValidity(cert).notAfter,
    });

    this.emit('pinned', { nodeId, fingerprint });
  }

  /**
   * Check if certificate matches pin
   */
  checkPin(nodeId, cert) {
    if (!this.config.enablePinning) {
      return { ok: true, pinned: false };
    }

    const pin = this.pins.get(nodeId);

    if (!pin) {
      this.stats.pinMisses++;
      // No pin = first contact, allow and pin
      return { ok: true, pinned: false, firstContact: true };
    }

    this.stats.pinHits++;

    const fingerprint = this.computeCertFingerprint(cert);

    if (fingerprint === pin.fingerprint) {
      return { ok: true, pinned: true, since: pin.pinnedAt };
    }

    // Fingerprint mismatch - check grace period for key rotation
    // Grace period only applies if the OLD certificate is expired or about to expire
    const now = Date.now();
    const expirationThreshold = pin.expiresAt - this.config.pinGracePeriod;

    if (now >= expirationThreshold && now < pin.expiresAt + this.config.pinGracePeriod) {
      // Within grace period (near expiration), allow but warn
      return {
        ok: true,
        pinned: true,
        gracePeriod: true,
        warning: 'Certificate changed during grace period',
      };
    }

    return {
      ok: false,
      pinned: true,
      error: 'Certificate fingerprint does not match pinned certificate',
    };
  }

  /**
   * Remove a pin
   */
  unpin(nodeId) {
    const had = this.pins.delete(nodeId);
    if (had) {
      this.emit('unpinned', { nodeId });
    }
    return had;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      pinnedNodes: this.pins.size,
    };
  }

  /**
   * Serialize pins for persistence
   */
  serializePins() {
    return {
      version: 1,
      timestamp: Date.now(),
      pins: Array.from(this.pins.entries()),
    };
  }

  /**
   * Restore pins from persistence
   */
  restorePins(data) {
    if (data?.version === 1 && Array.isArray(data.pins)) {
      this.pins = new Map(data.pins);

      // Clean expired pins
      const now = Date.now();
      for (const [nodeId, pin] of this.pins.entries()) {
        if (pin.expiresAt + this.config.pinGracePeriod < now) {
          this.pins.delete(nodeId);
        }
      }
    }
  }
}

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * TLSCapabilityAdvertiser - Adds TLS info to SHERPA beacons
 * ═══════════════════════════════════════════════════════════════════════════
 */
export class TLSCapabilityAdvertiser {
  constructor(certGenerator) {
    this.certGenerator = certGenerator;
  }

  /**
   * Get TLS capability info for SHERPA beacon
   */
  getBeaconTLSInfo() {
    const hasValidCert = !!(this.certGenerator.certificate &&
      !this.certGenerator.needsRenewal());

    return {
      tlsEnabled: hasValidCert,
      mtlsSupported: hasValidCert,
      certFingerprint: this.certGenerator.fingerprint || null,
      tlsVersion: 'TLS1.3',
      features: {
        tls13: true,
        mTLS: true,
        mlkem: false,          // Future
        hybridKex: false,      // Future
      },
    };
  }
}

export default {
  DOKOCertificateGenerator,
  TLSVerifier,
  TLSCapabilityAdvertiser,
};
