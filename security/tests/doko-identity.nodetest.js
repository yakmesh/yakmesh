/**
 * DOKO Identity Tests
 * Tests for the DOKO (Distributed Ownership & Key Object) system
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';

import {
  DOKO_TYPES,
  DOKO_VERSION,
  DOKODocument,
  DOKOGenerator,
  DOKOValidator,
  DOKOEndorsement,
  DOKOStore,
} from '../doko-identity.js';

describe('DOKO Identity', () => {
  
  describe('DOKODocument', () => {
    it('should compute DOKO ID from public key', () => {
      const mockPubKey = 'a'.repeat(64); // Mock hex public key
      const dokoId = DOKODocument.computeDokoId(mockPubKey, DOKO_TYPES.USER);
      
      assert.ok(dokoId.startsWith('doko-user-'));
      assert.strictEqual(dokoId.length, 'doko-user-'.length + 16);
    });

    it('should compute different IDs for different types', () => {
      const mockPubKey = 'a'.repeat(64);
      const userId = DOKODocument.computeDokoId(mockPubKey, DOKO_TYPES.USER);
      const traderId = DOKODocument.computeDokoId(mockPubKey, DOKO_TYPES.TRADER);
      
      assert.notStrictEqual(userId, traderId);
      assert.ok(userId.startsWith('doko-user-'));
      assert.ok(traderId.startsWith('doko-trader-'));
    });

    it('should create valid signable bytes', () => {
      const doc = new DOKODocument({
        type: DOKO_TYPES.USER,
        dokoId: 'doko-user-abc123',
        publicKey: 'a'.repeat(64),
        claims: { name: 'Test' },
      });
      
      const bytes = doc.getSignableBytes();
      assert.ok(bytes instanceof Buffer);
      assert.ok(bytes.length > 0);
    });

    it('should detect expired documents', () => {
      const expiredDoc = new DOKODocument({
        created: Date.now() - 1000000,
        expires: Date.now() - 1000,
      });
      
      assert.strictEqual(expiredDoc.isExpired(), true);
    });

    it('should serialize to JSON correctly', () => {
      const doc = new DOKODocument({
        type: DOKO_TYPES.TRADER,
        dokoId: 'doko-trader-test',
        publicKey: 'abc123',
        claims: { platform: 'peerquanta' },
      });
      
      const json = doc.toJSON();
      assert.strictEqual(json.type, DOKO_TYPES.TRADER);
      assert.strictEqual(json.dokoId, 'doko-trader-test');
      assert.strictEqual(json.claims.platform, 'peerquanta');
    });
  });

  describe('DOKOGenerator', () => {
    it('should generate a valid DOKO with keypair', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      
      assert.ok(result.doko);
      assert.ok(result.publicKey);
      assert.ok(result.secretKey);
      assert.ok(result.publicKeyHex);
      assert.ok(result.secretKeyHex);
      assert.ok(result.doko.signature);
      assert.strictEqual(result.doko.type, DOKO_TYPES.USER);
    });

    it('should generate trader DOKO with correct claims', () => {
      const result = DOKOGenerator.generateTrader({
        username: 'testuser',
        userId: 123,
        tradingPairs: ['BTC/QRL', 'ETH/QRL'],
      });
      
      assert.strictEqual(result.doko.type, DOKO_TYPES.TRADER);
      assert.strictEqual(result.doko.claims.platform, 'peerquanta');
      assert.strictEqual(result.doko.claims.username, 'testuser');
      assert.strictEqual(result.doko.claims.userId, 123);
      assert.ok(result.doko.extensions.capabilities.includes('trade'));
    });

    it('should generate merchant DOKO with domain claims', () => {
      const result = DOKOGenerator.generateMerchant({
        businessName: 'Test Corp',
        domain: 'testcorp.com',
      });
      
      assert.strictEqual(result.doko.type, DOKO_TYPES.MERCHANT);
      assert.strictEqual(result.doko.claims.businessName, 'Test Corp');
      assert.strictEqual(result.doko.claims.domain, 'testcorp.com');
      assert.strictEqual(result.doko.claims.verified, false);
    });

    it('should generate deterministic DOKO from seed', () => {
      const seed = new Uint8Array(32).fill(42);
      const result1 = DOKOGenerator.generate({ seed });
      const result2 = DOKOGenerator.generate({ seed });
      
      assert.strictEqual(result1.publicKeyHex, result2.publicKeyHex);
    });
  });

  describe('DOKOValidator', () => {
    let validDoko;
    
    beforeEach(() => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      validDoko = result.doko;
    });

    it('should validate a correctly signed DOKO', () => {
      const result = DOKOValidator.validate(validDoko);
      assert.strictEqual(result.valid, true);
    });

    it('should verify signature correctly', () => {
      const result = DOKOValidator.verifySignature(validDoko);
      assert.strictEqual(result.valid, true);
    });

    it('should verify DOKO ID matches public key', () => {
      const result = DOKOValidator.verifyDokoId(validDoko);
      assert.strictEqual(result.valid, true);
    });

    it('should reject tampered DOKO', () => {
      const tampered = DOKODocument.fromJSON(validDoko.toJSON());
      tampered.claims.tampered = true;
      
      const result = DOKOValidator.verifySignature(tampered);
      assert.strictEqual(result.valid, false);
    });

    it('should reject wrong DOKO ID', () => {
      const tampered = DOKODocument.fromJSON(validDoko.toJSON());
      tampered.dokoId = 'doko-user-wrong';
      
      const result = DOKOValidator.verifyDokoId(tampered);
      assert.strictEqual(result.valid, false);
    });

    it('should reject expired DOKO unless allowed', () => {
      const expiredDoko = DOKODocument.fromJSON({
        ...validDoko.toJSON(),
        expires: Date.now() - 1000,
      });
      
      const strictResult = DOKOValidator.validate(expiredDoko, { allowExpired: false });
      assert.strictEqual(strictResult.valid, false);
      
      // Note: allowExpired would skip expiration check but signature would fail
      // because expiration is in signed content
    });

    it('should reject missing signature', () => {
      const noSig = DOKODocument.fromJSON({
        ...validDoko.toJSON(),
        signature: null,
      });
      
      const result = DOKOValidator.verifySignature(noSig);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'MISSING_SIGNATURE_OR_KEY');
    });
  });

  describe('DOKOEndorsement', () => {
    let targetResult, endorserResult;
    
    beforeEach(() => {
      targetResult = DOKOGenerator.generate({ type: DOKO_TYPES.TRADER });
      endorserResult = DOKOGenerator.generate({ type: DOKO_TYPES.TRADER });
    });

    it('should create valid endorsement', () => {
      const endorsement = DOKOEndorsement.create(
        targetResult.doko,
        endorserResult.doko,
        endorserResult.secretKey,
        { tradingHistory: true, reliable: true }
      );
      
      assert.ok(endorsement.targetDokoId);
      assert.ok(endorsement.endorserDokoId);
      assert.ok(endorsement.signature);
      assert.strictEqual(endorsement.claims.tradingHistory, true);
    });

    it('should verify valid endorsement', () => {
      const endorsement = DOKOEndorsement.create(
        targetResult.doko,
        endorserResult.doko,
        endorserResult.secretKey,
        { trusted: true }
      );
      
      const result = DOKOEndorsement.verify(endorsement, targetResult.doko);
      assert.strictEqual(result.valid, true);
    });

    it('should reject endorsement for wrong target', () => {
      const otherResult = DOKOGenerator.generate({ type: DOKO_TYPES.TRADER });
      
      const endorsement = DOKOEndorsement.create(
        targetResult.doko,
        endorserResult.doko,
        endorserResult.secretKey,
        {}
      );
      
      const result = DOKOEndorsement.verify(endorsement, otherResult.doko);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'TARGET_MISMATCH');
    });

    it('should reject expired endorsement', () => {
      const endorsement = DOKOEndorsement.create(
        targetResult.doko,
        endorserResult.doko,
        endorserResult.secretKey,
        {}
      );
      endorsement.expires = Date.now() - 1000;
      
      const result = DOKOEndorsement.verify(endorsement, targetResult.doko);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'ENDORSEMENT_EXPIRED');
    });
  });

  describe('DOKOStore', () => {
    let store;
    
    beforeEach(() => {
      store = new DOKOStore();
    });

    it('should add and retrieve DOKO', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      const addResult = store.add(result.doko);
      
      assert.strictEqual(addResult.success, true);
      
      const retrieved = store.get(result.doko.dokoId);
      assert.ok(retrieved);
      assert.strictEqual(retrieved.dokoId, result.doko.dokoId);
    });

    it('should retrieve DOKO by public key', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      store.add(result.doko);
      
      const retrieved = store.getByPublicKey(result.doko.publicKey);
      assert.ok(retrieved);
      assert.strictEqual(retrieved.dokoId, result.doko.dokoId);
    });

    it('should retrieve DOKO by user ID', () => {
      const result = DOKOGenerator.generateTrader({
        username: 'testuser',
        userId: 456,
      });
      store.add(result.doko);
      
      const retrieved = store.getByUserId(456);
      assert.ok(retrieved);
      assert.strictEqual(retrieved.claims.userId, 456);
    });

    it('should filter by type', () => {
      const trader = DOKOGenerator.generateTrader({ username: 'trader1', userId: 1 });
      const merchant = DOKOGenerator.generateMerchant({ businessName: 'Biz', domain: 'biz.com' });
      const user = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      
      store.add(trader.doko);
      store.add(merchant.doko);
      store.add(user.doko);
      
      const traders = store.getTraders();
      const merchants = store.getMerchants();
      
      assert.strictEqual(traders.length, 1);
      assert.strictEqual(merchants.length, 1);
    });

    it('should remove DOKO', () => {
      const result = DOKOGenerator.generate({ type: DOKO_TYPES.USER });
      store.add(result.doko);
      
      const removed = store.remove(result.doko.dokoId);
      assert.strictEqual(removed, true);
      
      const retrieved = store.get(result.doko.dokoId);
      assert.strictEqual(retrieved, undefined);
    });

    it('should export and import DOKOs', () => {
      const result1 = DOKOGenerator.generateTrader({ username: 'u1', userId: 1 });
      const result2 = DOKOGenerator.generateTrader({ username: 'u2', userId: 2 });
      
      store.add(result1.doko);
      store.add(result2.doko);
      
      const exported = store.export();
      assert.strictEqual(exported.length, 2);
      
      const newStore = new DOKOStore();
      const importResult = newStore.import(exported);
      
      assert.strictEqual(importResult.imported, 2);
      assert.strictEqual(newStore.documents.size, 2);
    });

    it('should return correct stats', () => {
      store.add(DOKOGenerator.generateTrader({ username: 'u1', userId: 1 }).doko);
      store.add(DOKOGenerator.generateTrader({ username: 'u2', userId: 2 }).doko);
      store.add(DOKOGenerator.generateMerchant({ businessName: 'B', domain: 'b.com' }).doko);
      
      const stats = store.getStats();
      assert.strictEqual(stats.total, 3);
      assert.strictEqual(stats.byType.trader, 2);
      assert.strictEqual(stats.byType.merchant, 1);
    });
  });
});

console.log('Running DOKO Identity tests...');
