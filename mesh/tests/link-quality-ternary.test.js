/**
 * Tests for Ternary Link Quality (KHATA/SHERPA retrofit)
 * 
 * Verifies bidirectional link health uses ternary logic:
 *   GOOD (+1)    = Both directions healthy
 *   BAD (-1)     = Both directions degraded
 *   NEUTRAL (0)  = Asymmetric (mixed quality)
 * 
 * @module mesh/tests/link-quality-ternary.test
 */

import { describe, it, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import { LinkQuality } from '../sherpa-discovery.js';
import { POSITIVE, NEUTRAL, NEGATIVE } from '../../oracle/tribhuj.js';

// =============================================================================
// Visual Demo
// =============================================================================

console.log('\n🔗 KHATA/SHERPA Ternary Link Quality');
console.log('─'.repeat(50));

// Demo 1: Symmetric good link
const goodLink = new LinkQuality();
for (let i = 0; i < 10; i++) {
  goodLink.recordOutbound(true);
  goodLink.recordInbound(true);
}
console.log('📡 Symmetric Good Link:');
console.log(`   Outbound: ${goodLink.outboundQuality.value} (${goodLink.toJSON().outbound.successes}/${goodLink.toJSON().outbound.failures})`);
console.log(`   Inbound:  ${goodLink.inboundQuality.value} (${goodLink.toJSON().inbound.successes}/${goodLink.toJSON().inbound.failures})`);
console.log(`   Overall:  ${goodLink.toJSON().overall.qualityLabel}`);

// Demo 2: Asymmetric link (we can send, but not receive)
const asymLink = new LinkQuality();
for (let i = 0; i < 10; i++) {
  asymLink.recordOutbound(true);   // Our messages get through
  asymLink.recordInbound(false);   // Their replies don't arrive
}
console.log('\n📡 Asymmetric Link (outbound good, inbound bad):');
console.log(`   Outbound: ${asymLink.outboundQuality.value} (GOOD)`);
console.log(`   Inbound:  ${asymLink.inboundQuality.value} (BAD)`);
console.log(`   Overall:  ${asymLink.toJSON().overall.qualityLabel} ← Ternary AND = BAD`);
console.log(`   Symmetric: ${asymLink.isSymmetric}`);

// Demo 3: Mixed/uncertain link
const mixedLink = new LinkQuality();
for (let i = 0; i < 5; i++) {
  mixedLink.recordOutbound(i % 2 === 0);  // 50/50
  mixedLink.recordInbound(i % 3 === 0);   // 33/66
}
console.log('\n📡 Mixed/Uncertain Link:');
console.log(`   Outbound: ${mixedLink.outboundQuality.value} (NEUTRAL - mixed)`);
console.log(`   Inbound:  ${mixedLink.inboundQuality.value} (NEUTRAL - mixed)`);
console.log(`   Overall:  ${mixedLink.toJSON().overall.qualityLabel}`);

// Demo 4: Path balance
console.log('\n⚖️ Path Balance:');
console.log(`   Good link balance: ${JSON.stringify(goodLink.pathBalance)}`);
console.log(`   Asym link balance: ${JSON.stringify(asymLink.pathBalance)}`);

console.log('\n' + '─'.repeat(50) + '\n');

// =============================================================================
// Tests
// =============================================================================

describe('KHATA/SHERPA Ternary Link Quality', () => {

  describe('LinkQuality Construction', () => {
    it('starts with NEUTRAL quality (no data)', () => {
      const link = new LinkQuality();
      assert.equal(link.quality.value, NEUTRAL);
      assert.equal(link.outboundQuality.value, NEUTRAL);
      assert.equal(link.inboundQuality.value, NEUTRAL);
    });
  });

  describe('Outbound Quality', () => {
    it('POSITIVE when >70% success', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 8; i++) link.recordOutbound(true);
      for (let i = 0; i < 2; i++) link.recordOutbound(false);
      assert.equal(link.outboundQuality.value, POSITIVE);
    });

    it('NEGATIVE when <30% success', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 2; i++) link.recordOutbound(true);
      for (let i = 0; i < 8; i++) link.recordOutbound(false);
      assert.equal(link.outboundQuality.value, NEGATIVE);
    });

    it('NEUTRAL when mixed (30-70%)', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 5; i++) link.recordOutbound(true);
      for (let i = 0; i < 5; i++) link.recordOutbound(false);
      assert.equal(link.outboundQuality.value, NEUTRAL);
    });
  });

  describe('Inbound Quality', () => {
    it('POSITIVE when >70% success', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) link.recordInbound(true);
      assert.equal(link.inboundQuality.value, POSITIVE);
    });

    it('NEGATIVE when mostly failures', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) link.recordInbound(false);
      assert.equal(link.inboundQuality.value, NEGATIVE);
    });
  });

  describe('Bidirectional Quality', () => {
    let link;

    beforeEach(() => {
      link = new LinkQuality();
    });

    it('POSITIVE when both directions good', () => {
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(true);
        link.recordInbound(true);
      }
      assert.equal(link.quality.isPositive, true);
    });

    it('NEGATIVE when both directions bad', () => {
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(false);
        link.recordInbound(false);
      }
      assert.equal(link.quality.isNegative, true);
    });

    it('NEGATIVE when asymmetric (good out, bad in)', () => {
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(true);
        link.recordInbound(false);
      }
      // AND(POSITIVE, NEGATIVE) = NEGATIVE
      assert.equal(link.quality.isNegative, true);
    });

    it('NEUTRAL when outbound mixed', () => {
      for (let i = 0; i < 5; i++) {
        link.recordOutbound(true);
        link.recordOutbound(false);
        link.recordInbound(true);
      }
      // AND(NEUTRAL, POSITIVE) = NEUTRAL
      assert.equal(link.quality.isNeutral, true);
    });
  });

  describe('Symmetry Detection', () => {
    it('isSymmetric when both directions same', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(true);
        link.recordInbound(true);
      }
      assert.equal(link.isSymmetric, true);
    });

    it('isAsymmetric when directions differ', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(true);
        link.recordInbound(false);
      }
      assert.equal(link.isAsymmetric, true);
    });
  });

  describe('Path Balance', () => {
    it('reports balance for symmetric good link', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(true);
        link.recordInbound(true);
      }
      const { balance, isBalanced } = link.pathBalance;
      // balance = +1 + +1 = 2 (not balanced, but symmetric good)
      assert.equal(typeof balance, 'number');
      assert.equal(balance, 2);
    });

    it('balanced when opposite qualities (sum = 0)', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) {
        link.recordOutbound(true);  // POSITIVE
      }
      for (let i = 0; i < 10; i++) {
        link.recordInbound(false);  // NEGATIVE
      }
      // balance = +1 + -1 = 0
      assert.equal(link.pathBalance.balance, 0);
      assert.equal(link.pathBalance.isBalanced, true);
    });
  });

  describe('Reset and Decay', () => {
    it('reset clears all counters', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) link.recordOutbound(true);
      link.reset();
      assert.equal(link.quality.value, NEUTRAL);
    });

    it('decay reduces counters', () => {
      const link = new LinkQuality();
      for (let i = 0; i < 10; i++) link.recordOutbound(true);
      link.decay(0.5);
      // 10 * 0.5 = 5
      const json = link.toJSON();
      assert.equal(json.outbound.successes, 5);
    });
  });

  describe('Serialization', () => {
    it('toJSON includes all metrics', () => {
      const link = new LinkQuality();
      link.recordOutbound(true);
      link.recordInbound(false);
      
      const json = link.toJSON();
      
      assert.ok('outbound' in json);
      assert.ok('inbound' in json);
      assert.ok('overall' in json);
      assert.equal(json.outbound.successes, 1);
      assert.equal(json.inbound.failures, 1);
      assert.ok(json.overall.qualityLabel);
    });
  });
});

console.log('✅ KHATA/SHERPA ternary link quality tests complete!\n');
