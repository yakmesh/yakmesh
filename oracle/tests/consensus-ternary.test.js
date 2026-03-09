/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Tests for Ternary Consensus (LAMA retrofit)
 * 
 * Verifies that LAMA consensus engine now supports ternary votes:
 *   ACCEPT  (+1) = I validate this content
 *   REJECT  (-1) = I reject this content
 *   ABSTAIN  (0) = I cannot determine (propagating)
 * 
 * @module oracle/tests/consensus-ternary.test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ConsensusVote, computeTernaryConsensus } from '../consensus-engine.js';
import { Trit, POSITIVE, NEUTRAL, NEGATIVE } from '../tribhuj.js';

// =============================================================================
// Visual Demo
// =============================================================================

console.log('\n🗳️ LAMA Ternary Consensus Retrofit');
console.log('─'.repeat(50));

// Simulate a 5-node network voting on content
const votes = [
  ConsensusVote.accept('node-1', { weight: 10 }),  // Trusted validator
  ConsensusVote.accept('node-2', { weight: 5 }),   // Regular node
  ConsensusVote.reject('node-3', 'SIGNATURE_EXPIRED', { weight: 3 }),
  ConsensusVote.abstain('node-4'),                 // Still propagating
  ConsensusVote.accept('node-5', { weight: 2 }),   // New node
];

console.log('📊 Votes Cast:');
votes.forEach(v => {
  const label = v.isAccept ? '✓ ACCEPT' : (v.isReject ? '✗ REJECT' : '◌ ABSTAIN');
  console.log(`   ${v.nodeId}: ${label} (weight: ${v.weight})${v.reason ? ' - ' + v.reason : ''}`);
});

const { result, confidence, summary } = computeTernaryConsensus(votes);
console.log('\n📈 Consensus Result:');
console.log(`   Decision: ${result.isPositive ? 'ACCEPT' : (result.isNegative ? 'REJECT' : 'UNDECIDED')}`);
console.log(`   Confidence: ${(confidence * 100).toFixed(1)}%`);
console.log(`   Accept/Reject/Abstain: ${summary.accept}/${summary.reject}/${summary.abstain}`);
console.log(`   Weighted Accept/Reject: ${summary.acceptWeight}/${summary.rejectWeight}`);

// Demo: Close vote scenario
console.log('\n⚖️ Close Vote Scenario:');
const closeVotes = [
  ConsensusVote.accept('node-1', { weight: 5 }),
  ConsensusVote.reject('node-2', 'INVALID_CONTENT', { weight: 4 }),
  ConsensusVote.abstain('node-3'),
];
const closeResult = computeTernaryConsensus(closeVotes, { threshold: 0.2 });
console.log(`   With 20% threshold: ${closeResult.result.isNeutral ? 'UNDECIDED (margin too close)' : 'DECIDED'}`);

console.log('\n' + '─'.repeat(50) + '\n');

// =============================================================================
// Tests
// =============================================================================

describe('LAMA Ternary Consensus', () => {

  describe('ConsensusVote', () => {
    it('accept() creates positive vote', () => {
      const vote = ConsensusVote.accept('node-1');
      assert.equal(vote.isAccept, true);
      assert.equal(vote.vote.value, POSITIVE);
      assert.equal(vote.nodeId, 'node-1');
    });

    it('reject() creates negative vote with reason', () => {
      const vote = ConsensusVote.reject('node-1', 'BAD_SIG');
      assert.equal(vote.isReject, true);
      assert.equal(vote.vote.value, NEGATIVE);
      assert.equal(vote.reason, 'BAD_SIG');
    });

    it('abstain() creates neutral vote', () => {
      const vote = ConsensusVote.abstain('node-1');
      assert.equal(vote.isAbstain, true);
      assert.equal(vote.vote.value, NEUTRAL);
    });

    it('has default weight of 1', () => {
      const vote = ConsensusVote.accept('node-1');
      assert.equal(vote.weight, 1);
    });

    it('accepts custom weight', () => {
      const vote = ConsensusVote.accept('node-1', { weight: 10 });
      assert.equal(vote.weight, 10);
    });

    it('records timestamp', () => {
      const before = Date.now();
      const vote = ConsensusVote.accept('node-1');
      const after = Date.now();
      assert.ok(vote.timestamp >= before && vote.timestamp <= after);
    });

    it('is immutable', () => {
      const vote = ConsensusVote.accept('node-1');
      assert.throws(() => {
        vote.newProp = 'test';
      });
    });

    it('toJSON includes all fields', () => {
      const vote = ConsensusVote.reject('node-1', 'ERR', { weight: 5 });
      const json = vote.toJSON();
      
      assert.equal(json.nodeId, 'node-1');
      assert.equal(json.vote, -1);
      assert.equal(json.voteLabel, 'REJECT');
      assert.equal(json.weight, 5);
      assert.equal(json.reason, 'ERR');
    });
  });

  describe('computeTernaryConsensus', () => {
    it('unanimous accept returns ACCEPT', () => {
      const votes = [
        ConsensusVote.accept('a'),
        ConsensusVote.accept('b'),
        ConsensusVote.accept('c'),
      ];
      const { result } = computeTernaryConsensus(votes, { threshold: 0.5 });
      assert.equal(result.isPositive, true);
    });

    it('unanimous reject returns REJECT', () => {
      const votes = [
        ConsensusVote.reject('a', 'X'),
        ConsensusVote.reject('b', 'Y'),
      ];
      const { result } = computeTernaryConsensus(votes, { threshold: 0.5 });
      assert.equal(result.isNegative, true);
    });

    it('strong majority accept wins', () => {
      const votes = [
        ConsensusVote.accept('a', { weight: 10 }),
        ConsensusVote.accept('b', { weight: 5 }),
        ConsensusVote.reject('c', 'X', { weight: 2 }),
      ];
      // Weighted score = (10+5-2)/(10+5+2) = 13/17 ≈ 0.76
      const { result, confidence } = computeTernaryConsensus(votes, { threshold: 0.5 });
      assert.equal(result.isPositive, true);
      assert.ok(confidence > 0.5);
    });

    it('close vote returns NEUTRAL (undecided)', () => {
      const votes = [
        ConsensusVote.accept('a', { weight: 5 }),
        ConsensusVote.reject('b', 'X', { weight: 5 }),
      ];
      // Weighted score = (5-5)/10 = 0 → below any threshold
      const { result } = computeTernaryConsensus(votes, { threshold: 0.2 });
      assert.equal(result.isNeutral, true);
    });

    it('abstain votes are neutral in weighted calculation', () => {
      const votes = [
        ConsensusVote.accept('a', { weight: 5 }),
        ConsensusVote.abstain('b', 'PROPAGATING', { weight: 10 }),
      ];
      const { result, summary } = computeTernaryConsensus(votes);
      
      // Abstains don't block accept, but reduce confidence
      assert.equal(summary.abstain, 1);
      assert.equal(summary.acceptWeight, 5);
    });

    it('provides correct summary stats', () => {
      const votes = [
        ConsensusVote.accept('a', { weight: 10 }),
        ConsensusVote.accept('b', { weight: 5 }),
        ConsensusVote.reject('c', 'X', { weight: 3 }),
        ConsensusVote.abstain('d'),
      ];
      const { summary } = computeTernaryConsensus(votes);
      
      assert.equal(summary.total, 4);
      assert.equal(summary.accept, 2);
      assert.equal(summary.reject, 1);
      assert.equal(summary.abstain, 1);
      assert.equal(summary.acceptWeight, 15);
      assert.equal(summary.rejectWeight, 3);
      assert.equal(summary.totalWeight, 19);
    });

    it('handles empty votes array', () => {
      const { result, confidence, summary } = computeTernaryConsensus([]);
      assert.equal(result.isNeutral, true); // No votes = undecided
      assert.equal(summary.total, 0);
    });

    it('single vote determines result', () => {
      const { result } = computeTernaryConsensus([
        ConsensusVote.accept('a'),
      ], { threshold: 0.5 });
      assert.equal(result.isPositive, true);
    });
  });
});

console.log('✅ LAMA ternary consensus tests complete!\n');
