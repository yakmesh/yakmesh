/**
 * Trust Tiers - Combined Hardware + Time Source Trust Levels
 * 
 * The ultimate trust stack for YAKMESH:
 * - ORACLE: Atomic Clock + Real Hardware (AES-NI)
 * - ANCHOR: GPS + PPS + Real Hardware
 * - SENTINEL: PTP (IEEE 1588) + Real Hardware
 * - PARTICIPANT: NTP + Real Hardware
 * - OBSERVER: Unverified hardware or time
 * 
 * "You can't fake physics. Atomic time and real silicon are your credentials."
 * 
 * @module security/trust-tier
 * @version 1.0.0
 */

import { HardwareAttestation, validateAESTiming } from './hardware-attestation.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('security:trust-tier');

/**
 * Trust Tiers - hierarchical trust levels
 */
export const TRUST_TIER = {
  ORACLE: 'oracle',         // Atomic clock + AES-NI
  ANCHOR: 'anchor',         // GPS + PPS + AES-NI
  SENTINEL: 'sentinel',     // PTP + AES-NI
  PARTICIPANT: 'participant', // NTP + AES-NI
  OBSERVER: 'observer',     // Unverified
};

/**
 * Time source levels (from oracle/time-source.js)
 */
export const TIME_SOURCE = {
  ATOMIC: 'atomic',   // PCIe atomic clock
  GPS: 'gps',         // GPS with PPS
  PTP: 'ptp',         // IEEE 1588 Precision Time Protocol
  NTP: 'ntp',         // Network Time Protocol
  SYSTEM: 'system',   // System clock only
};

/**
 * Attestation weight multipliers by tier
 */
export const TIER_WEIGHT = {
  [TRUST_TIER.ORACLE]: 2.0,      // Maximum trust
  [TRUST_TIER.ANCHOR]: 1.5,      // High trust
  [TRUST_TIER.SENTINEL]: 1.25,   // Good trust
  [TRUST_TIER.PARTICIPANT]: 1.0, // Standard trust
  [TRUST_TIER.OBSERVER]: 0.25,   // Minimal trust
};

/**
 * Tier requirements
 */
export const TIER_REQUIREMENTS = {
  [TRUST_TIER.ORACLE]: {
    timeSource: [TIME_SOURCE.ATOMIC],
    requiresAESNI: true,
    minNetworkAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    minEndorsements: 3,
  },
  [TRUST_TIER.ANCHOR]: {
    timeSource: [TIME_SOURCE.GPS],
    requiresAESNI: true,
    minNetworkAge: 14 * 24 * 60 * 60 * 1000, // 14 days
    minEndorsements: 2,
  },
  [TRUST_TIER.SENTINEL]: {
    timeSource: [TIME_SOURCE.PTP],
    requiresAESNI: true,
    minNetworkAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    minEndorsements: 1,
  },
  [TRUST_TIER.PARTICIPANT]: {
    timeSource: [TIME_SOURCE.NTP, TIME_SOURCE.SYSTEM],
    requiresAESNI: true,
    minNetworkAge: 24 * 60 * 60 * 1000, // 1 day
    minEndorsements: 0,
  },
  [TRUST_TIER.OBSERVER]: {
    timeSource: [TIME_SOURCE.NTP, TIME_SOURCE.SYSTEM],
    requiresAESNI: false,
    minNetworkAge: 0,
    minEndorsements: 0,
  },
};

/**
 * Node Trust Profile
 * Combines all factors into a trust assessment
 */
export class TrustProfile {
  constructor(options = {}) {
    this.dokoId = options.dokoId;
    this.hardwareAttestation = options.hardwareAttestation || null;
    this.timeSource = options.timeSource || TIME_SOURCE.SYSTEM;
    this.networkAge = options.networkAge || 0;
    this.endorsementCount = options.endorsementCount || 0;
    this.lastUpdated = options.lastUpdated || Date.now();
  }

  /**
   * Calculate the trust tier for this profile
   */
  calculateTier() {
    // Check each tier from highest to lowest
    const tiers = [
      TRUST_TIER.ORACLE,
      TRUST_TIER.ANCHOR,
      TRUST_TIER.SENTINEL,
      TRUST_TIER.PARTICIPANT,
    ];

    for (const tier of tiers) {
      if (this.meetsTierRequirements(tier)) {
        return tier;
      }
    }

    return TRUST_TIER.OBSERVER;
  }

  /**
   * Check if profile meets requirements for a tier
   */
  meetsTierRequirements(tier) {
    const req = TIER_REQUIREMENTS[tier];
    
    // Check time source
    if (!req.timeSource.includes(this.timeSource)) {
      return false;
    }

    // Check hardware
    if (req.requiresAESNI) {
      if (!this.hardwareAttestation) return false;
      
      const validation = validateAESTiming(this.hardwareAttestation.timing);
      if (!validation.hasAESNI) return false;
    }

    // Check network age
    if (this.networkAge < req.minNetworkAge) {
      return false;
    }

    // Check endorsements
    if (this.endorsementCount < req.minEndorsements) {
      return false;
    }

    return true;
  }

  /**
   * Get attestation weight for this profile
   */
  getWeight() {
    const tier = this.calculateTier();
    return TIER_WEIGHT[tier];
  }

  /**
   * Get detailed breakdown
   */
  getDetails() {
    const tier = this.calculateTier();
    
    return {
      dokoId: this.dokoId,
      tier,
      weight: TIER_WEIGHT[tier],
      factors: {
        timeSource: this.timeSource,
        hasAESNI: this.hardwareAttestation?.validation?.hasAESNI || false,
        networkAgeDays: Math.floor(this.networkAge / (24 * 60 * 60 * 1000)),
        endorsements: this.endorsementCount,
      },
      requirements: TIER_REQUIREMENTS[tier],
      nextTier: this.getNextTierRequirements(),
    };
  }

  /**
   * Get requirements for next tier upgrade
   */
  getNextTierRequirements() {
    const currentTier = this.calculateTier();
    const tierOrder = [
      TRUST_TIER.OBSERVER,
      TRUST_TIER.PARTICIPANT,
      TRUST_TIER.SENTINEL,
      TRUST_TIER.ANCHOR,
      TRUST_TIER.ORACLE,
    ];

    const currentIndex = tierOrder.indexOf(currentTier);
    if (currentIndex >= tierOrder.length - 1) {
      return null; // Already at max tier
    }

    const nextTier = tierOrder[currentIndex + 1];
    const req = TIER_REQUIREMENTS[nextTier];
    const missing = [];

    if (!req.timeSource.includes(this.timeSource)) {
      missing.push(`Upgrade time source to: ${req.timeSource.join(' or ')}`);
    }

    if (req.requiresAESNI && !this.hardwareAttestation?.validation?.hasAESNI) {
      missing.push('Requires AES-NI hardware attestation');
    }

    if (this.networkAge < req.minNetworkAge) {
      const daysNeeded = Math.ceil((req.minNetworkAge - this.networkAge) / (24 * 60 * 60 * 1000));
      missing.push(`Need ${daysNeeded} more days of network presence`);
    }

    if (this.endorsementCount < req.minEndorsements) {
      missing.push(`Need ${req.minEndorsements - this.endorsementCount} more endorsements`);
    }

    return {
      tier: nextTier,
      weight: TIER_WEIGHT[nextTier],
      missing,
    };
  }

  /**
   * Serialize to JSON
   */
  toJSON() {
    return {
      dokoId: this.dokoId,
      hardwareAttestation: this.hardwareAttestation,
      timeSource: this.timeSource,
      networkAge: this.networkAge,
      endorsementCount: this.endorsementCount,
      lastUpdated: this.lastUpdated,
      tier: this.calculateTier(),
      weight: this.getWeight(),
    };
  }

  /**
   * Deserialize from JSON
   */
  static fromJSON(json) {
    return new TrustProfile(json);
  }
}

/**
 * Trust Tier Registry
 * Manages trust profiles for all known nodes
 */
export class TrustTierRegistry {
  constructor(options = {}) {
    this.profiles = new Map(); // dokoId -> TrustProfile
    
    // External data sources
    this.getTimeSource = options.getTimeSource || (() => TIME_SOURCE.SYSTEM);
    this.getNetworkAge = options.getNetworkAge || (() => 0);
    this.getEndorsementCount = options.getEndorsementCount || (() => 0);
    this.getHardwareAttestation = options.getHardwareAttestation || (() => null);
  }

  /**
   * Get or create trust profile for a node
   */
  async getProfile(dokoId) {
    let profile = this.profiles.get(dokoId);
    
    if (!profile || this.isStale(profile)) {
      profile = await this.refreshProfile(dokoId);
    }
    
    return profile;
  }

  /**
   * Refresh a node's trust profile
   */
  async refreshProfile(dokoId) {
    const profile = new TrustProfile({
      dokoId,
      hardwareAttestation: await this.getHardwareAttestation(dokoId),
      timeSource: await this.getTimeSource(dokoId),
      networkAge: await this.getNetworkAge(dokoId),
      endorsementCount: await this.getEndorsementCount(dokoId),
      lastUpdated: Date.now(),
    });

    this.profiles.set(dokoId, profile);
    
    log.debug('profile-refreshed', {
      dokoId,
      tier: profile.calculateTier(),
      weight: profile.getWeight(),
    });

    return profile;
  }

  /**
   * Check if profile is stale (older than 1 hour)
   */
  isStale(profile) {
    return Date.now() - profile.lastUpdated > 60 * 60 * 1000;
  }

  /**
   * Get tier for a node
   */
  async getTier(dokoId) {
    const profile = await this.getProfile(dokoId);
    return profile.calculateTier();
  }

  /**
   * Get attestation weight for a node
   */
  async getWeight(dokoId) {
    const profile = await this.getProfile(dokoId);
    return profile.getWeight();
  }

  /**
   * Calculate effective attestation count with tier weighting
   */
  async calculateEffectiveCount(attestations) {
    let count = 0;

    for (const attestation of attestations) {
      const weight = await this.getWeight(attestation.attesterId);
      count += weight;
    }

    return count;
  }

  /**
   * Get network tier distribution
   */
  getTierDistribution() {
    const distribution = {
      [TRUST_TIER.ORACLE]: 0,
      [TRUST_TIER.ANCHOR]: 0,
      [TRUST_TIER.SENTINEL]: 0,
      [TRUST_TIER.PARTICIPANT]: 0,
      [TRUST_TIER.OBSERVER]: 0,
    };

    for (const profile of this.profiles.values()) {
      distribution[profile.calculateTier()]++;
    }

    return distribution;
  }

  /**
   * Get effective network size (weighted)
   */
  getEffectiveNetworkSize() {
    let size = 0;

    for (const profile of this.profiles.values()) {
      size += profile.getWeight();
    }

    return size;
  }

  /**
   * Get statistics
   */
  getStats() {
    const distribution = this.getTierDistribution();
    
    return {
      totalNodes: this.profiles.size,
      effectiveSize: this.getEffectiveNetworkSize(),
      distribution,
      averageWeight: this.profiles.size > 0 
        ? this.getEffectiveNetworkSize() / this.profiles.size 
        : 0,
    };
  }

  /**
   * Clear all profiles (for testing)
   */
  clear() {
    this.profiles.clear();
  }
}

/**
 * Weighted Revocation Threshold Calculator
 * Uses trust tiers for revocation consensus
 */
export class WeightedRevocationCalculator {
  constructor(registry) {
    this.registry = registry;
  }

  /**
   * Calculate if a DOKO is revoked based on weighted attestations
   */
  async isRevoked(attestations, minNodes = 3) {
    const effectiveCount = await this.registry.calculateEffectiveCount(attestations);
    const effectiveNetworkSize = this.registry.getEffectiveNetworkSize();

    if (this.registry.profiles.size < minNodes) {
      return {
        revoked: false,
        reason: 'INSUFFICIENT_NETWORK',
        effectiveCount,
        threshold: null,
      };
    }

    // Threshold is 2/3 of effective network size
    const threshold = effectiveNetworkSize * (2 / 3);

    if (effectiveCount >= threshold) {
      return {
        revoked: true,
        effectiveCount,
        threshold,
        effectiveNetworkSize,
        confidence: effectiveCount / effectiveNetworkSize,
      };
    }

    return {
      revoked: false,
      reason: 'BELOW_THRESHOLD',
      effectiveCount,
      threshold,
      effectiveNetworkSize,
      progress: effectiveCount / threshold,
    };
  }
}

export default TrustTierRegistry;
