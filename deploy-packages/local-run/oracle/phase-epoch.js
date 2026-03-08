/**
 * Phase Epoch Module
 * 
 * Implements Star Trek TNG-inspired "frequency modulation" for cryptographic
 * derivation parameters. Like rotating shield frequencies to prevent the Borg
 * from adapting, this module provides time-based phase rotation for security.
 * 
 * PHILOSOPHY:
 * - Static keys are vulnerable to pre-computation attacks
 * - Time-based phases make captured values expire automatically
 * - All legitimate nodes stay in sync through deterministic time
 * - Attackers can't pre-compute future phases
 * 
 * SECURITY PROPERTIES:
 * - Phase rotates every EPOCH_DURATION hours
 * - All nodes with same code + same time = same phase
 * - Captured fingerprints/tokens expire after rotation
 * - No coordination needed - purely time-based
 * 
 * @module oracle/phase-epoch
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
// Using sha3_256 for all hashing operations for post-quantum consistency

// AGUWA — canonical mesh time source
import { aguwa } from '../mesh/aguwa.js';

// ============================================================
// CONFIGURATION
// ============================================================

/**
 * Default phase epoch duration in hours
 * Can be overridden based on time source quality
 * 
 * Atomic clock: 1 hour (tight security)
 * GPS/PTP: 2 hours
 * NTP: 6 hours (default)
 * Unsync: 12 hours (lenient for degraded mode)
 */
export const EPOCH_DURATION_HOURS = 6;

/**
 * Default grace period in minutes for phase transitions
 * Can be tightened for atomic-synced nodes
 * 
 * Atomic: 1 minute
 * GPS/PTP: 5 minutes
 * NTP: 15 minutes (default)
 * Unsync: 30 minutes
 */
export const GRACE_PERIOD_MINUTES = 15;

/**
 * Number of future phases to pre-compute for validation
 * Helps with slight clock differences
 */
export const LOOKAHEAD_PHASES = 1;

/**
 * Dynamic configuration based on time source quality
 * Import TimeSourceDetector to use these
 */
export const TRUST_LEVEL_CONFIG = {
  atomic: { epochHours: 1, graceMinutes: 1, toleranceMs: 100 },
  gps: { epochHours: 2, graceMinutes: 5, toleranceMs: 500 },
  ptp: { epochHours: 2, graceMinutes: 5, toleranceMs: 500 },
  ntp: { epochHours: 6, graceMinutes: 15, toleranceMs: 5000 },
  unsync: { epochHours: 12, graceMinutes: 30, toleranceMs: 30000 },
};

// Runtime configuration (can be updated by time source detector)
let activeConfig = {
  epochDurationHours: EPOCH_DURATION_HOURS,
  gracePeriodMinutes: GRACE_PERIOD_MINUTES,
  trustLevel: 'ntp',
};

/**
 * Update phase configuration based on time source quality
 * @param {string} trustLevel - Trust level from TimeSourceDetector
 */
export function setPhaseConfig(trustLevel) {
  const config = TRUST_LEVEL_CONFIG[trustLevel] || TRUST_LEVEL_CONFIG.ntp;
  activeConfig = {
    epochDurationHours: config.epochHours,
    gracePeriodMinutes: config.graceMinutes,
    trustLevel,
  };
  return activeConfig;
}

/**
 * Get current active configuration
 */
export function getActiveConfig() {
  return { ...activeConfig };
}

// ============================================================
// PHASE CALCULATION
// ============================================================

/**
 * Get effective epoch duration (respects active config)
 */
function getEffectiveEpochHours() {
  return activeConfig.epochDurationHours || EPOCH_DURATION_HOURS;
}

/**
 * Get effective grace period (respects active config)
 */
function getEffectiveGraceMinutes() {
  return activeConfig.gracePeriodMinutes || GRACE_PERIOD_MINUTES;
}

/**
 * Get the current phase epoch number
 * This is a monotonically increasing integer based on time
 * 
 * @param {number} [timestamp] - Optional timestamp (ms), defaults to now
 * @returns {number} Current phase epoch number
 */
export function getCurrentEpoch(timestamp = aguwa.now()) {
  const epochHours = getEffectiveEpochHours();
  const hours = Math.floor(timestamp / (1000 * 60 * 60));
  return Math.floor(hours / epochHours);
}

/**
 * Get the timestamp when the current epoch started
 * 
 * @param {number} [epoch] - Optional epoch number, defaults to current
 * @returns {number} Epoch start timestamp in ms
 */
export function getEpochStartTime(epoch = getCurrentEpoch()) {
  const epochHours = getEffectiveEpochHours();
  return epoch * epochHours * 60 * 60 * 1000;
}

/**
 * Get the timestamp when the current epoch ends
 * 
 * @param {number} [epoch] - Optional epoch number, defaults to current
 * @returns {number} Epoch end timestamp in ms
 */
export function getEpochEndTime(epoch = getCurrentEpoch()) {
  return getEpochStartTime(epoch + 1);
}

/**
 * Get time remaining in current epoch
 * 
 * @returns {Object} { hours, minutes, seconds, totalMs }
 */
export function getTimeUntilRotation() {
  const now = aguwa.now();
  const epochEnd = getEpochEndTime();
  const remainingMs = epochEnd - now;

  const hours = Math.floor(remainingMs / (1000 * 60 * 60));
  const minutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((remainingMs % (1000 * 60)) / 1000);

  return { hours, minutes, seconds, totalMs: remainingMs };
}

/**
 * Check if we're in the grace period (accept previous phase too)
 * Grace period is configurable based on time source quality
 * 
 * @returns {boolean} True if in grace period
 */
export function isInGracePeriod() {
  const epochStart = getEpochStartTime();
  const graceMinutes = getEffectiveGraceMinutes();
  const graceEnd = epochStart + (graceMinutes * 60 * 1000);
  return aguwa.now() < graceEnd;
}

/**
 * Get valid epochs for validation (current + grace period + lookahead)
 * 
 * @returns {number[]} Array of valid epoch numbers
 */
export function getValidEpochs() {
  const current = getCurrentEpoch();
  const epochs = [current];

  // Add previous epoch if in grace period
  if (isInGracePeriod() && current > 0) {
    epochs.push(current - 1);
  }

  // Add lookahead epochs
  for (let i = 1; i <= LOOKAHEAD_PHASES; i++) {
    epochs.push(current + i);
  }

  return epochs;
}

// ============================================================
// PHASE-MODULATED DERIVATION
// ============================================================

/**
 * Create a phase-modulated salt from a base salt
 * The resulting salt changes every epoch
 * 
 * @param {string} baseSalt - The static base salt
 * @param {number} [epoch] - Optional epoch, defaults to current
 * @returns {Uint8Array} Phase-modulated salt bytes
 */
export function modulateSalt(baseSalt, epoch = getCurrentEpoch()) {
  const combined = `${baseSalt}:phase:${epoch}`;
  return utf8ToBytes(combined);
}

/**
 * Create a phase-modulated info parameter
 * 
 * @param {string} baseInfo - The static base info string
 * @param {number} [epoch] - Optional epoch, defaults to current
 * @returns {Uint8Array} Phase-modulated info bytes
 */
export function modulateInfo(baseInfo, epoch = getCurrentEpoch()) {
  const combined = `${baseInfo}:epoch:${epoch}`;
  return utf8ToBytes(combined);
}

/**
 * Derive a phase-modulated value using HKDF
 * This is the core function for creating rotating secrets
 * 
 * @param {Uint8Array} inputKey - The input key material (e.g., code hash bytes)
 * @param {string} baseSalt - Base salt string
 * @param {string} baseInfo - Base info string  
 * @param {number} outputLength - Desired output length in bytes
 * @param {number} [epoch] - Optional epoch, defaults to current
 * @returns {Uint8Array} Derived bytes
 */
export function derivePhaseModulated(inputKey, baseSalt, baseInfo, outputLength, epoch = getCurrentEpoch()) {
  const salt = modulateSalt(baseSalt, epoch);
  const info = modulateInfo(baseInfo, epoch);

  return hkdf(sha3_256, inputKey, salt, info, outputLength);
}

/**
 * Derive a phase-modulated hex string
 * 
 * @param {Uint8Array} inputKey - The input key material
 * @param {string} baseSalt - Base salt string
 * @param {string} baseInfo - Base info string
 * @param {number} outputLength - Desired output length in bytes
 * @param {number} [epoch] - Optional epoch, defaults to current
 * @returns {string} Derived hex string
 */
export function derivePhaseModulatedHex(inputKey, baseSalt, baseInfo, outputLength, epoch = getCurrentEpoch()) {
  const bytes = derivePhaseModulated(inputKey, baseSalt, baseInfo, outputLength, epoch);
  return bytesToHex(bytes);
}

// ============================================================
// PHASE FINGERPRINT
// ============================================================

/**
 * Derive a phase-modulated fingerprint
 * This rotates every epoch while the base fingerprint stays stable
 * 
 * @param {string} codeHashHex - The oracle code hash (hex string)
 * @param {number} [epoch] - Optional epoch, defaults to current
 * @returns {string} Phase-modulated fingerprint (hex)
 */
export function derivePhaseFingerprint(codeHashHex, epoch = getCurrentEpoch()) {
  const hashBytes = hexToBytes(codeHashHex);

  return derivePhaseModulatedHex(
    hashBytes,
    'yakmesh-phase-fingerprint',
    'rotating-identity-v1',
    16,  // 16 bytes = 32 hex chars (shorter than stable fingerprint)
    epoch
  );
}

/**
 * Verify a phase fingerprint against valid epochs
 * Returns true if fingerprint matches any valid epoch
 * 
 * @param {string} codeHashHex - The oracle code hash
 * @param {string} fingerprintToVerify - The fingerprint to check
 * @returns {Object} { valid: boolean, epoch: number|null, reason: string }
 */
export function verifyPhaseFingerprint(codeHashHex, fingerprintToVerify) {
  const validEpochs = getValidEpochs();

  for (const epoch of validEpochs) {
    const expected = derivePhaseFingerprint(codeHashHex, epoch);
    if (expected === fingerprintToVerify) {
      return {
        valid: true,
        epoch,
        reason: epoch === getCurrentEpoch() ? 'CURRENT_PHASE' : 'GRACE_PERIOD',
      };
    }
  }

  return {
    valid: false,
    epoch: null,
    reason: 'PHASE_MISMATCH',
  };
}

// ============================================================
// CHALLENGE TOKEN MODULATION
// ============================================================

/**
 * Create a phase-modulated challenge token
 * Includes epoch information so challenges expire after rotation
 * 
 * @param {string} challengeBytes - Random challenge bytes (hex)
 * @param {string} challengerNodeId - Challenger's node ID
 * @param {string} targetNodeId - Target's node ID
 * @param {number} [epoch] - Optional epoch, defaults to current
 * @returns {Object} Challenge token with phase info
 */
export function createPhasedChallenge(challengeBytes, challengerNodeId, targetNodeId, epoch = getCurrentEpoch()) {
  // Create challenge binding hash
  const bindingData = `${challengeBytes}:${challengerNodeId}:${targetNodeId}:${epoch}`;
  const bindingHash = bytesToHex(sha3_256(utf8ToBytes(bindingData)));

  return {
    challenge: challengeBytes,
    epoch,
    binding: bindingHash.slice(0, 16),  // Short binding for verification
    expiresAt: getEpochEndTime(epoch) + (GRACE_PERIOD_MINUTES * 60 * 1000),
  };
}

/**
 * Verify a phased challenge is still valid
 * 
 * @param {Object} phasedChallenge - The challenge to verify
 * @returns {Object} { valid: boolean, reason: string }
 */
export function verifyPhasedChallenge(phasedChallenge) {
  const { epoch, expiresAt } = phasedChallenge;
  const validEpochs = getValidEpochs();

  // Check if epoch is valid
  if (!validEpochs.includes(epoch)) {
    return { valid: false, reason: 'EPOCH_EXPIRED' };
  }

  // Check if not expired
  if (aguwa.now() > expiresAt) {
    return { valid: false, reason: 'CHALLENGE_EXPIRED' };
  }

  return { valid: true, reason: 'VALID' };
}

// ============================================================
// PHASE STATUS
// ============================================================

/**
 * Get comprehensive phase status
 * Useful for debugging and monitoring
 * Now includes time source trust level information
 * 
 * @returns {Object} Phase status information
 */
export function getPhaseStatus() {
  const epoch = getCurrentEpoch();
  const remaining = getTimeUntilRotation();
  const inGrace = isInGracePeriod();
  const config = getActiveConfig();

  return {
    currentEpoch: epoch,
    epochDurationHours: config.epochDurationHours,
    gracePeriodMinutes: config.gracePeriodMinutes,
    inGracePeriod: inGrace,
    validEpochs: getValidEpochs(),
    epochStartedAt: new Date(getEpochStartTime()).toISOString(),
    epochEndsAt: new Date(getEpochEndTime()).toISOString(),
    timeUntilRotation: `${remaining.hours}h ${remaining.minutes}m ${remaining.seconds}s`,
    rotationMessage: remaining.hours < 1
      ? `⚠️ Phase rotation in ${remaining.minutes}m ${remaining.seconds}s`
      : `Next rotation in ${remaining.hours}h ${remaining.minutes}m`,
    // Time source trust level info
    timeSource: {
      trustLevel: config.trustLevel,
      toleranceMs: TRUST_LEVEL_CONFIG[config.trustLevel]?.toleranceMs || 5000,
      isAtomicSynced: config.trustLevel === 'atomic',
      isHighPrecision: ['atomic', 'gps', 'ptp'].includes(config.trustLevel),
    },
  };
}

/**
 * Format epoch as human-readable phase identifier
 * 
 * @param {number} epoch - Epoch number
 * @returns {string} Human-readable phase like "Phase-42α"
 */
export function formatPhaseId(epoch = getCurrentEpoch()) {
  const greekLetters = ['α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ'];
  const cyclePosition = epoch % greekLetters.length;
  const cycleNumber = Math.floor(epoch / greekLetters.length);

  return `Phase-${cycleNumber}${greekLetters[cyclePosition]}`;
}

// ============================================================
// UTILITY
// ============================================================

/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string
 * @returns {Uint8Array} Bytes
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Configuration
  EPOCH_DURATION_HOURS,
  GRACE_PERIOD_MINUTES,
  LOOKAHEAD_PHASES,
  TRUST_LEVEL_CONFIG,

  // Dynamic configuration
  setPhaseConfig,
  getActiveConfig,

  // Epoch functions
  getCurrentEpoch,
  getEpochStartTime,
  getEpochEndTime,
  getTimeUntilRotation,
  isInGracePeriod,
  getValidEpochs,

  // Modulation functions
  modulateSalt,
  modulateInfo,
  derivePhaseModulated,
  derivePhaseModulatedHex,

  // Fingerprint functions
  derivePhaseFingerprint,
  verifyPhaseFingerprint,

  // Challenge functions
  createPhasedChallenge,
  verifyPhasedChallenge,

  // Status functions
  getPhaseStatus,
  formatPhaseId,
};




// Alias for backward compatibility
export { setPhaseConfig as setTimeSourceConfig };
