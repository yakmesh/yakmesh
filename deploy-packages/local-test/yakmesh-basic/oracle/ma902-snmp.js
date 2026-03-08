/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║              📡 MA-902 SNMP MONITOR — CELESTIAL STONE TELEMETRY 📡          ║ 
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  The MA-902/S-C1 GPS Gigabit Time Server is a hardware MANI stone —          ║
 * ║  a celestial marker receiving signals from satellite constellations.          ║
 * ║                                                                               ║
 * ║  This module queries the MA-902 via SNMP v2c to extract:                     ║
 * ║  - GPS time (Unix epoch) with sub-second precision                           ║
 * ║  - Satellite lock status and constellation info                              ║
 * ║  - Visible/tracked/used satellite counts                                     ║
 * ║  - Alarm and quality indicators                                              ║
 * ║                                                                               ║
 * ║  Enterprise OID: 1.3.6.1.4.1.26381 (Chongqing Miaoan / MA-902)              ║
 * ║                                                                               ║
 * ║  SNMP data feeds directly into ManiTimeDetector for real-time trust          ║
 * ║  assessment — if satellites degrade, trust level adjusts automatically.      ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * @module mani/ma902-snmp
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';

const log = createLogger('mani:ma902');

// ============================================================
// MA-902 ENTERPRISE OID MAP
// ============================================================

/**
 * Enterprise OID prefix for the MA-902/S-C1 time server
 * Vendor: Chongqing Miaoan Technology (重庆妙安科技有限公司)
 * IANA Enterprise Number: 26381
 */
const MA902_ENTERPRISE_OID = '1.3.6.1.4.1.26381';
const MA902_DATA_PREFIX = `${MA902_ENTERPRISE_OID}.1.1`;

/**
 * MA-902 proprietary SNMP OID definitions
 * Discovered via SNMP walk on 2026-02-19
 */
const MA902_OIDS = {
  GPS_TIME: `${MA902_DATA_PREFIX}.1.0`,   // Unix timestamp (seconds)
  SUB_SECONDS: `${MA902_DATA_PREFIX}.2.0`,   // Sub-second counter (nanosecond-scale)
  LOCK_STATUS: `${MA902_DATA_PREFIX}.3.0`,   // 1 = locked to satellites, 0 = unlocked
  REF_SOURCE: `${MA902_DATA_PREFIX}.4.0`,   // Reference source type (1 = GPS)
  CONSTELLATION_MASK: `${MA902_DATA_PREFIX}.5.0`,   // Bitmask of active constellations
  SATS_VISIBLE: `${MA902_DATA_PREFIX}.6.0`,   // Number of satellites visible
  SATS_USED: `${MA902_DATA_PREFIX}.7.0`,   // Number of satellites in fix solution
  SATS_TRACKING: `${MA902_DATA_PREFIX}.8.0`,   // Number of satellites being tracked
  ALARM_STATUS: `${MA902_DATA_PREFIX}.9.0`,   // 0 = no alarms
  QUALITY: `${MA902_DATA_PREFIX}.10.0`,   // Timing quality indicator
  OFFSET: `${MA902_DATA_PREFIX}.11.0`,   // Clock offset
  RESERVED: `${MA902_DATA_PREFIX}.12.0`,   // Reserved (0xFFFFFFFF sentinel)
};

/**
 * Standard MIB-II OIDs for basic system info
 */
const SYSTEM_OIDS = {
  SYS_DESCR: '1.3.6.1.2.1.1.1.0',
  SYS_UPTIME: '1.3.6.1.2.1.1.3.0',
  SYS_NAME: '1.3.6.1.2.1.1.5.0',
};

/**
 * Constellation bitmask mapping
 * Based on observed values: GPS=1, BeiDou=2, GLONASS=4, Galileo=8, QZSS=16
 */
const CONSTELLATION_FLAGS = {
  GPS: 0x01,
  BEIDOU: 0x02,
  GLONASS: 0x04,
  GALILEO: 0x08,
  QZSS: 0x10,
};

/**
 * Minimum satellite thresholds for trust assessment
 */
const SAT_THRESHOLDS = {
  EXCELLENT: 8,   // >=8 sats = excellent fix
  GOOD: 5,   // >=5 sats = good fix  
  MARGINAL: 3,   // >=3 sats = marginal fix (3D requires minimum 4)
  DEGRADED: 1,   // 1-2 sats = degraded, likely no valid fix
};

// ============================================================
// MA-902 SNMP MONITOR
// ============================================================

/**
 * MA-902 GPS Time Server SNMP Monitor
 * 
 * Queries the MA-902 via SNMP v2c to extract real-time satellite
 * and timing telemetry. Emits events when status changes.
 * 
 * @example
 * const monitor = new MA902Monitor({ host: '192.168.1.30' });
 * monitor.on('telemetry', (data) => console.log(data));
 * await monitor.start();
 */
export class MA902Monitor extends EventEmitter {
  constructor(options = {}) {
    super();

    this.options = {
      host: options.host || '192.168.1.30',
      port: options.port || 161,
      community: options.community || 'public',
      pollInterval: options.pollInterval || 10000,   // 10s default
      retries: options.retries || 2,
      timeout: options.timeout || 3000,              // 3s SNMP timeout
      minSatellites: options.minSatellites || SAT_THRESHOLDS.MARGINAL,
      verbose: options.verbose || false,
    };

    this.snmpSession = null;
    this.snmpLib = null;
    this.pollTimer = null;
    this.available = false;
    this.lastTelemetry = null;
    this.consecutiveFailures = 0;
    this.maxConsecutiveFailures = 5;
    this.systemInfo = null;
  }

  /**
   * Initialize the SNMP library (lazy-loaded to avoid hard dependency)
   * @returns {boolean} Whether SNMP is available
   */
  async _initSnmp() {
    if (this.snmpLib) return true;

    try {
      this.snmpLib = await import('net-snmp');
      // Handle both default and named export patterns
      if (this.snmpLib.default) {
        this.snmpLib = this.snmpLib.default;
      }
      return true;
    } catch (err) {
      log.warn('net-snmp not available - MA-902 SNMP monitoring disabled', {
        hint: 'npm install net-snmp',
        error: err.message,
      });
      return false;
    }
  }

  /**
   * Create or recreate the SNMP session
   */
  _createSession() {
    if (this.snmpSession) {
      try { this.snmpSession.close(); } catch (e) { /* ignore */ }
    }

    this.snmpSession = this.snmpLib.createSession(this.options.host, this.options.community, {
      port: this.options.port,
      retries: this.options.retries,
      timeout: this.options.timeout,
      version: this.snmpLib.Version2c,
      transport: 'udp4',
    });

    this.snmpSession.on('error', (err) => {
      log.debug('SNMP session error', { error: err.message });
    });
  }

  /**
   * Start monitoring the MA-902
   * @returns {boolean} Whether monitoring started successfully
   */
  async start() {
    const snmpAvailable = await this._initSnmp();
    if (!snmpAvailable) {
      this.available = false;
      return false;
    }

    this._createSession();

    // Initial probe - verify the device responds
    const probe = await this._querySystemInfo();
    if (!probe) {
      log.warn('MA-902 not responding at ' + this.options.host, {
        action: 'Will retry on next poll cycle',
      });
    } else {
      this.systemInfo = probe;
      this.available = true;
      log.info('MA-902 GPS Time Server connected via SNMP', {
        host: this.options.host,
        description: probe.description,
        uptime: Math.round(probe.uptimeSeconds) + 's',
      });
    }

    // Start polling
    await this.poll();

    if (this.options.pollInterval > 0) {
      this.pollTimer = setInterval(() => this.poll(), this.options.pollInterval);
    }

    return this.available;
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.snmpSession) {
      try { this.snmpSession.close(); } catch (e) { /* ignore */ }
      this.snmpSession = null;
    }
    this.available = false;
  }

  /**
   * Query basic system info (sysDescr, sysUptime, sysName)
   * @returns {Object|null} System info or null on failure
   */
  async _querySystemInfo() {
    return new Promise((resolve) => {
      const oids = [SYSTEM_OIDS.SYS_DESCR, SYSTEM_OIDS.SYS_UPTIME, SYSTEM_OIDS.SYS_NAME];

      this.snmpSession.get(oids, (err, varbinds) => {
        if (err) {
          resolve(null);
          return;
        }

        try {
          resolve({
            description: varbinds[0].value.toString(),
            uptimeSeconds: parseInt(varbinds[1].value) / 100,
            name: varbinds[2].value.toString(),
          });
        } catch (e) {
          resolve(null);
        }
      });
    });
  }

  /**
   * Poll the MA-902 for current telemetry
   * @returns {Object|null} Telemetry data or null on failure
   */
  async poll() {
    if (!this.snmpSession) return null;

    const telemetry = await this._queryTelemetry();

    if (!telemetry) {
      this.consecutiveFailures++;

      if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
        if (this.available) {
          this.available = false;
          log.warn('MA-902 connection lost after ' + this.consecutiveFailures + ' failures', {
            host: this.options.host,
          });
          this.emit('connectionLost', { host: this.options.host });
        }
        // Recreate session on next attempt
        this._createSession();
      }

      return null;
    }

    // Success - reset failure counter
    if (!this.available) {
      this.available = true;
      log.info('MA-902 connection restored', { host: this.options.host });
      this.emit('connectionRestored', { host: this.options.host });
    }
    this.consecutiveFailures = 0;

    // Detect changes
    const previousTelemetry = this.lastTelemetry;
    this.lastTelemetry = telemetry;

    // Emit telemetry event
    this.emit('telemetry', telemetry);

    // Detect significant state changes
    if (previousTelemetry) {
      this._checkStateChanges(previousTelemetry, telemetry);
    }

    return telemetry;
  }

  /**
   * Query enterprise OIDs for MA-902 telemetry
   * @returns {Object|null} Parsed telemetry or null on failure
   */
  async _queryTelemetry() {
    return new Promise((resolve) => {
      const oids = Object.values(MA902_OIDS);

      this.snmpSession.get(oids, (err, varbinds) => {
        if (err) {
          log.debug('SNMP query failed', { error: err.message });
          resolve(null);
          return;
        }

        try {
          const keys = Object.keys(MA902_OIDS);
          const raw = {};
          varbinds.forEach((vb, i) => {
            if (this.snmpLib.isVarbindError(vb)) {
              raw[keys[i]] = null;
            } else {
              raw[keys[i]] = typeof vb.value === 'object' && Buffer.isBuffer(vb.value)
                ? parseInt(vb.value.toString('hex'), 16)
                : parseInt(vb.value.toString());
            }
          });

          resolve(this._parseTelemetry(raw));
        } catch (e) {
          log.debug('Telemetry parse error', { error: e.message });
          resolve(null);
        }
      });
    });
  }

  /**
   * Parse raw SNMP values into structured telemetry
   * @param {Object} raw - Raw OID values keyed by MA902_OIDS names
   * @returns {Object} Structured telemetry
   */
  _parseTelemetry(raw) {
    const gpsTimeUnix = raw.GPS_TIME;
    const systemTimeUnix = Math.floor(Date.now() / 1000);
    const clockDelta = gpsTimeUnix ? Math.abs(systemTimeUnix - gpsTimeUnix) : null;
    // Signed offset: positive = system ahead of GPS, negative = system behind
    const clockOffsetSeconds = gpsTimeUnix ? (gpsTimeUnix - systemTimeUnix) : null;

    const locked = raw.LOCK_STATUS === 1;
    const satsVisible = raw.SATS_VISIBLE || 0;
    const satsUsed = raw.SATS_USED || 0;
    const satsTracking = raw.SATS_TRACKING || 0;
    const alarmActive = raw.ALARM_STATUS !== 0;

    // Decode constellation bitmask
    const constellationMask = raw.CONSTELLATION_MASK || 0;
    const constellations = [];
    if (constellationMask & CONSTELLATION_FLAGS.GPS) constellations.push('GPS');
    if (constellationMask & CONSTELLATION_FLAGS.BEIDOU) constellations.push('BeiDou');
    if (constellationMask & CONSTELLATION_FLAGS.GLONASS) constellations.push('GLONASS');
    if (constellationMask & CONSTELLATION_FLAGS.GALILEO) constellations.push('Galileo');
    if (constellationMask & CONSTELLATION_FLAGS.QZSS) constellations.push('QZSS');

    // Assess satellite quality
    let satQuality;
    if (satsUsed >= SAT_THRESHOLDS.EXCELLENT) satQuality = 'excellent';
    else if (satsUsed >= SAT_THRESHOLDS.GOOD) satQuality = 'good';
    else if (satsUsed >= SAT_THRESHOLDS.MARGINAL) satQuality = 'marginal';
    else if (satsUsed >= SAT_THRESHOLDS.DEGRADED) satQuality = 'degraded';
    else satQuality = 'none';

    // Determine if GPS time source is trustworthy
    const synchronized = locked && satsUsed >= this.options.minSatellites && !alarmActive;

    // Build telemetry object
    const telemetry = {
      timestamp: Date.now(),
      host: this.options.host,

      // Time data
      gpsTime: gpsTimeUnix,
      gpsTimeISO: gpsTimeUnix ? new Date(gpsTimeUnix * 1000).toISOString() : null,
      subSeconds: raw.SUB_SECONDS,
      systemTime: systemTimeUnix,
      clockDeltaSeconds: clockDelta,
      clockOffsetSeconds: clockOffsetSeconds,  // signed: GPS - system (for AGUWA calibration)

      // Lock & sync
      locked,
      synchronized,
      refSource: raw.REF_SOURCE,

      // Satellite data
      satellites: {
        visible: satsVisible,
        used: satsUsed,
        tracking: satsTracking,
        quality: satQuality,
        constellations,
        constellationMask,
      },

      // Health
      alarm: alarmActive,
      alarmCode: raw.ALARM_STATUS,
      qualityIndicator: raw.QUALITY,
      offset: raw.OFFSET,

      // Trust assessment for MANI integration
      maniTrust: this._assessManiTrust(locked, satsUsed, alarmActive, clockDelta),
    };

    if (this.options.verbose) {
      log.info('MA-902 telemetry', {
        locked,
        sats: `${satsUsed}/${satsTracking}/${satsVisible}`,
        quality: satQuality,
        constellations: constellations.join('+'),
        delta: clockDelta !== null ? clockDelta + 's' : 'unknown',
      });
    }

    return telemetry;
  }

  /**
   * Assess MANI trust level based on MA-902 telemetry
   * 
   * This is the key integration point - translating hardware telemetry
   * into the MANI trust hierarchy.
   * 
   * @param {boolean} locked - Satellite lock status
   * @param {number} satsUsed - Satellites used in fix
   * @param {boolean} alarm - Alarm active
   * @param {number|null} clockDelta - Seconds between GPS and system time
   * @returns {Object} Trust assessment
   */
  _assessManiTrust(locked, satsUsed, alarm, clockDelta) {
    // GPS trust requires: locked, sufficient satellites, no alarms
    if (!locked || alarm) {
      return {
        trustworthy: false,
        level: 'degraded',
        reason: !locked ? 'No satellite lock' : 'Alarm active',
        confidence: 0,
      };
    }

    if (satsUsed < SAT_THRESHOLDS.MARGINAL) {
      return {
        trustworthy: false,
        level: 'degraded',
        reason: `Insufficient satellites (${satsUsed} < ${SAT_THRESHOLDS.MARGINAL})`,
        confidence: 0.2,
      };
    }

    // Clock delta sanity check - GPS leap seconds can cause up to ~37s offset
    // but anything beyond 120s suggests something is wrong
    if (clockDelta !== null && clockDelta > 120) {
      return {
        trustworthy: false,
        level: 'suspect',
        reason: `Clock delta too large (${clockDelta}s)`,
        confidence: 0.1,
      };
    }

    // Calculate confidence based on satellite count
    const satConfidence = Math.min(1.0, satsUsed / SAT_THRESHOLDS.EXCELLENT);

    if (satsUsed >= SAT_THRESHOLDS.EXCELLENT) {
      return {
        trustworthy: true,
        level: 'excellent',
        reason: `${satsUsed} satellites, locked, no alarms`,
        confidence: 1.0,
      };
    }

    if (satsUsed >= SAT_THRESHOLDS.GOOD) {
      return {
        trustworthy: true,
        level: 'good',
        reason: `${satsUsed} satellites, locked`,
        confidence: satConfidence,
      };
    }

    // Marginal (3-4 sats)
    return {
      trustworthy: true,
      level: 'marginal',
      reason: `${satsUsed} satellites (marginal fix)`,
      confidence: satConfidence,
    };
  }

  /**
   * Check for significant state changes between polls
   */
  _checkStateChanges(prev, curr) {
    // Lock lost
    if (prev.locked && !curr.locked) {
      log.warn('MA-902: Satellite lock LOST');
      this.emit('lockLost', curr);
    }

    // Lock acquired
    if (!prev.locked && curr.locked) {
      log.info('MA-902: Satellite lock acquired');
      this.emit('lockAcquired', curr);
    }

    // Alarm triggered
    if (!prev.alarm && curr.alarm) {
      log.warn('MA-902: Alarm triggered', { code: curr.alarmCode });
      this.emit('alarm', curr);
    }

    // Alarm cleared
    if (prev.alarm && !curr.alarm) {
      log.info('MA-902: Alarm cleared');
      this.emit('alarmCleared', curr);
    }

    // Satellite degradation (significant drop)
    if (prev.satellites.used - curr.satellites.used >= 3) {
      log.warn('MA-902: Significant satellite degradation', {
        before: prev.satellites.used,
        after: curr.satellites.used,
      });
      this.emit('satelliteDegradation', {
        before: prev.satellites.used,
        after: curr.satellites.used,
        telemetry: curr,
      });
    }

    // Trust level change
    if (prev.maniTrust.level !== curr.maniTrust.level) {
      log.info('MA-902: Trust level changed', {
        from: prev.maniTrust.level,
        to: curr.maniTrust.level,
      });
      this.emit('trustChanged', {
        from: prev.maniTrust.level,
        to: curr.maniTrust.level,
        telemetry: curr,
      });
    }
  }

  /**
   * Get current telemetry (last polled values)
   * @returns {Object|null} Latest telemetry or null if unavailable
   */
  getTelemetry() {
    return this.lastTelemetry;
  }

  /**
   * Check if the MA-902 is available and responding
   * @returns {boolean}
   */
  isAvailable() {
    return this.available;
  }

  /**
   * Check if the MA-902 has a valid satellite lock
   * @returns {boolean}
   */
  isLocked() {
    return this.lastTelemetry?.locked ?? false;
  }

  /**
   * Check if the MA-902 is synchronized (locked + sufficient sats + no alarms)
   * @returns {boolean}
   */
  isSynchronized() {
    return this.lastTelemetry?.synchronized ?? false;
  }

  /**
   * Get satellite count (used in fix)
   * @returns {number}
   */
  getSatelliteCount() {
    return this.lastTelemetry?.satellites?.used ?? 0;
  }

  /**
   * Get the MANI trust assessment from latest telemetry
   * @returns {Object} Trust assessment
   */
  getManiTrust() {
    return this.lastTelemetry?.maniTrust ?? {
      trustworthy: false,
      level: 'unavailable',
      reason: 'No telemetry data',
      confidence: 0,
    };
  }

  /**
   * Get status summary for API responses
   * @returns {Object} Status object
   */
  getStatus() {
    if (!this.available || !this.lastTelemetry) {
      return {
        available: false,
        host: this.options.host,
        reason: 'MA-902 not responding or SNMP disabled',
      };
    }

    const t = this.lastTelemetry;
    return {
      available: true,
      host: this.options.host,
      locked: t.locked,
      synchronized: t.synchronized,
      satellites: t.satellites,
      gpsTime: t.gpsTimeISO,
      clockDelta: t.clockDeltaSeconds,
      clockOffset: t.clockOffsetSeconds,  // signed: GPS - system (seconds)
      alarm: t.alarm,
      quality: t.qualityIndicator,
      trust: t.maniTrust,
      uptime: this.systemInfo?.uptimeSeconds ?? null,
      lastPoll: t.timestamp,
    };
  }
}

// ============================================================
// SINGLETON INSTANCE
// ============================================================

let globalMonitor = null;

/**
 * Get or create the global MA-902 monitor instance
 * @param {Object} options - Monitor options
 * @returns {MA902Monitor}
 */
export function getMA902Monitor(options = {}) {
  if (!globalMonitor) {
    globalMonitor = new MA902Monitor(options);
  }
  return globalMonitor;
}

// ============================================================
// EXPORTS
// ============================================================

export {
  MA902_OIDS,
  MA902_ENTERPRISE_OID,
  CONSTELLATION_FLAGS,
  SAT_THRESHOLDS,
};

export default {
  MA902Monitor,
  getMA902Monitor,
  MA902_OIDS,
  MA902_ENTERPRISE_OID,
  CONSTELLATION_FLAGS,
  SAT_THRESHOLDS,
};
