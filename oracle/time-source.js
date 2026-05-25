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
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║                    ⏱️ MANI TIME SYNCHRONIZATION - PRECIOUS PRECISION ⏱️        ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  In Tibetan Buddhism, MANI stones are sacred rocks inscribed with mantras,   ║
 * ║  placed along mountain paths as immutable markers of time and devotion.      ║
 * ║  Each stone is precisely positioned, never moved—eternal reference points    ║
 * ║  for travelers navigating the high passes.                                   ║
 * ║                                                                               ║
 * ║  The MANI Time Protocol embodies this principle:                             ║
 * ║  - Atomic clocks as primary MANI stones (immutable reference)                ║
 * ║  - GPS signals as celestial markers (from the heavens)                       ║
 * ║  - Each node synchronizes to the most precious time source available         ║
 * ║  - Phase tolerance tightens with higher-quality sources                      ║
 * ║                                                                               ║
 * ║  PROTOCOL PHILOSOPHY:                                                         ║
 * ║    "Precious stones mark the path" - Quality time enables tight consensus    ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * MANI Time Source Detection Module
 * 
 * Detects and integrates with various precision time sources:
 * - PCIe Atomic Clocks (CSAC, Rubidium) - Primary MANI stones
 * - GPS receivers with PPS - Celestial markers
 * - PTP (IEEE 1588) hardware timestamping - Network reference
 * - Standard NTP (fallback) - Basic synchronization
 * 
 * Provides trust levels based on time source quality,
 * enabling tighter phase tolerances for atomic-synced nodes.
 * 
 * TRUST LEVELS:
 * - ATOMIC (Level 3): PCIe atomic clock, ±100ms tolerance
 * - GPS (Level 2): Hardware GPS/PPS, ±500ms tolerance
 * - STANDARD (Level 1): NTP only, ±5000ms tolerance
 * 
 * @module mani/time-source
 */

import { execSync, exec } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { platform } from 'os';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { MA902Monitor, getMA902Monitor } from './ma902-snmp.js';
import { SerialGpsMonitor } from './gps-serial.js';

const log = createLogger('mani:time-source');

// ============================================================
// SILENT COMMAND EXECUTION HELPER
// ============================================================

/**
 * Execute a command silently, returning null on any failure
 * This prevents console spam from commands that don't exist or fail
 * 
 * @param {string} command - Command to execute
 * @param {number} timeout - Timeout in ms (default 5000)
 * @returns {string|null} - Command output or null on failure
 */
function execSilent(command, timeout = 5000) {
  try {
    return execSync(command, {
      encoding: 'utf8',
      timeout,
      stdio: ['pipe', 'pipe', 'pipe'], // Capture all streams, don't inherit
      windowsHide: true, // Hide window on Windows
    });
  } catch (e) {
    // Silently return null - command not available or failed
    return null;
  }
}

// ============================================================
// CONSTANTS
// ============================================================

/**
 * MANI Time Trust Levels - Quality of time reference
 * Named after the precious gems in Buddhist tradition
 */
export const ManiTrustLevel = {
  QUANTUM: 'quantum',   // Quantum optical network (WR-PTP, optical atomic, entanglement-based)
  ATOMIC: 'atomic',     // PCIe atomic clock (CSAC, Rubidium) - Most precious MANI stone
  GPS: 'gps',           // GPS with PPS signal - Celestial marker
  PTP: 'ptp',           // IEEE 1588 PTP synchronized - Network reference
  NTP: 'ntp',           // Standard NTP - Basic synchronization
  UNSYNC: 'unsync',     // No reliable time source - Lost on the path
};

// Backward compatibility alias
export const TimeTrustLevel = ManiTrustLevel;

/**
 * MANI Phase Tolerance - Precision in milliseconds per trust level
 * Higher-quality MANI stones enable tighter consensus
 */
export const ManiPhaseTolerance = {
  [ManiTrustLevel.QUANTUM]: 1,    // ±1ms for quantum (sub-nanosecond capable)
  [ManiTrustLevel.ATOMIC]: 100,      // ±100ms for atomic
  [ManiTrustLevel.GPS]: 500,         // ±500ms for GPS
  [ManiTrustLevel.PTP]: 500,         // ±500ms for PTP
  [ManiTrustLevel.NTP]: 5000,        // ±5 seconds for NTP
  [ManiTrustLevel.UNSYNC]: 30000,    // ±30 seconds for unsync (degraded mode)
};

// Backward compatibility alias
export const PhaseTolerance = ManiPhaseTolerance;

/**
 * MANI Stratum Levels - Hierarchical quality (like layers of a stupa)
 */
export const ManiStratumLevel = {
  [ManiTrustLevel.QUANTUM]: 0, // Quantum reference (highest - the jewel atop the stupa)
  [ManiTrustLevel.ATOMIC]: 0,  // Reference clock (primary MANI stone)
  [ManiTrustLevel.GPS]: 1,     // Primary server (celestial marker)
  [ManiTrustLevel.PTP]: 1,     // Primary server (network reference)
  [ManiTrustLevel.NTP]: 2,     // Secondary server (distant echo)
  [ManiTrustLevel.UNSYNC]: 16, // Unsynchronized (lost on the path)
};

// Backward compatibility alias
export const StratumLevel = ManiStratumLevel;

// ============================================================
// DEVICE PATHS
// ============================================================

/**
 * Common device paths for time sources
 */
const DEVICE_PATHS = {
  linux: {
    pps: ['/dev/pps0', '/dev/pps1', '/dev/pps2'],
    ptp: ['/dev/ptp0', '/dev/ptp1', '/dev/ptp2'],
    gps: ['/dev/ttyUSB0', '/dev/ttyACM0', '/dev/gps0'],
    chrony: '/var/run/chrony/chronyd.sock',
    ntpd: '/var/run/ntpd.pid',
  },
  win32: {
    // Windows uses different mechanisms
    timeService: 'w32tm',
    ptp: null, // Requires vendor drivers
  },
  darwin: {
    pps: ['/dev/pps0'],
    ptp: ['/dev/ptp0'],
    gps: ['/dev/cu.usbserial*'],
  },
};

// ============================================================
// MANI TIME SOURCE DETECTOR
// ============================================================

/**
 * MANI Time Source Detector
 * Automatically detects available time sources and their quality,
 * like a pilgrim discovering MANI stones along the mountain path.
 */
export class ManiTimeDetector extends EventEmitter {
  constructor(options = {}) {
    super();

    this.options = {
      // Enable hardware detection
      detectHardware: options.detectHardware ?? true,
      // Enable NTP status checking
      checkNtp: options.checkNtp ?? true,
      // Custom device paths
      customDevices: options.customDevices || {},
      // Refresh interval (ms)
      refreshInterval: options.refreshInterval || 60000,
      // Verbose logging
      verbose: options.verbose || false,
      // MA-902 SNMP monitoring configuration
      ma902: {
        enabled: true, // ALWAYS ENABLED - never opt-in
        host: options.ma902?.host || '192.168.1.30',
        pollInterval: options.ma902?.pollInterval || 10000,
        ...options.ma902
      },
    };

    this.platform = platform();
    this.detectedSources = new Map();
    this.primarySource = null;
    this.trustLevel = ManiTrustLevel.UNSYNC;
    this.lastCheck = null;
    this.refreshTimer = null;

    // MA-902 SNMP monitor instance
    this.ma902Monitor = null;

    // Generic Serial GPS monitor (u-blox, NMEA, etc.)
    this.genericGpsMonitor = null;
  }

  /**
   * Start continuous monitoring of time sources
   */
  async start() {
    // 1. Start MA-902 SNMP monitor
    // We only initialize if the host is reachable to avoid "assinine" timeouts on other nodes.
    try {
      const ma902Host = this.options.ma902?.host || '192.168.1.30';

      // Fast probe (ping/port check) before committing to a heavy monitor loop
      const isReachable = this.platform === 'win32'
        ? execSilent(`ping -n 1 -w 500 ${ma902Host}`)
        : execSilent(`ping -c 1 -W 1 ${ma902Host}`);

      if (isReachable) {
        log.info(`📡 MA-902 Hardware detected at ${ma902Host}. Engaging SNMP telemetry...`);
        this.ma902Monitor = new MA902Monitor({
          verbose: this.options.verbose,
          ...this.options.ma902,
        });

        // Forward MA-902 events
        this.ma902Monitor.on('telemetry', (data) => {
          this.emit('ma902:telemetry', data);
        });
        this.ma902Monitor.on('lockLost', (data) => {
          log.warn('MA-902 satellite lock lost — GPS trust degraded');
          this.emit('ma902:lockLost', data);
          this.detect();
        });
        this.ma902Monitor.on('lockAcquired', (data) => {
          log.info('MA-902 satellite lock acquired — GPS trust restored');
          this.emit('ma902:lockAcquired', data);
          this.detect();
        });
        this.ma902Monitor.on('alarm', (data) => {
          this.emit('ma902:alarm', data);
          this.detect();
        });
        this.ma902Monitor.on('trustChanged', (data) => {
          this.emit('ma902:trustChanged', data);
          this.detect();
        });

        await this.ma902Monitor.start();
      } else {
        if (this.options.verbose) {
          log.debug(`MA-902 host ${ma902Host} not found on this local network. skipping.`);
        }
      }
    } catch (err) {
      log.warn('MA-902 SNMP monitor failed to start', { error: err.message });
      this.ma902Monitor = null;
    }

    // 2. Start Generic Serial/USB GPS Hardware Monitor
    if (this.options.detectHardware) {
      const probePaths = this.platform === 'linux' ? DEVICE_PATHS.linux.gps :
        (this.platform === 'darwin' ? DEVICE_PATHS.darwin.gps : []);

      for (const gpsPath of probePaths) {
        if (existsSync(gpsPath)) {
          log.info(`📡 Universal GPS Scanner: Found candidate peripheral at ${gpsPath}`);
          this.genericGpsMonitor = new SerialGpsMonitor({ device: gpsPath });

          this.genericGpsMonitor.on('telemetry', (data) => {
            this.emit('genericGps:telemetry', data);
            this.detect();
          });
          this.genericGpsMonitor.on('lockAcquired', (data) => {
            this.emit('genericGps:lockAcquired', data);
            this.detect();
          });
          this.genericGpsMonitor.on('lockLost', (data) => {
            this.emit('genericGps:lockLost', data);
            this.detect();
          });

          this.genericGpsMonitor.start();
          break; // Use the first available serial device
        }
      }
    }

    this.detect();

    if (this.options.refreshInterval > 0) {
      this.refreshTimer = setInterval(() => {
        this.detect();
      }, this.options.refreshInterval);
    }

    return this;
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.ma902Monitor) {
      this.ma902Monitor.stop();
      this.ma902Monitor = null;
    }
    if (this.genericGpsMonitor) {
      this.genericGpsMonitor.stop();
      this.genericGpsMonitor = null;
    }
  }

  /**
   * Detect all available time sources
   * @returns {Object} Detection results
   */
  detect() {
    const results = {
      platform: this.platform,
      timestamp: Date.now(),
      sources: {},
      primarySource: null,
      trustLevel: TimeTrustLevel.UNSYNC,
      phaseTolerance: PhaseTolerance[TimeTrustLevel.UNSYNC],
    };

    try {
      // Check for atomic clock (highest priority)
      const atomicResult = this.detectAtomicClock();
      if (atomicResult.detected) {
        results.sources.atomic = atomicResult;
        this.detectedSources.set('atomic', atomicResult);
      }

      // Check for GPS/PPS (enriched with MA-902 SNMP telemetry)
      const gpsResult = this.detectGPS();

      // Enrich GPS result with Generic Serial/USB GPS telemetry if available
      if (this.genericGpsMonitor) {
        const telemetry = this.genericGpsMonitor.getTelemetry();
        if (telemetry) {
          gpsResult.detected = true;
          gpsResult.device = gpsResult.device || this.genericGpsMonitor.device;
          gpsResult.synchronized = gpsResult.synchronized || telemetry.locked;
          gpsResult.satellites = gpsResult.satellites || telemetry.satellites;
          gpsResult.latitude = gpsResult.latitude || telemetry.latitude;
          gpsResult.longitude = gpsResult.longitude || telemetry.longitude;
          gpsResult.serialGps = {
            device: this.genericGpsMonitor.device,
            locked: telemetry.locked,
            satellites: telemetry.satellites,
            gpsTime: new Date(telemetry.timestamp).toISOString(),
            valid: telemetry.valid
          };
        }
      }

      // Enrich GPS result with MA-902 SNMP data if available
      if (this.ma902Monitor && this.ma902Monitor.isAvailable()) {
        const telemetry = this.ma902Monitor.getTelemetry();
        if (telemetry) {
          gpsResult.detected = true;
          gpsResult.device = gpsResult.device || 'MA-902/S-C1';
          gpsResult.synchronized = telemetry.synchronized;
          gpsResult.satellites = telemetry.satellites.used;
          gpsResult.ma902 = {
            host: telemetry.host,
            locked: telemetry.locked,
            satellites: telemetry.satellites,
            gpsTime: telemetry.gpsTimeISO,
            clockDelta: telemetry.clockDeltaSeconds,
            alarm: telemetry.alarm,
            quality: telemetry.qualityIndicator,
            trust: telemetry.maniTrust,
            constellations: telemetry.satellites.constellations,
          };
        }
      }

      if (gpsResult.detected) {
        results.sources.gps = gpsResult;
        this.detectedSources.set('gps', gpsResult);
      }

      // Check for PTP
      const ptpResult = this.detectPTP();
      if (ptpResult.detected) {
        results.sources.ptp = ptpResult;
        this.detectedSources.set('ptp', ptpResult);
      }

      // Check NTP status — if MA-902 is the NTP source, note that
      const ntpResult = this.detectNTP();
      if (ntpResult.server && this.ma902Monitor?.isAvailable()) {
        const ma902Host = this.ma902Monitor.options.host;
        if (ntpResult.server === ma902Host || ntpResult.server.includes(ma902Host)) {
          ntpResult.ma902Backed = true;
        }
      }
      results.sources.ntp = ntpResult;
      this.detectedSources.set('ntp', ntpResult);

      // Determine primary source and trust level
      if (atomicResult.detected && atomicResult.synchronized) {
        results.primarySource = 'atomic';
        results.trustLevel = TimeTrustLevel.ATOMIC;
      } else if (gpsResult.detected && gpsResult.synchronized) {
        results.primarySource = 'gps';
        results.trustLevel = TimeTrustLevel.GPS;
      } else if (ptpResult.detected && ptpResult.synchronized) {
        results.primarySource = 'ptp';
        results.trustLevel = TimeTrustLevel.PTP;
      } else if (ntpResult.synchronized) {
        results.primarySource = 'ntp';
        results.trustLevel = TimeTrustLevel.NTP;
      }

      // MA-902 data enrichment for results
      if (this.ma902Monitor) {
        results.ma902 = this.ma902Monitor.getStatus();
      }

      results.phaseTolerance = PhaseTolerance[results.trustLevel];

    } catch (error) {
      if (this.options.verbose) {
        log.error('Time source detection error', { error: error.message });
      }
    }

    // Update state
    this.primarySource = results.primarySource;
    this.trustLevel = results.trustLevel;
    this.lastCheck = results.timestamp;

    // Emit event
    this.emit('detected', results);

    if (this.options.verbose) {
      this.logDetectionResults(results);
    }

    return results;
  }

  /**
   * Detect PCIe atomic clock
   */
  detectAtomicClock() {
    const result = {
      detected: false,
      synchronized: false,
      device: null,
      type: null,
      precision: null,
      stratum: null,
    };

    if (this.platform === 'linux') {
      // Check for common atomic clock indicators

      // 1. Check chrony sources for atomic reference
      try {
        const chronyOutput = execSilent('chronyc sources 2>/dev/null', { encoding: 'utf8', timeout: 5000 });

        // Look for PPS or atomic sources (marked with * for selected, # for preferred)
        if (chronyOutput.includes('PPS') || chronyOutput.includes('ATOM')) {
          const lines = chronyOutput.split('\n');
          for (const line of lines) {
            if ((line.includes('PPS') || line.includes('ATOM')) && (line.startsWith('*') || line.startsWith('#'))) {
              result.detected = true;
              result.synchronized = line.startsWith('*');
              result.type = line.includes('ATOM') ? 'CSAC' : 'PPS';
              result.stratum = 0;
              result.precision = 100; // nanoseconds
            }
          }
        }
      } catch (e) {
        // chrony not available
      }

      // 2. Check for PPS devices that might be atomic
      for (const ppsPath of DEVICE_PATHS.linux.pps) {
        if (existsSync(ppsPath)) {
          try {
            // Read PPS device info
            const ppsNum = ppsPath.match(/pps(\d+)/)?.[1];
            const ppsInfoPath = `/sys/class/pps/pps${ppsNum}/`;

            if (existsSync(ppsInfoPath)) {
              const name = readFileSync(`${ppsInfoPath}name`, 'utf8').trim();

              // Known atomic clock identifiers
              const atomicIndicators = ['atomic', 'csac', 'rubidium', 'caesium', 'cesium', 'sa.45'];
              if (atomicIndicators.some(ind => name.toLowerCase().includes(ind))) {
                result.detected = true;
                result.device = ppsPath;
                result.type = name;
                result.stratum = 0;
              }
            }
          } catch (e) {
            // Can't read PPS info
          }
        }
      }

      // 3. Check for known PCIe atomic clock devices
      try {
        const lspciOutput = execSilent('lspci 2>/dev/null | grep -i "time\\|clock\\|atomic"', { encoding: 'utf8', timeout: 5000 });
        if (lspciOutput.trim()) {
          result.detected = true;
          result.type = 'PCIe Time Card';
          result.device = lspciOutput.trim().split('\n')[0];
        }
      } catch (e) {
        // lspci not available or no match
      }
    }

    if (this.platform === 'win32') {
      // Windows: Check for vendor-specific atomic clock software
      try {
        // Check for Jackson Labs CSAC driver
        const tasklist = execSilent('tasklist 2>nul | findstr /i "csac jacksonlabs rubidium"', { encoding: 'utf8', timeout: 5000 });
        if (tasklist.trim()) {
          result.detected = true;
          result.type = 'CSAC (Windows)';
        }
      } catch (e) {
        // Not found
      }
    }

    return result;
  }

  /**
   * Detect GPS receiver with PPS (Universal Hardware Probe)
   */
  detectGPS() {
    const result = {
      detected: false,
      synchronized: false,
      device: null,
      type: 'Generic GPS',
      hasPPS: false,
      satellites: null,
      latitude: null,
      longitude: null,
    };

    // 1. Probe Serial/USB GPS Hardware (Linux/macOS/Windows)
    const probePaths = this.platform === 'linux' ? DEVICE_PATHS.linux.gps :
      (this.platform === 'darwin' ? DEVICE_PATHS.darwin.gps : []);

    for (const gpsPath of probePaths) {
      if (existsSync(gpsPath)) {
        result.detected = true;
        result.device = gpsPath;
        result.type = 'NMEA Serial GPS';
        break;
      }
    }

    if (this.platform === 'linux') {
      // 2. Check if gpsd is running (shrapnel/ublox/etc)
      try {
        const gpsdStatus = execSilent('systemctl is-active gpsd 2>/dev/null || pgrep gpsd');
        if (gpsdStatus) {
          result.detected = true;
          result.type = 'gpsd Managed Receiver';

          // Try to get GPS info from gpsd
          const gpsInfo = execSilent('gpspipe -w -n 5 2>/dev/null | head -1');
          if (gpsInfo) {
            try {
              const data = JSON.parse(gpsInfo);
              if (data.class === 'TPV') {
                result.synchronized = data.mode >= 2;
                result.latitude = data.lat;
                result.longitude = data.lon;
              }
            } catch (e) { }
          }
        }
      } catch (e) { }

      // 3. Check for associated PPS hardware pin
      for (const ppsPath of DEVICE_PATHS.linux.pps) {
        if (existsSync(ppsPath)) {
          result.hasPPS = true;
          break;
        }
      }
    }

    // 4. Windows Generic Hardware Probe (COM ports)
    if (this.platform === 'win32') {
      try {
        const comPorts = execSilent('wmic path Win32_SerialPort get DeviceID');
        if (comPorts && comPorts.includes('COM')) {
          result.detected = true;
          result.type = 'Windows Serial GPS Candidate';
        }
      } catch (e) { }
    }

    return result;
  }

/**
 * Detect PTP (IEEE 1588) time synchronization
 */
detectPTP() {
  const result = {
    detected: false,
    synchronized: false,
    device: null,
    master: null,
    offset: null,
  };

  if (this.platform === 'linux') {
    // 1. Check for PTP devices
    for (const ptpPath of DEVICE_PATHS.linux.ptp) {
      if (existsSync(ptpPath)) {
        result.detected = true;
        result.device = ptpPath;
        break;
      }
    }

    // 2. Check if ptp4l is running
    {
      const ptp4lStatus = execSilent('systemctl is-active ptp4l 2>/dev/null || pgrep ptp4l');
      if (ptp4lStatus && ptp4lStatus.trim()) {
        result.detected = true;

        // Try to get PTP status
        const pmcOutput = execSilent('pmc -u -b 0 "GET CURRENT_DATA_SET" 2>/dev/null');
        if (pmcOutput && pmcOutput.includes('offsetFromMaster')) {
          const match = pmcOutput.match(/offsetFromMaster\s+(-?\d+)/);
          if (match) {
            result.offset = parseInt(match[1]);
            result.synchronized = Math.abs(result.offset) < 1000000; // < 1ms
          }
        }
      }
    }

    // 3. Check phc2sys (syncs PTP to system clock)
    {
      const phc2sysStatus = execSilent('pgrep phc2sys');
      if (phc2sysStatus && phc2sysStatus.trim()) {
        result.synchronized = true;
      }
    }
  }
  // 4. Check for Meinberg PTP hardware (PTP270PEX, etc.)
  try {
    // Check for Meinberg driver/software via lspci
    const meinbergCheck = execSilent('lspci 2>/dev/null | grep -i meinberg', { encoding: 'utf8', timeout: 5000 });
    if (meinbergCheck.trim()) {
      result.detected = true;
      result.device = 'Meinberg PTP';
      result.type = meinbergCheck.includes('270') ? 'PTP270PEX' : 'Meinberg PTP Card';

      // Try to get sync status from mbgstatus if available
      try {
        const mbgStatus = execSilent('mbgstatus 2>/dev/null | head -20', { encoding: 'utf8', timeout: 5000 });
        if (mbgStatus.includes('SYNC') || mbgStatus.includes('synchronized')) {
          result.synchronized = true;
        }
        // Extract offset if available
        const offsetMatch = mbgStatus.match(/offset[:\s]+(-?\d+)/i);
        if (offsetMatch) {
          result.offset = parseInt(offsetMatch[1]);
        }
      } catch (e) {
        // mbgstatus not available, check via standard PTP
      }
    }
  } catch (e) {
    // Meinberg not found via lspci
  }

  // 5. Windows: Check for Meinberg driver + MbgAdjTm service
  if (this.platform === 'win32') {
    try {
      const driverCheck = execSilent('driverquery /v 2>nul | findstr /i meinberg', { encoding: 'utf8', timeout: 5000 });
      if (driverCheck.trim()) {
        result.detected = true;
        result.type = 'Meinberg PTP270PEX (Windows)';

        // Check if MbgAdjTm service is running (disciplines system clock from PTP card)
        const svcCheck = execSilent('sc query MbgAdjTm 2>nul', { encoding: 'utf8', timeout: 3000 });
        if (svcCheck && /RUNNING/i.test(svcCheck)) {
          result.serviceRunning = true;

          // Cross-reference with MA-902 SNMP: if MA-902 is GPS-locked and serving PTP,
          // and MbgAdjTm is running, the PTP card is receiving disciplined time
          if (this.ma902Monitor?.isAvailable() && this.ma902Monitor.isLocked()) {
            result.synchronized = true;
            result.source = 'ma902-ptp';
            result.device = 'PTP270PEX ← MA-902/S-C1';
          }
        }
      }
    } catch (e) {
      // Meinberg driver not found
    }
  }

  return result;
}

/**
 * Detect NTP synchronization status
 */
detectNTP() {
  const result = {
    detected: true, // NTP is always "available" conceptually
    synchronized: false,
    stratum: 16,
    offset: null,
    server: null,
    method: null,
  };

  if (this.platform === 'linux') {
    // 1. Check chrony
    try {
      const chronyTracking = execSilent('chronyc tracking 2>/dev/null', { encoding: 'utf8', timeout: 5000 });

      if (chronyTracking.includes('Reference ID')) {
        result.method = 'chrony';

        // Parse stratum
        const stratumMatch = chronyTracking.match(/Stratum\s+:\s+(\d+)/);
        if (stratumMatch) {
          result.stratum = parseInt(stratumMatch[1]);
          result.synchronized = result.stratum < 16;
        }

        // Parse offset
        const offsetMatch = chronyTracking.match(/System time\s+:\s+([\d.]+)\s+seconds\s+(slow|fast)/);
        if (offsetMatch) {
          result.offset = parseFloat(offsetMatch[1]) * (offsetMatch[2] === 'slow' ? -1 : 1);
        }

        // Parse reference
        const refMatch = chronyTracking.match(/Reference ID\s+:\s+([^\s]+)\s+\(([^)]+)\)/);
        if (refMatch) {
          result.server = refMatch[2];
        }
      }
    } catch (e) {
      // chrony not available
    }

    // 2. Check systemd-timesyncd
    if (!result.synchronized) {
      try {
        const timedatectl = execSilent('timedatectl show 2>/dev/null', { encoding: 'utf8', timeout: 5000 });

        if (timedatectl.includes('NTPSynchronized=yes')) {
          result.synchronized = true;
          result.method = 'systemd-timesyncd';
          result.stratum = 3; // Assume stratum 3 for systemd-timesyncd
        }
      } catch (e) {
        // timedatectl not available
      }
    }

    // 3. Check ntpd
    if (!result.synchronized) {
      try {
        const ntpq = execSilent('ntpq -p 2>/dev/null | grep "^\\*"', { encoding: 'utf8', timeout: 5000 });
        if (ntpq.trim()) {
          result.synchronized = true;
          result.method = 'ntpd';
          const parts = ntpq.trim().split(/\s+/);
          result.server = parts[0]?.replace('*', '');
          result.stratum = parseInt(parts[2]) || 3;
        }
      } catch (e) {
        // ntpd not available
      }
    }
  }

  if (this.platform === 'win32') {
    const w32tm = execSilent('w32tm /query /status');

    if (w32tm && w32tm.includes('Source:') && !w32tm.includes('Free-running')) {
      result.synchronized = true;
      result.method = 'w32tm';

      const sourceMatch = w32tm.match(/Source:\s+(.+)/);
      if (sourceMatch) {
        result.server = sourceMatch[1].trim();
      }

      const stratumMatch = w32tm.match(/Stratum:\s+(\d+)/);
      if (stratumMatch) {
        result.stratum = parseInt(stratumMatch[1]);
      }
    }
  }

  if (this.platform === 'darwin') {
    try {
      const sntp = execSilent('sntp -d time.apple.com 2>&1 | head -5', { encoding: 'utf8', timeout: 10000 });
      if (sntp.includes('offset')) {
        result.synchronized = true;
        result.method = 'sntp';
        result.server = 'time.apple.com';
      }
    } catch (e) {
      // sntp failed
    }
  }

  return result;
}

/**
 * Log detection results
 */
logDetectionResults(results) {
  log.info('Time Source Detection Results', {
    platform: results.platform,
    trustLevel: results.trustLevel.toUpperCase(),
    phaseTolerance: results.phaseTolerance,
    primarySource: results.primarySource || 'none',
  });

  if (results.sources.atomic?.detected) {
    log.info('Atomic clock detected', {
      type: results.sources.atomic.type || 'detected',
      device: results.sources.atomic.device || 'unknown',
      synchronized: results.sources.atomic.synchronized,
    });
  }

  if (results.sources.gps?.detected) {
    const gpsLog = {
      device: results.sources.gps.device || 'detected',
      hasPPS: results.sources.gps.hasPPS,
      synchronized: results.sources.gps.synchronized,
    };
    // Enrich log with MA-902 SNMP data if available
    if (results.sources.gps.ma902) {
      const ma = results.sources.gps.ma902;
      gpsLog.ma902 = true;
      gpsLog.satellites = `${ma.satellites.used}/${ma.satellites.tracking}/${ma.satellites.visible}`;
      gpsLog.constellations = ma.constellations.join('+');
      gpsLog.locked = ma.locked;
      gpsLog.trust = ma.trust.level;
    }
    log.info('GPS detected', gpsLog);
  }

  if (results.sources.ptp?.detected) {
    log.info('PTP detected', {
      device: results.sources.ptp.device || 'detected',
      offset: results.sources.ptp.offset ?? 'unknown',
      synchronized: results.sources.ptp.synchronized,
    });
  }

  if (results.sources.ntp) {
    log.info('NTP detected', {
      method: results.sources.ntp.method || 'not configured',
      server: results.sources.ntp.server || 'unknown',
      stratum: results.sources.ntp.stratum,
      synchronized: results.sources.ntp.synchronized,
    });
  }
}

/**
 * Get current trust level
 */
getTrustLevel() {
  return this.trustLevel;
}

/**
 * Get phase tolerance for current trust level
 */
getPhaseTolerance() {
  return PhaseTolerance[this.trustLevel];
}

/**
 * Get stratum level for current trust level
 */
getStratum() {
  return StratumLevel[this.trustLevel];
}

/**
 * Check if atomic-tier time source is available
 */
hasAtomicTime() {
  return this.trustLevel === TimeTrustLevel.ATOMIC;
}

/**
 * Check if high-precision time source is available (atomic or GPS)
 */
hasHighPrecisionTime() {
  return [TimeTrustLevel.ATOMIC, TimeTrustLevel.GPS, TimeTrustLevel.PTP].includes(this.trustLevel);
}

/**
 * Get status object for API responses
 */
getStatus() {
  const status = {
    trustLevel: this.trustLevel,
    phaseTolerance: this.getPhaseTolerance(),
    stratum: this.getStratum(),
    primarySource: this.primarySource,
    sources: Object.fromEntries(this.detectedSources),
    lastCheck: this.lastCheck,
    capabilities: {
      atomicTime: this.hasAtomicTime(),
      highPrecisionTime: this.hasHighPrecisionTime(),
      tightPhaseWindow: this.trustLevel !== TimeTrustLevel.UNSYNC,
    },
  };

  // Include MA-902 SNMP status if monitor is active
  if (this.ma902Monitor) {
    status.ma902 = this.ma902Monitor.getStatus();
  }

  return status;
}

/**
 * Get the MA-902 monitor instance (if configured)
 * @returns {MA902Monitor|null}
 */
getMA902Monitor() {
  return this.ma902Monitor;
}
}

// ============================================================
// INTEGRATION WITH PHASE EPOCH
// ============================================================

/**
 * Create a phase epoch configuration based on time source quality
 * @param {TimeSourceDetector} detector - Time source detector instance
 * @returns {Object} Phase configuration
 */
export function createPhaseConfig(detector) {
  const trustLevel = detector.getTrustLevel();
  const tolerance = detector.getPhaseTolerance();

  // Tighter phase windows for higher-quality time sources
  const phaseConfig = {
    trustLevel,
    toleranceMs: tolerance,

    // Epoch duration based on trust level
    epochDurationHours: {
      [TimeTrustLevel.ATOMIC]: 1,    // 1-hour epochs for atomic
      [TimeTrustLevel.GPS]: 2,       // 2-hour epochs for GPS
      [TimeTrustLevel.PTP]: 2,       // 2-hour epochs for PTP
      [TimeTrustLevel.NTP]: 6,       // 6-hour epochs for NTP (default)
      [TimeTrustLevel.UNSYNC]: 12,   // 12-hour epochs for unsync
    }[trustLevel],

    // Grace period based on trust level
    gracePeriodMinutes: {
      [TimeTrustLevel.ATOMIC]: 1,    // 1 minute grace for atomic
      [TimeTrustLevel.GPS]: 5,       // 5 minutes for GPS
      [TimeTrustLevel.PTP]: 5,       // 5 minutes for PTP
      [TimeTrustLevel.NTP]: 15,      // 15 minutes for NTP
      [TimeTrustLevel.UNSYNC]: 30,   // 30 minutes for unsync
    }[trustLevel],

    // Whether this node can participate in time-critical operations
    capabilities: {
      canBeTimeOracle: trustLevel === TimeTrustLevel.ATOMIC,
      canValidateTightPhase: [TimeTrustLevel.ATOMIC, TimeTrustLevel.GPS].includes(trustLevel),
      canParticipateInConsensus: trustLevel !== TimeTrustLevel.UNSYNC,
    },
  };

  return phaseConfig;
}

// ============================================================
// SINGLETON INSTANCE
// ============================================================

let globalDetector = null;

/**
 * Get or create the global MANI time source detector
 * @param {Object} options - Detector options
 * @returns {ManiTimeDetector}
 */
export function getManiTimeDetector(options = {}) {
  if (!globalDetector) {
    globalDetector = new ManiTimeDetector(options);
  }
  return globalDetector;
}

// Backward compatibility alias
export const getTimeSourceDetector = getManiTimeDetector;

/**
 * Quick detection of time sources
 * @returns {Object} Detection results
 */
export function detectTimeSources() {
  const detector = new ManiTimeDetector({ verbose: false });
  return detector.detect();
}

// ============================================================
// EXPORTS - MANI naming with backward compatibility
// ============================================================

// Primary exports (MANI naming)
// Note: getManiTimeDetector, ManiTimeDetector, ManiTrustLevel, ManiPhaseTolerance, ManiStratumLevel
//       are already exported at their declarations
export {
  // Re-export only things not already exported inline
};

// Backward compatibility exports (original naming)
export { ManiTimeDetector as TimeSourceDetector };

// Re-export MA-902 monitor for direct access
export { MA902Monitor, getMA902Monitor } from './ma902-snmp.js';

export default {
  ManiTimeDetector,
  ManiTrustLevel,
  ManiPhaseTolerance,
  ManiStratumLevel,
  createPhaseConfig,
  getManiTimeDetector,
  detectTimeSources,
  MA902Monitor,
  getMA902Monitor,
  // Backward compatibility
  TimeSourceDetector: ManiTimeDetector,
  TimeTrustLevel: ManiTrustLevel,
  PhaseTolerance: ManiPhaseTolerance,
  StratumLevel: ManiStratumLevel,
  getTimeSourceDetector: getManiTimeDetector,
};





