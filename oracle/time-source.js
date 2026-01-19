/**
 * Time Source Detection Module
 * 
 * Detects and integrates with various precision time sources:
 * - PCIe Atomic Clocks (CSAC, Rubidium)
 * - GPS receivers with PPS
 * - PTP (IEEE 1588) hardware timestamping
 * - Standard NTP (fallback)
 * 
 * Provides trust levels based on time source quality,
 * enabling tighter phase tolerances for atomic-synced nodes.
 * 
 * TRUST LEVELS:
 * - ATOMIC (Level 3): PCIe atomic clock, ±100ms tolerance
 * - GPS (Level 2): Hardware GPS/PPS, ±500ms tolerance
 * - STANDARD (Level 1): NTP only, ±5000ms tolerance
 * 
 * @module oracle/time-source
 */

import { execSync, exec } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { platform } from 'os';
import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:time-source');

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
 * Trust levels for time sources
 */
export const TimeTrustLevel = {
  QUANTUM: 'quantum',   // Quantum optical network (WR-PTP, optical atomic, entanglement-based)
  ATOMIC: 'atomic',     // PCIe atomic clock (CSAC, Rubidium)
  GPS: 'gps',           // GPS with PPS signal
  PTP: 'ptp',           // IEEE 1588 PTP synchronized
  NTP: 'ntp',           // Standard NTP
  UNSYNC: 'unsync',     // No reliable time source
};

/**
 * Phase tolerance in milliseconds per trust level
 */
export const PhaseTolerance = {
  [TimeTrustLevel.QUANTUM]: 1,    // ±1ms for quantum (sub-nanosecond capable)
  [TimeTrustLevel.ATOMIC]: 100,      // ±100ms for atomic
  [TimeTrustLevel.GPS]: 500,         // ±500ms for GPS
  [TimeTrustLevel.PTP]: 500,         // ±500ms for PTP
  [TimeTrustLevel.NTP]: 5000,        // ±5 seconds for NTP
  [TimeTrustLevel.UNSYNC]: 30000,    // ±30 seconds for unsync (degraded mode)
};

/**
 * Stratum equivalents for trust levels
 */
export const StratumLevel = {
  [TimeTrustLevel.QUANTUM]: 0, // Quantum reference (highest)
  [TimeTrustLevel.ATOMIC]: 0,  // Reference clock
  [TimeTrustLevel.GPS]: 1,     // Primary server
  [TimeTrustLevel.PTP]: 1,     // Primary server
  [TimeTrustLevel.NTP]: 2,     // Secondary server
  [TimeTrustLevel.UNSYNC]: 16, // Unsynchronized
};

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
// TIME SOURCE DETECTOR
// ============================================================

/**
 * Time Source Detector
 * Automatically detects available time sources and their quality
 */
export class TimeSourceDetector extends EventEmitter {
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
    };
    
    this.platform = platform();
    this.detectedSources = new Map();
    this.primarySource = null;
    this.trustLevel = TimeTrustLevel.UNSYNC;
    this.lastCheck = null;
    this.refreshTimer = null;
  }
  
  /**
   * Start continuous monitoring of time sources
   */
  start() {
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
      
      // Check for GPS/PPS
      const gpsResult = this.detectGPS();
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
      
      // Check NTP status
      const ntpResult = this.detectNTP();
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
   * Detect GPS receiver with PPS
   */
  detectGPS() {
    const result = {
      detected: false,
      synchronized: false,
      device: null,
      hasPPS: false,
      satellites: null,
      latitude: null,
      longitude: null,
    };
    
    if (this.platform === 'linux') {
      // 1. Check if gpsd is running
      try {
        const gpsdStatus = execSilent('systemctl is-active gpsd 2>/dev/null || pgrep gpsd', { encoding: 'utf8', timeout: 5000 });
        if (gpsdStatus.trim()) {
          result.detected = true;
          
          // Try to get GPS info from gpsd
          try {
            const gpsInfo = execSilent('gpspipe -w -n 5 2>/dev/null | head -1', { encoding: 'utf8', timeout: 10000 });
            const data = JSON.parse(gpsInfo);
            if (data.class === 'TPV') {
              result.synchronized = data.mode >= 2;
              result.latitude = data.lat;
              result.longitude = data.lon;
            }
          } catch (e) {
            // gpspipe not available
          }
        }
      } catch (e) {
        // gpsd not running
      }
      
      // 2. Check for GPS serial devices
      for (const gpsPath of DEVICE_PATHS.linux.gps) {
        if (existsSync(gpsPath)) {
          result.detected = true;
          result.device = gpsPath;
          break;
        }
      }
      
      // 3. Check for associated PPS
      for (const ppsPath of DEVICE_PATHS.linux.pps) {
        if (existsSync(ppsPath)) {
          result.hasPPS = true;
          break;
        }
      }
      
      // 4. Check chrony for GPS source
      try {
        const chronyOutput = execSilent('chronyc sources 2>/dev/null | grep -i gps', { encoding: 'utf8', timeout: 5000 });
        if (chronyOutput.trim()) {
          result.detected = true;
          result.synchronized = chronyOutput.includes('*');
        }
      } catch (e) {
        // chrony not available
      }
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
        const meinbergCheck = execSilent('lspci 2>/dev/null | grep -i meinberg', { encoding: 'utf8', timeout: 5000 });
        if (meinbergCheck.trim()) {
          result.detected = true;
          result.device = 'Meinberg PTP';
          result.type = meinbergCheck.includes('270') ? 'PTP270PEX' : 'Meinberg PTP Card';
          try {
            const mbgStatus = execSilent('mbgstatus 2>/dev/null | head -20', { encoding: 'utf8', timeout: 5000 });
            if (mbgStatus.includes('SYNC') || mbgStatus.includes('synchronized')) {
              result.synchronized = true;
            }
            const offsetMatch = mbgStatus.match(/offset[:\s]+(-?\d+)/i);
            if (offsetMatch) {
              result.offset = parseInt(offsetMatch[1]);
            }
          } catch (e) { /* mbgstatus not available */ }
        }
      } catch (e) { /* Meinberg not found */ }
      // 4. Check for Meinberg PTP hardware (PTP270PEX, etc.)
      try {
        const meinbergCheck = execSilent('lspci 2>/dev/null | grep -i meinberg', { encoding: 'utf8', timeout: 5000 });
        if (meinbergCheck.trim()) {
          result.detected = true;
          result.device = 'Meinberg PTP';
          result.type = meinbergCheck.includes('270') ? 'PTP270PEX' : 'Meinberg PTP Card';
          try {
            const mbgStatus = execSilent('mbgstatus 2>/dev/null | head -20', { encoding: 'utf8', timeout: 5000 });
            if (mbgStatus.includes('SYNC') || mbgStatus.includes('synchronized')) {
              result.synchronized = true;
            }
            const offsetMatch = mbgStatus.match(/offset[:\s]+(-?\d+)/i);
            if (offsetMatch) {
              result.offset = parseInt(offsetMatch[1]);
            }
          } catch (e) { /* mbgstatus not available */ }
        }
      } catch (e) { /* Meinberg not found */ }
      // 4. Check for Meinberg PTP hardware (PTP270PEX, etc.)
      try {
        // Check for Meinberg driver/software
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
      
      // 5. Windows: Check for Meinberg driver
      if (this.platform === 'win32') {
        try {
          const driverCheck = execSilent('driverquery /v 2>nul | findstr /i meinberg', { encoding: 'utf8', timeout: 5000 });
          if (driverCheck.trim()) {
            result.detected = true;
            result.type = 'Meinberg (Windows)';
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
      log.info('GPS detected', {
        device: results.sources.gps.device || 'detected',
        hasPPS: results.sources.gps.hasPPS,
        synchronized: results.sources.gps.synchronized,
      });
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
    return {
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
 * Get or create the global time source detector
 * @param {Object} options - Detector options
 * @returns {TimeSourceDetector}
 */
export function getTimeSourceDetector(options = {}) {
  if (!globalDetector) {
    globalDetector = new TimeSourceDetector(options);
  }
  return globalDetector;
}

/**
 * Quick detection of time sources
 * @returns {Object} Detection results
 */
export function detectTimeSources() {
  const detector = new TimeSourceDetector({ verbose: false });
  return detector.detect();
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  TimeSourceDetector,
  TimeTrustLevel,
  PhaseTolerance,
  StratumLevel,
  createPhaseConfig,
  getTimeSourceDetector,
  detectTimeSources,
};





