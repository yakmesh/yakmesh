/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 */

import { createReadStream, existsSync } from 'fs';
import { EventEmitter } from 'events';
import { NmeaParser } from '../utils/nmea-parser.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('oracle:gps-serial');

/**
 * Universal Serial GPS Monitor
 * Probes serial ports for NMEA data ($GPRMC, $GPZDA).
 *
 * Supported Protocols: NMEA 0183 (9600-115200 baud)
 * Supported Devices: u-blox, GlobalSat, Garmin, generic serial/USB GPS.
 *
 * @module oracle/gps-serial
 */
export class SerialGpsMonitor extends EventEmitter {
  constructor(options = {}) {
    super();
    this.device = options.device || '/dev/ttyUSB0';
    this.baud = options.baud || 9600;
    this.parser = new NmeaParser();
    this.stream = null;
    this.buffer = '';
    this.running = false;
    this.lastLock = false;
    this.telemetry = null;
  }

  /**
   * Start GPS monitoring
   */
  start() {
    if (!existsSync(this.device)) {
      log.warn(`Serial device ${this.device} not found — generic GPS detection offline`);
      return false;
    }

    log.info(`📡 Probing generic GPS at ${this.device}...`);
    this.running = true;

    try {
      this.stream = createReadStream(this.device, { encoding: 'utf8' });
      
      this.stream.on('data', (chunk) => {
        this._handleData(chunk);
      });

      this.stream.on('error', (err) => {
        log.error(`Serial GPS error at ${this.device}`, { error: err.message });
        this.stop();
      });

      this.stream.on('end', () => {
        log.warn(`Serial GPS stream ended at ${this.device}`);
        this.stop();
      });

      return true;
    } catch (err) {
      log.error(`Failed to open serial GPS at ${this.device}`, { error: err.message });
      return false;
    }
  }

  /**
   * Stop monitoring
   */
  stop() {
    this.running = false;
    if (this.stream) {
      this.stream.destroy();
      this.stream = null;
    }
  }

  /**
   * Handle incoming raw data
   */
  _handleData(chunk) {
    this.buffer += chunk;
    
    // Split by NMEA line delimiters (CR/LF)
    const lines = this.buffer.split(/\r?\n/);
    this.buffer = lines.pop(); // Keep the partial last line

    for (const line of lines) {
      const telemetry = this.parser.parse(line.trim());
      if (telemetry && telemetry.valid) {
        this.telemetry = { ...telemetry, lastUpdated: Date.now() };
        this.emit('telemetry', this.telemetry);

        // Lock status state machine
        if (this.telemetry.locked && !this.lastLock) {
          log.info(`Celestial Marker Lock Acquired: ${this.device} (${this.telemetry.satellites} sats)`);
          this.emit('lockAcquired', this.telemetry);
        } else if (!this.telemetry.locked && this.lastLock) {
          log.warn(`Celestial Marker Lock Lost: ${this.device}`);
          this.emit('lockLost', this.telemetry);
        }
        this.lastLock = this.telemetry.locked;
      }
    }
  }

  /**
   * Get latest GPS telemetry
   */
  getTelemetry() {
    return this.telemetry;
  }

  /**
   * Check if hardware is providing a valid lock
   */
  isLocked() {
    return this.telemetry?.locked || false;
  }
}
