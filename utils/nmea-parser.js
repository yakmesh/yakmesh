/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */

/**
 * Universal NMEA GPS Sentence Parser
 * Decodes standard NMEA 0183 sentences ($GPRMC, $GPZDA, $GPGGA)
 * to extract high-precision UTC time, date, and lock status.
 *
 * Designed for zero-dependency hardware integration.
 *
 * @module utils/nmea-parser
 */

export class NmeaParser {
    constructor() {
        this.lastTp = null; // Time of last valid TPV (Time, Position, Velocity)
        this.status = {
            locked: false,
            satellites: 0,
            timestamp: null, // Unix timestamp in ms
            latitude: null,
            longitude: null,
            altitude: null,
            valid: false
        };
    }

    /**
     * Parse a single NMEA sentence
     * @param {string} line - Raw NMEA string (e.g., "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A")
     * @returns {Object|null} Updated status or null if ignored
     */
    parse(line) {
        if (!line || !line.startsWith('$')) return null;

        // Verify checksum if present
        const starIndex = line.lastIndexOf('*');
        if (starIndex !== -1) {
            const payload = line.substring(1, starIndex);
            const expectedChecksum = line.substring(starIndex + 1);
            let checksum = 0;
            for (let i = 0; i < payload.length; i++) {
                checksum ^= payload.charCodeAt(i);
            }
            if (checksum.toString(16).toUpperCase() !== expectedChecksum.toUpperCase().padStart(2, '0')) {
                return null; // Checksum failed
            }
        }

        const parts = line.split(',');
        const type = parts[0].substring(3); // e.g., "RMC", "GGA", "ZDA"

        switch (type) {
            case 'RMC': return this._parseRMC(parts);
            case 'GGA': return this._parseGGA(parts);
            case 'ZDA': return this._parseZDA(parts);
            default: return null;
        }
    }

    /**
     * Recommended Minimum Navigation Information ($--RMC)
     * Essential for time + data + validity
     */
    _parseRMC(p) {
        // $GPRMC,hhmmss.ss,A,llll.ll,a,yyyyy.yy,a,vv.v,tt.t,ddmmyy,mag,,*CS
        if (p.length < 10) return null;

        const time = p[1];    // hhmmss.ss
        const status = p[2];  // A=Active (Locked), V=Void
        const date = p[9];    // ddmmyy

        if (status === 'A' && time && date) {
            this.status.locked = true;
            this.status.timestamp = this._parseUtc(time, date);
            this.status.valid = true;
        } else {
            this.status.locked = false;
            this.status.valid = false;
        }

        return this.status;
    }

    /**
     * Global Positioning System Fix Data ($--GGA)
     * Satellite count and altitude
     */
    _parseGGA(p) {
        // $GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,a.a,M,g.g,M,x.x,xxxx*CS
        if (p.length < 10) return null;

        this.status.satellites = parseInt(p[7]) || 0;
        this.status.altitude = parseFloat(p[9]) || null;

        // Status x: 0=No fix, 1=GPS fix, 2=DGPS fix
        if (parseInt(p[6]) > 0) {
            this.status.locked = true;
        }

        return this.status;
    }

    /**
     * Date & Time ($--ZDA)
     * Most reliable for full year and millisecond precision
     */
    _parseZDA(p) {
        // $GPZDA,hhmmss.ss,dd,mm,yyyy,xx,xx*CS
        if (p.length < 5) return null;

        const time = p[1];
        const day = p[2];
        const month = p[3];
        const year = p[4];

        if (time && day && month && year) {
            const dateStr = `${day}${month}${year.substring(2)}`;
            this.status.timestamp = this._parseUtc(time, dateStr, year);
            this.status.locked = true;
            this.status.valid = true;
        }

        return this.status;
    }

    /**
     * Convert NMEA time/date to Unix ms
     */
    _parseUtc(time, date, fullYear = null) {
        // hhmmss.ss
        const hh = parseInt(time.substring(0, 2));
        const mm = parseInt(time.substring(2, 4));
        const ss = parseInt(time.substring(4, 6));
        const msMatch = time.match(/\.(\d+)/);
        const ms = msMatch ? parseInt(msMatch[1].substring(0, 3).padEnd(3, '0')) : 0;

        // ddmmyy
        const d = parseInt(date.substring(0, 2));
        const m = parseInt(date.substring(2, 4)) - 1; // 0-indexed month
        const y = fullYear ? parseInt(fullYear) : (2000 + parseInt(date.substring(4, 6)));

        const utc = Date.UTC(y, m, d, hh, mm, ss, ms);
        return utc;
    }
}
