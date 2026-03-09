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
 * BYOND Topic Protocol Client
 * 
 * Implements the BYOND Topic protocol for communicating with DreamDaemon servers.
 * Based on the BYOND wire format used by world/Topic() and world.Export().
 * 
 * Protocol Format:
 * - Packet: [0x00][0x83][size_high][size_low][0x00][0x6A][data...][0x00]
 * - Response: [0x00][0x83][size_high][size_low][type][data...]
 * 
 * @module adapters/adapter-byond/topic-client
 * @version 1.0.0
 */

import { Socket } from 'net';
import { EventEmitter } from 'events';

// BYOND Protocol Constants
const BYOND_HEADER = Buffer.from([0x00, 0x83]);
const BYOND_TOPIC_MARKER = Buffer.from([0x00, 0x6A]);
const BYOND_RESPONSE_TYPES = {
  NULL: 0x00,
  FLOAT: 0x2a,
  STRING: 0x06,
};

// Default timeout for Topic requests (10 seconds)
const DEFAULT_TIMEOUT = 10000;

/**
 * Parse a BYOND Topic response
 * @param {Buffer} buffer - Raw response buffer
 * @returns {Object} Parsed response with type and value
 */
export function parseTopicResponse(buffer) {
  if (buffer.length < 5) {
    return { type: 'error', value: null, raw: buffer };
  }

  // Verify header
  if (buffer[0] !== 0x00 || buffer[1] !== 0x83) {
    return { type: 'invalid', value: null, raw: buffer };
  }

  // Get size from bytes 2-3 (big endian)
  const size = (buffer[2] << 8) | buffer[3];

  // Get response type
  const responseType = buffer[4];

  switch (responseType) {
    case BYOND_RESPONSE_TYPES.NULL:
      return { type: 'null', value: null, raw: buffer };

    case BYOND_RESPONSE_TYPES.FLOAT:
      // Float is 4 bytes, little endian
      if (buffer.length >= 9) {
        const floatBuf = buffer.slice(5, 9);
        const value = floatBuf.readFloatLE(0);
        return { type: 'float', value, raw: buffer };
      }
      return { type: 'float', value: 0, raw: buffer };

    case BYOND_RESPONSE_TYPES.STRING:
      // String starts after type byte, null-terminated
      const strEnd = buffer.indexOf(0x00, 5);
      const strData = buffer.slice(5, strEnd > 5 ? strEnd : buffer.length);
      return { type: 'string', value: strData.toString('utf8'), raw: buffer };

    default:
      // Unknown type - return raw data as string
      const rawStr = buffer.slice(5).toString('utf8').replace(/\0+$/, '');
      return { type: 'unknown', value: rawStr, raw: buffer };
  }
}

/**
 * Build a BYOND Topic request packet
 * @param {string} topic - Topic string (query format: key=value&key2=value2)
 * @returns {Buffer} Wire-format packet
 */
export function buildTopicPacket(topic) {
  // Encode topic string
  const topicBytes = Buffer.from(topic, 'utf8');
  
  // Total payload: marker(2) + topic + null terminator
  const payloadLength = 2 + topicBytes.length + 1;
  
  // Build packet
  const packet = Buffer.alloc(4 + payloadLength);
  
  // Header
  packet[0] = 0x00;
  packet[1] = 0x83;
  
  // Size (big endian, includes everything after size bytes)
  packet[2] = (payloadLength >> 8) & 0xFF;
  packet[3] = payloadLength & 0xFF;
  
  // Topic marker
  packet[4] = 0x00;
  packet[5] = 0x6A;
  
  // Topic data
  topicBytes.copy(packet, 6);
  
  // Null terminator
  packet[packet.length - 1] = 0x00;
  
  return packet;
}

/**
 * BYOND Topic Client
 * Manages connections to BYOND DreamDaemon servers
 */
export class BYONDTopicClient extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.retries = options.retries || 0;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Send a Topic request to a BYOND server
   * @param {Object} options - Connection options
   * @param {string} options.host - Server hostname or IP
   * @param {number} options.port - Server port
   * @param {string} options.topic - Topic string
   * @param {number} [options.timeout] - Request timeout in ms
   * @returns {Promise<Object>} Parsed response
   */
  async sendTopic({ host, port, topic, timeout }) {
    const requestTimeout = timeout || this.timeout;
    
    return new Promise((resolve, reject) => {
      const socket = new Socket();
      let responseBuffer = Buffer.alloc(0);
      let timeoutHandle = null;
      let resolved = false;

      const cleanup = () => {
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
          timeoutHandle = null;
        }
        socket.destroy();
      };

      const finish = (result) => {
        if (!resolved) {
          resolved = true;
          cleanup();
          if (result instanceof Error) {
            reject(result);
          } else {
            resolve(result);
          }
        }
      };

      // Set timeout
      timeoutHandle = setTimeout(() => {
        finish(new Error(`Topic request timeout after ${requestTimeout}ms`));
      }, requestTimeout);

      // Handle errors
      socket.on('error', (err) => {
        finish(new Error(`Connection error: ${err.message}`));
      });

      // Handle connection close
      socket.on('close', () => {
        if (!resolved && responseBuffer.length > 0) {
          const parsed = parseTopicResponse(responseBuffer);
          finish(parsed);
        } else if (!resolved) {
          finish(new Error('Connection closed without response'));
        }
      });

      // Collect response data
      socket.on('data', (chunk) => {
        responseBuffer = Buffer.concat([responseBuffer, chunk]);
        
        // Check if we have a complete response
        if (responseBuffer.length >= 4) {
          const expectedSize = (responseBuffer[2] << 8) | responseBuffer[3];
          if (responseBuffer.length >= 4 + expectedSize) {
            const parsed = parseTopicResponse(responseBuffer);
            finish(parsed);
          }
        }
      });

      // Connect and send
      socket.connect(port, host, () => {
        const packet = buildTopicPacket(topic);
        socket.write(packet);
        this.emit('topic-sent', { host, port, topic });
      });
    });
  }

  /**
   * Send a Topic request with automatic retries
   * @param {Object} options - Same as sendTopic
   * @returns {Promise<Object>} Parsed response
   */
  async sendTopicWithRetry(options) {
    let lastError = null;
    
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        return await this.sendTopic(options);
      } catch (err) {
        lastError = err;
        
        if (attempt < this.retries) {
          await new Promise(r => setTimeout(r, this.retryDelay));
          this.emit('topic-retry', { 
            attempt: attempt + 1, 
            maxRetries: this.retries,
            error: err.message 
          });
        }
      }
    }
    
    throw lastError;
  }

  /**
   * Query server status
   * Common Topic query supported by most BYOND games
   * @param {string} host - Server hostname
   * @param {number} port - Server port
   * @returns {Promise<Object>} Server status
   */
  async queryStatus(host, port) {
    const response = await this.sendTopic({
      host,
      port,
      topic: 'status',
    });

    if (response.type === 'string') {
      // Parse key=value&key2=value2 format
      const params = {};
      response.value.split('&').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) {
          params[decodeURIComponent(key)] = value ? decodeURIComponent(value) : '';
        }
      });
      return { ...response, parsed: params };
    }

    return response;
  }

  /**
   * Ping a server to check if it's online
   * @param {string} host - Server hostname
   * @param {number} port - Server port
   * @returns {Promise<boolean>} True if server responds
   */
  async ping(host, port) {
    try {
      const response = await this.sendTopic({
        host,
        port,
        topic: 'ping',
        timeout: 5000,
      });
      return response.type !== 'error' && response.type !== 'invalid';
    } catch {
      return false;
    }
  }
}

/**
 * Create a Topic connection for repeated queries to same server
 * @param {Object} options - Connection options
 * @returns {Object} Connection object with send method
 */
export function createTopicConnection({ host, port, timeout, retries }) {
  const client = new BYONDTopicClient({ timeout, retries });
  
  return {
    send: (topic) => client.sendTopic({ host, port, topic }),
    sendWithRetry: (topic) => client.sendTopicWithRetry({ host, port, topic }),
    status: () => client.queryStatus(host, port),
    ping: () => client.ping(host, port),
    client,
  };
}

// Export default client instance
export default BYONDTopicClient;
