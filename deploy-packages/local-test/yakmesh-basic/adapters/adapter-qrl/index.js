/**
 * QRL Blockchain Adapter
 *
 * Polls the QRL Explorer API for incoming transactions to a deposit address,
 * extracts payment codes from transaction message fields, and confirms
 * payments through C2C's internal API.
 *
 * Two exports:
 *   QRLWatcher  — standalone polling service (no mesh dependency)
 *   QRLAdapter  — mesh adapter extending BaseAdapter for network propagation
 *
 * Payment flow:
 *   1. Player creates payment in C2C → gets payment_code (C2C-XXXXXXXXXXXX)
 *   2. Player sends QRL to deposit address with payment_code in message field
 *   3. QRLWatcher polls explorer, extracts code, calls C2C /api/wallet/qrl-confirm
 *   4. C2C credits Star Credits to player
 *   5. QRLAdapter (optional) gossips confirmation across mesh
 *
 * @module adapters/adapter-qrl
 * @version 1.0.0
 */

import { BaseAdapter } from '../base-adapter.js';
import { createHmac } from 'node:crypto';

const QRL_EXPLORER_API = 'https://explorer.theqrl.org';
const SHOR_PER_QRL = 1_000_000_000;

// ═══════════════════════════════════════════════════════════════════════════
// QRLWatcher — standalone blockchain poller, no mesh required
// ═══════════════════════════════════════════════════════════════════════════

export class QRLWatcher {
  /**
   * @param {Object} config
   * @param {string} config.depositAddress  — QRL address to watch
   * @param {string} config.c2cEndpoint     — C2C server base URL (default http://localhost:3091)
   * @param {string} config.adapterKey      — shared secret for X-Adapter-Key header
   * @param {number} config.pollInterval    — ms between polls (default 60 000)
   * @param {number} config.minConfirmations — block confirmations required (default 6)
   */
  constructor(config = {}) {
    this.depositAddress = config.depositAddress || '';
    this.c2cEndpoint = config.c2cEndpoint || 'http://localhost:3091';
    this.adapterKey = config.adapterKey || '';
    this.pollInterval = config.pollInterval || 60_000;
    this.minConfirmations = config.minConfirmations || 6;

    this.processedTxs = new Set();
    this.isRunning = false;
    this._timer = null;
    this._listeners = {};

    this.stats = {
      polls: 0,
      txsScanned: 0,
      paymentsMatched: 0,
      paymentsConfirmed: 0,
      errors: 0,
      lastPoll: null,
      lastConfirmation: null,
    };
  }

  // ── Event emitter (minimal, no dependency) ────────────────────────────

  on(event, fn) {
    (this._listeners[event] ??= []).push(fn);
    return this;
  }

  off(event, fn) {
    const arr = this._listeners[event];
    if (arr) this._listeners[event] = arr.filter(f => f !== fn);
    return this;
  }

  _emit(event, ...args) {
    for (const fn of this._listeners[event] || []) {
      try { fn(...args); } catch { /* listener error — don't kill the watcher */ }
    }
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────

  async start() {
    if (this.isRunning) return;
    if (!this.depositAddress) throw new Error('QRL deposit address required');

    this.isRunning = true;
    console.log(`[QRL] Watcher started — polling every ${this.pollInterval / 1000}s`);
    console.log(`[QRL] Deposit: ${this.depositAddress.slice(0, 12)}...${this.depositAddress.slice(-8)}`);

    // First poll immediately, then on interval
    await this.poll();
    this._timer = setInterval(() => this.poll(), this.pollInterval);
  }

  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this.isRunning = false;
    console.log('[QRL] Watcher stopped');
  }

  // ── Core poll cycle ───────────────────────────────────────────────────

  async poll() {
    try {
      this.stats.polls++;
      this.stats.lastPoll = Date.now();

      const data = await this._fetchAddress();
      if (!data) return;

      // QRL Explorer returns transactions in various formats
      const txs = data.transactions || data.txs || [];
      this.stats.txsScanned += txs.length;

      for (const tx of txs) {
        await this._processTx(tx);
      }
    } catch (err) {
      this.stats.errors++;
      this._emit('error', err);
      console.error('[QRL] Poll error:', err.message);
    }
  }

  async _processTx(tx) {
    // Extract transaction hash — try multiple paths for API compatibility
    const hash = tx.tx?.transaction_hash
      || tx.transaction_hash
      || tx.hash
      || tx.tx_hash;
    if (!hash || this.processedTxs.has(hash)) return;

    // Extract payment code from the message field
    const paymentCode = this._extractPaymentCode(tx);
    if (!paymentCode) {
      // Not a C2C payment — skip but mark as seen to avoid re-scanning
      this.processedTxs.add(hash);
      return;
    }

    this.stats.paymentsMatched++;

    // Extract amount in QRL
    const amountQrl = this._extractAmount(tx);
    if (!amountQrl || amountQrl <= 0) {
      console.warn(`[QRL] Matched code ${paymentCode} but zero/invalid amount in tx ${hash}`);
      this.processedTxs.add(hash);
      return;
    }

    // Estimate confirmations
    const confirmations = tx.confirmations ?? this.minConfirmations;

    console.log(`[QRL] Payment matched: ${paymentCode} | ${amountQrl} QRL | tx ${hash.slice(0, 16)}...`);
    const result = await this._confirmWithC2C(paymentCode, hash, amountQrl, confirmations);

    this.processedTxs.add(hash);

    if (result && (result.status === 'completed' || result.status === 'already_completed')) {
      this.stats.paymentsConfirmed++;
      this.stats.lastConfirmation = Date.now();
      this._emit('confirmation', {
        paymentCode,
        txHash: hash,
        amountQrl,
        amountSc: result.amount_sc || 0,
        status: result.status,
      });
      console.log(`[QRL] ✓ Confirmed: ${paymentCode} → ${result.amount_sc || '?'} SC`);
    } else if (result && result.status === 'confirming') {
      this._emit('confirming', {
        paymentCode,
        txHash: hash,
        amountQrl,
        confirmations: result.confirmations,
        required: result.required,
      });
    }
  }

  // ── Data extraction helpers ───────────────────────────────────────────

  /**
   * Extract payment code from transaction message field.
   * Format: C2C-<alphanumeric 8-21 chars>
   * The message may be hex-encoded or plain text depending on QRL API version.
   */
  _extractPaymentCode(tx) {
    let msg = tx.tx?.transfer?.message_data
      || tx.tx?.message_data
      || tx.message_data
      || tx.message
      || '';

    // Handle hex-encoded messages
    if (typeof msg === 'string' && /^[0-9a-fA-F]+$/.test(msg) && msg.length >= 8) {
      try {
        msg = Buffer.from(msg, 'hex').toString('utf8');
      } catch { /* not valid hex — use as-is */ }
    }

    // Match C2C payment code pattern
    const match = msg.match(/C2C-([A-Za-z0-9_-]{8,21})/);
    return match ? match[0] : null;
  }

  /**
   * Extract transfer amount in QRL (not Shor).
   * Tries multiple API response paths for compatibility.
   */
  _extractAmount(tx) {
    const shor = Number(
      tx.tx?.transfer?.totalAmount
      || tx.tx?.transfer?.total_amount
      || tx.tx?.amount
      || tx.amount
      || tx.total_amount
      || 0
    );
    return shor / SHOR_PER_QRL;
  }

  // ── C2C communication ─────────────────────────────────────────────────

  async _fetchAddress() {
    const url = `${QRL_EXPLORER_API}/api/a/${this.depositAddress}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Explorer API ${res.status}: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Call C2C's internal confirm endpoint.
   * Uses X-Adapter-Key header for service-to-service auth (replaces HMAC webhook).
   */
  async _confirmWithC2C(paymentCode, txHash, amountQrl, confirmations) {
    try {
      const body = JSON.stringify({
        payment_code: paymentCode,
        qrl_tx_hash: txHash,
        amount_qrl: amountQrl,
        confirmations,
      });

      // Build HMAC auth headers (timestamp + HMAC-SHA256)
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const headers = { 'Content-Type': 'application/json' };

      if (this.adapterKey) {
        const signature = createHmac('sha256', this.adapterKey)
          .update(`${timestamp}:${body}`)
          .digest('hex');
        headers['X-Adapter-Signature'] = signature;
        headers['X-Adapter-Timestamp'] = timestamp;
      }

      const res = await fetch(`${this.c2cEndpoint}/api/wallet/qrl-confirm`, {
        method: 'POST',
        headers,
        body,
      });

      const data = await res.json();
      if (!res.ok) {
        console.warn(`[QRL] C2C rejected: ${data.error || res.statusText}`);
        return null;
      }
      return data;
    } catch (err) {
      console.error(`[QRL] C2C confirm failed: ${err.message}`);
      return null;
    }
  }

  // ── Status ────────────────────────────────────────────────────────────

  getStatus() {
    return {
      running: this.isRunning,
      depositAddress: this.depositAddress
        ? `${this.depositAddress.slice(0, 12)}...${this.depositAddress.slice(-8)}`
        : '(not configured)',
      pollInterval: this.pollInterval,
      minConfirmations: this.minConfirmations,
      processedTxCount: this.processedTxs.size,
      ...this.stats,
    };
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// QRLAdapter — mesh adapter extending BaseAdapter
// Wraps QRLWatcher and gossips confirmations across the yakmesh network.
// ═══════════════════════════════════════════════════════════════════════════

export class QRLAdapter extends BaseAdapter {
  constructor(node, config = {}) {
    super(node, config);
    this.watcher = new QRLWatcher(config);
  }

  async init() {
    // Forward watcher events and gossip confirmations to mesh
    this.watcher.on('confirmation', (data) => {
      this.emit('qrl:confirmation', data);

      // Propagate across mesh
      if (this.node?.gossip) {
        this.node.gossip.spreadRumor('adapter:qrl_confirmation', {
          table: 'qrl_confirmations',
          operation: 'INSERT',
          data: {
            payment_code: data.paymentCode,
            tx_hash: data.txHash,
            amount_qrl: data.amountQrl,
            amount_sc: data.amountSc,
            confirmed_at: Date.now(),
          },
        });
      }
    });

    this.watcher.on('error', (err) => {
      this.emit('qrl:error', err);
    });

    await this.watcher.start();
    this.isInitialized = true;
  }

  getSchema() {
    return {
      qrl_confirmations: {
        primaryKey: 'tx_hash',
        fields: ['payment_code', 'tx_hash', 'amount_qrl', 'amount_sc', 'confirmations', 'confirmed_at'],
      },
    };
  }

  async fetchChanges(_since) {
    // Watcher handles polling internally and pushes via events
    return [];
  }

  async applyChange(table, record, _operation) {
    if (table === 'qrl_confirmations') {
      console.log(`[QRL] Mesh confirmation received: ${record.tx_hash}`);
      this.emit('qrl:mesh-confirmation', record);
    }
  }

  validate(type, data) {
    if (type === 'qrl_confirmation') {
      if (!data.tx_hash || !data.payment_code) {
        return { valid: false, errors: ['Missing tx_hash or payment_code'] };
      }
      return { valid: true, errors: [] };
    }
    return { valid: true, errors: [] };
  }

  getStats() {
    return {
      ...super.getStats(),
      watcher: this.watcher.getStatus(),
    };
  }

  stopSync() {
    super.stopSync();
    this.watcher.stop();
  }
}

export default QRLAdapter;
