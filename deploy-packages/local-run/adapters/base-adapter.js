/**
 * Yakmesh - Base Adapter Interface
 * 
 * All platform adapters must extend this class.
 * Adapters bridge external data sources with the Yakmesh network.
 * 
 * @module adapters/base-adapter
 * @version 1.0.0
 */

import { EventEmitter } from 'events';

/**
 * Abstract base class for Yakmesh adapters
 * 
 * Implement this to create integrations with:
 * - phpBB forums (PeerQuanta)
 * - WordPress/WooCommerce
 * - Custom REST APIs
 * - PostgreSQL databases
 * - MongoDB collections
 */
export class BaseAdapter extends EventEmitter {
  constructor(YakmeshNode, config = {}) {
    super();
    
    if (new.target === BaseAdapter) {
      throw new Error('BaseAdapter is abstract and cannot be instantiated directly');
    }
    
    this.node = YakmeshNode;
    this.config = config;
    this.syncInterval = null;
    this.isInitialized = false;
    
    // Statistics
    this.stats = {
      recordsProcessed: 0,
      recordsValidated: 0,
      recordsRejected: 0,
      lastSyncTime: null,
      errors: [],
    };
  }
  
  /**
   * Initialize the adapter
   * Must be implemented by subclasses
   * @abstract
   */
  async init() {
    throw new Error('init() must be implemented by subclass');
  }
  
  /**
   * Get the schema definition for replicated tables
   * Must be implemented by subclasses
   * @abstract
   * @returns {Object} Schema definition
   */
  getSchema() {
    throw new Error('getSchema() must be implemented by subclass');
  }
  
  /**
   * Fetch records that have changed since last sync
   * Must be implemented by subclasses
   * @abstract
   * @param {Date} since - Timestamp of last sync
   * @returns {Promise<Array>} Changed records
   */
  async fetchChanges(since) {
    throw new Error('fetchChanges() must be implemented by subclass');
  }
  
  /**
   * Apply a record change from the mesh to the local database
   * Must be implemented by subclasses
   * @abstract
   * @param {string} table - Table name
   * @param {Object} record - Record data
   * @param {string} operation - 'INSERT', 'UPDATE', 'DELETE'
   */
  async applyChange(table, record, operation) {
    throw new Error('applyChange() must be implemented by subclass');
  }
  
  /**
   * Validate a record using custom rules
   * Override to add platform-specific validation
   * @param {string} type - Record type
   * @param {Object} data - Record data
   * @returns {Object} { valid: boolean, errors: string[] }
   */
  validate(type, data) {
    return { valid: true, errors: [] };
  }
  
  /**
   * Start periodic synchronization
   * @param {number} intervalMs - Sync interval in milliseconds
   */
  startSync(intervalMs = 60000) {
    if (this.syncInterval) {
      this.stopSync();
    }
    
    console.log('Starting sync every ' + (intervalMs / 1000) + 's');
    this.sync();
    
    this.syncInterval = setInterval(() => {
      this.sync();
    }, intervalMs);
  }
  
  /**
   * Stop periodic synchronization
   */
  stopSync() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }
  
  /**
   * Perform a sync cycle
   */
  async sync() {
    try {
      const changes = await this.fetchChanges(this.stats.lastSyncTime);
      
      for (const change of changes) {
        const validation = this.validate(change.type, change.data);
        
        if (validation.valid) {
          this.node.gossip.spreadRumor('adapter:' + change.type, {
            table: change.table,
            operation: change.operation,
            data: change.data,
          });
          this.stats.recordsValidated++;
        } else {
          this.stats.recordsRejected++;
          this.emit('validation-error', { change, errors: validation.errors });
        }
        this.stats.recordsProcessed++;
      }
      
      this.stats.lastSyncTime = new Date();
      this.emit('sync-complete', { processed: changes.length });
      
    } catch (error) {
      this.stats.errors.push({ time: new Date(), error: error.message });
      this.emit('sync-error', error);
    }
  }
  
  getStats() {
    return {
      ...this.stats,
      isRunning: this.syncInterval !== null,
      adapterType: this.constructor.name,
    };
  }
  
  async handleRumor(topic, data, origin) {
    if (topic.startsWith('adapter:')) {
      const { table, operation, data: recordData } = data;
      await this.applyChange(table, recordData, operation);
    }
  }
}

export default BaseAdapter;


