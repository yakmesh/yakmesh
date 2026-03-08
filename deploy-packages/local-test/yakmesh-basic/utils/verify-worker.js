/**
 * ACCEL Verify Worker — ML-DSA-65 Batch Verification Worker Thread
 * 
 * Receives chunks of signature/message/publicKey triples from the
 * BatchVerifyQueue and verifies them using @noble/post-quantum.
 * Each worker runs in its own V8 isolate for true CPU parallelism.
 * 
 * The parent thread distributes batch chunks across a pool of these
 * workers (sized to CPU core count), achieving near-linear speedup
 * for large verification batches on multi-core processors.
 * 
 * Architecture:
 *   BatchVerifyQueue._flush()
 *     → splits batch into N chunks (N = available workers)
 *     → postMessage({ id, items }) to each worker
 *     → worker verifies chunk and postMessage({ id, results }) back
 *     → parent resolves/rejects the original enqueue() promises
 * 
 * Note: This worker uses @noble/post-quantum directly. If a native
 * PQ addon (liboqs) is installed, the main thread's sequential
 * fallback path will use it, but workers use pure JS. A future
 * enhancement could probe and load native PQ in each worker.
 * 
 * @module utils/verify-worker
 * @version 1.0.0
 */

import { parentPort } from 'worker_threads';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

/**
 * Process a batch of ML-DSA-65 verification requests.
 * 
 * @message {{ id: number, items: Array<{ signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array }> }}
 * @response {{ id: number, results: Array<{ ok: boolean, err: string|null }> }}
 */
parentPort.on('message', ({ id, items }) => {
  const results = new Array(items.length);

  for (let i = 0; i < items.length; i++) {
    const { signature, message, publicKey } = items[i];
    try {
      results[i] = {
        ok: ml_dsa65.verify(
          new Uint8Array(signature),
          new Uint8Array(message),
          new Uint8Array(publicKey)
        ),
        err: null,
      };
    } catch (err) {
      results[i] = { ok: false, err: err.message };
    }
  }

  parentPort.postMessage({ id, results });
});
