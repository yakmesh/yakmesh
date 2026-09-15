/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Run Vitest-compatible tests (security + mesh modules)
    include: [
      'security/tests/**/*.test.js',
      'mesh/tests/**/*.test.js',
    ],
    
    // Exclude Node.js test runner files
    exclude: [
      '**/node_modules/**',
      '**/deploy-packages/**',
      'oracle/tests/**',      // Uses Node.js test runner
      'protocol/tests/**',    // Uses Node.js test runner
      'tests/**',             // Uses Node.js test runner
    ],
    
    // Test environment
    environment: 'node',
    
    // Timeout for slow crypto tests
    testTimeout: 30000,
    
    // Reporter
    reporters: ['default'],
    
    // Coverage (optional)
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      exclude: ['**/tests/**', '**/node_modules/**'],
    },
  },
});
