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
