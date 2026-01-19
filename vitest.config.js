import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Only run Vitest-compatible tests (security module)
    include: ['security/tests/**/*.test.js'],
    
    // Exclude Node.js test runner files
    exclude: [
      '**/node_modules/**',
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
