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
