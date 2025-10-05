import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Test file patterns
    include: ['tests/**/*.test.{js,ts}'],
    exclude: ['**/node_modules/**', '**/dist/**', 'tests/deno/**'],

    // Timeout for each test (10 seconds)
    testTimeout: 30000,

    // Global test utilities
    globals: false, // Explicitly import from 'vitest'

    // Reporters
    reporters: ['verbose'],

    // Parallel execution
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        maxThreads: 8,  // Adjust based on your CPU cores
        minThreads: 4
      }
    },

    // Allow concurrent test execution within files
    fileParallelism: true,
    maxConcurrency: 8,  // Max concurrent tests per file

    // Run tests in both Node.js and browser environments
    // Default to Node.js, but can be overridden with --environment flag
    environment: process.env.TEST_ENV || 'node'
  }
});
