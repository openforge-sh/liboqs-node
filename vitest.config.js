import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Test file patterns
    include: ['tests/**/*.test.{js,ts}'],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'tests/deno/**',
      // Exclude CLI tests in browser mode
      ...(process.env.TEST_ENV === 'browser' ? ['tests/cli.test.ts'] : [])
    ],

    // Timeout for each test
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

    // Browser mode configuration for real browser testing
    browser: {
      enabled: process.env.TEST_ENV === 'browser',
      name: 'chromium',
      provider: 'playwright',
      headless: true,
      screenshotOnFailure: false
    }
  }
});
