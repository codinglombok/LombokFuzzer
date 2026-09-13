/**
 * LombokFuzzer — Jest configuration
 *
 * Tests run against TypeScript source via ts-jest, so `require('../../src/...')`
 * inside the test files resolves to the transpiled modules on the fly.
 *
 * @license Apache-2.0
 */

/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  // Source files use `.js` import specifiers (NodeNext ESM convention).
  // Map them back to `.ts` so ts-jest can resolve them.
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        // Relax for tests: allow require() and CommonJS interop
        module: 'commonjs',
        moduleResolution: 'node',
        noUnusedLocals: false,
        noUnusedParameters: false,
        isolatedModules: true,
      },
    }],
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/index.ts',
    '!src/**/*.d.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
  verbose: true,
};
