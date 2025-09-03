module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: [
    "**/__tests__/**/*.spec.ts",
    "**/?(*.)+(spec|test).ts",
    "!**/node_modules/**",
    "!**/dist/**"
  ],
  collectCoverageFrom: [
    '**/*.(t|j)s',
    '!**/node_modules/**',
    '!**/dist/**'
  ],
  moduleFileExtensions: ['js', 'json', 'ts'],
  moduleNameMapper: {
    '^src/(.*)$': '<rootDir>/src/$1',
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest'
  },
  reporters: [
    'default',
    [
      'jest-html-reporter',
      {
        pageTitle: 'Stargate API Test Report',
        outputPath: 'test/reports/test-report.html',
        includeConsoleLog: true,
        includeSuiteFailure: true,
        includeStackTrace: true,
        includeFailureMsg: true,
        useCssFile: false,
        styleOverridePath: false,
        darkTheme: false,
        dateFormat: 'yyyy-mm-dd HH:MM:ss',
        executionTimeWarningThreshold: 5,
        sort: 'status',
        customScriptPath: './test/custom-reporter-enhancement.js',
        prependFile: false,
        appendFile: false,
        appendTimestamp: false,
        columns: [
          'suiteName',
          'testName',
          'status',
          'duration',
          'consoleLog'
        ]
      }
    ]
  ]
};