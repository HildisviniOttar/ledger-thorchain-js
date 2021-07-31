// For a detailed explanation regarding each configuration property, visit:
// https://jestjs.io/docs/en/configuration.html

module.exports = {
  preset: 'ts-jest',
  modulePaths: ["<rootDir>/src", "<rootDir>/tests"],
  testPathIgnorePatterns: ['<rootDir>/node_modules', '<rootDir>/dist'],
  // Automatically clear mock calls and instances between every test
  clearMocks: true,
  // The test environment that will be used for testing
  testEnvironment: "node",
  // The glob patterns Jest uses to detect test files
  testMatch: [
    "**/tests/**/*.[jt]s?(x)",
    "**/?(*.)+(spec|test).[tj]s?(x)",
    "**/?(*.)+(ispec|test).[tj]s?(x)",
  ],
};
