/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  // Enable this if tests are failing but all you get is
  // "Do not know how to serialize a BigInt" in messageParent.ts
  // maxWorkers: 1,
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: {
          target: "es2020",
          esModuleInterop: true,
          allowJs: true,
        },
      },
    ],
    "^.+\\.jsx?$": [
      "babel-jest",
      {
        presets: [["@babel/preset-env", { targets: { node: "current" }, modules: "commonjs" }]],
      },
    ],
  },
  transformIgnorePatterns: ["node_modules/(?!(@zkpassport)/)"],
}
