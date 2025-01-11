/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
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
