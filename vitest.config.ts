import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // Scanner tests touch the filesystem, spawn git, and run Semgrep. Semgrep
    // carries a large fixed startup cost, measured here at roughly 7 seconds
    // before it reads a single rule, so a test performing three scans needs
    // well over the 30 seconds this used to allow. The limit is a guard
    // against a hang, not a performance assertion.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    coverage: {
      provider: "v8",
      reportsDirectory: "coverage",
      include: ["src/**/*.ts"],
      exclude: ["src/**/index.ts", "src/patterns/**"],
      // Set just under the current measured level. The point is to fail when
      // coverage regresses, not to chase a round number.
      thresholds: {
        lines: 65,
        functions: 72,
        statements: 65,
        branches: 75,
      },
    },
  },
});
