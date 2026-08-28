import { describe, expect, it } from "vitest";
import { getAllPatterns } from "../src/patterns/index.js";
import { secretPatterns } from "../src/patterns/secrets.js";
import { MAX_LINE_LENGTH } from "../src/core/constants.js";

/**
 * Sentinel is pointed at repositories it does not control, including pull
 * requests from strangers in CI. A pattern whose cost grows superlinearly with
 * line length turns a crafted file into a stalled scan, so every rule is held
 * to a time budget against inputs shaped to force backtracking.
 *
 * MAX_LINE_LENGTH bounds a single line, but a file may hold many of them: at
 * the 136ms BRACKET_NOTATION_USER_INPUT once cost, ten thousand such lines
 * stalled a scan for over twenty minutes.
 */

/**
 * The budget is relative, not absolute.
 *
 * An earlier version asserted a fixed number of milliseconds, which failed
 * whenever the suite ran under load: a linear pattern was measured at 42.9ms
 * against a 25ms limit purely through CPU contention. What this test exists to
 * catch is superlinear backtracking, which is thousands of times slower than a
 * well-behaved pattern rather than twice as slow, so comparing each rule
 * against a linear baseline measured on the same machine at the same moment is
 * both stricter and immune to load.
 */
const BASELINE_PATTERN = /[A-Za-z0-9_]{40,}/;
const BUDGET_MULTIPLE = 50;
/** Floor, so a baseline measured near zero cannot make the budget impossible. */
const BUDGET_FLOOR_MS = 20;

/**
 * Best of several runs, not a single sample.
 *
 * The relative budget below still has an absolute floor, and a single sample
 * crossed it under load: a linear rule measured 26.4ms against a 20ms floor
 * purely from CPU contention while three suites ran at once. Scheduler noise
 * only ever adds time, so the minimum of several runs is stable, while a
 * pattern that really backtracks is slow in every one of them - the case this
 * guards took 136ms on every attempt. Taking the best sample removes the
 * flake without weakening what the test detects.
 */
const SAMPLES = 5;

function measure(regex: RegExp, input: string): number {
  let best = Infinity;
  for (let attempt = 0; attempt < SAMPLES; attempt++) {
    const startedAt = process.hrtime.bigint();
    regex.lastIndex = 0;
    regex.exec(input);
    best = Math.min(best, Number(process.hrtime.bigint() - startedAt) / 1e6);
  }
  return best;
}

/** Time a known-linear pattern over the same inputs, right now. */
function baselineMs(inputs: readonly string[]): number {
  let worst = 0;
  for (const input of inputs) worst = Math.max(worst, measure(BASELINE_PATTERN, input));
  return worst;
}

const attacks = [
  "a".repeat(MAX_LINE_LENGTH),
  " ".repeat(MAX_LINE_LENGTH),
  "ab".repeat(MAX_LINE_LENGTH / 2),
  "=".repeat(MAX_LINE_LENGTH),
  `"${"a".repeat(MAX_LINE_LENGTH - 2)}"`,
  `query(\`${"${x}".repeat(MAX_LINE_LENGTH / 4)}\`)`,
  `exec(${"'a',".repeat(MAX_LINE_LENGTH / 4)})`,
  `cidr_blocks = [${'"0.0.0.0/0",'.repeat(MAX_LINE_LENGTH / 12)}]`,
  `password = ${"'".repeat(MAX_LINE_LENGTH)}`,
  `yaml.load(${"x,".repeat(MAX_LINE_LENGTH / 2)})`,
  `const a = ${"(".repeat(MAX_LINE_LENGTH)}`,
  `http://${"a.".repeat(MAX_LINE_LENGTH / 2)}`,
];

const allPatterns = [...getAllPatterns(), ...secretPatterns];

describe("pattern catalogue resists catastrophic backtracking", () => {
  it.each(allPatterns.map((p) => [p.id, p] as const))(
    "%s stays within the time budget on adversarial input",
    (id, pattern) => {
      const budget = Math.max(baselineMs(attacks) * BUDGET_MULTIPLE, BUDGET_FLOOR_MS);

      for (const input of attacks) {
        const elapsedMs = measure(pattern.regex, input);
        expect(
          elapsedMs,
          `${id} took ${elapsedMs.toFixed(1)}ms against a ${budget.toFixed(1)}ms budget`
        ).toBeLessThan(budget);
      }
    }
  );
});

describe("BRACKET_NOTATION_USER_INPUT", () => {
  const rule = allPatterns.find((p) => p.id === "BRACKET_NOTATION_USER_INPUT")!;
  const test = (line: string) => {
    rule.regex.lastIndex = 0;
    return rule.regex.test(line);
  };

  it("is bounded rather than quadratic in line length", () => {
    const time = (n: number) => {
      const line = "a".repeat(n);
      const startedAt = process.hrtime.bigint();
      rule.regex.lastIndex = 0;
      rule.regex.exec(line);
      return Number(process.hrtime.bigint() - startedAt) / 1e6;
    };

    // Quadratic growth showed as roughly 16x for 4x the input: 136ms where a
    // linear pattern took a fraction of a millisecond.
    const budget = Math.max(baselineMs(["a".repeat(4000)]) * BUDGET_MULTIPLE, BUDGET_FLOOR_MS);
    expect(time(4000)).toBeLessThan(budget);
  });

  it("still flags dynamic access driven by request data", () => {
    expect(test("obj[req.query]")).toBe(true);
    expect(test("target[ params.id ]")).toBe(true);
    expect(test("o[userInput]")).toBe(true);
    expect(test("data[query.name]")).toBe(true);
  });

  it("leaves static and unrelated property access alone", () => {
    expect(test("obj[safeKey]")).toBe(false);
    expect(test("arr[0]")).toBe(false);
    expect(test("map[other.thing]")).toBe(false);
  });
});
