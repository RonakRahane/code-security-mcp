# Sentinel architecture

This document describes the module layout, the scan pipeline, and the design
decisions that are easy to undo by accident.

## Layers

Imports flow in one direction. Nothing in a lower layer imports from a higher one.

```
types/      Shared type definitions. No runtime dependencies.
  ↓
core/       Cross-cutting primitives: constants, logging, severity, path
            validation, filesystem traversal, diagnostics, de-duplication.
  ↓
patterns/   Declarative rule definitions. Data only, no logic.
  ↓
scanner/    Analysis engines and the pipeline that orchestrates them.
  ↓
tools/      MCP tool handlers. Validate input, call the scanner, shape output.
  ↓
index.ts    Entry point: CLI mode and MCP stdio server mode.
```

`reporting/`, `dashboard/`, and `github/` are leaf modules used by `tools/` and
`index.ts`.

## The scan pipeline

`runUnifiedScan()` in [`src/scanner/unified-scanner.ts`](../src/scanner/unified-scanner.ts)
is the single entry point for a project scan. Every tool that scans a tree goes
through it, including SARIF export. A second walker would drift out of sync
with the first, and the two would disagree about what was covered.

1. **Resolve and configure.** The root is resolved through `realpath`, then
   `sentinel.config.json` and `.sentinelignore` are loaded. Config parse errors
   become warnings, never silent defaults.
2. **Static analysis.** Semgrep runs if available; otherwise the built-in
   pattern engine runs during the file sweep. The engine actually used is
   recorded in the result.
3. **File sweep.** One asynchronous, bounded-concurrency walk reads every
   candidate file once and runs the enabled analyses over it.
4. **Dependency audit.** Manifests are discovered by the same walker, parsed,
   and queried against OSV in batches. A reachability index is built once per
   manifest and reused for all of its advisories.
5. **De-duplication.** Overlapping reports of one issue are collapsed.
6. **Policy filtering.** `ignoreRules`, then `minimumSeverity`.
7. **Baseline suppression.** Known fingerprints from `.sentinel-baseline.json`.
8. **Sort and summarise.** Deterministic ordering, then coverage accounting.

## Decisions worth preserving

### Logs go to stderr, always

In MCP stdio mode, **stdout carries the JSON-RPC framing**. A single `console.log`
in a scanner corrupts the protocol stream and disconnects the client. Use
`logger` from `core/logger.ts`; it writes structured JSON to stderr and redacts
credential-shaped fields.

### Traversal limits live in one place

`core/constants.ts` owns the ignored-directory set, skip extensions, and size
caps. Redefining them per walker makes coverage depend on which entry point the
caller used, so every scan path reads them from here.

### Failures become warnings, not silence

`core/diagnostics.ts` collects every unreadable path and configuration problem
and surfaces them in `warnings[]` and the report's Scan Coverage section.

This is the difference between "no vulnerabilities found" and "no vulnerabilities
looked for". A scan that could not read half a repository must not present
itself as clean, because the user will act on that silence.

Per-path detail is logged at `debug`; repeated failures are aggregated into one
warning per cause so a permission problem across 900 files reads as one
actionable line.

### Two masking scopes

`maskCode()` blanks comments and string literals so rules match executable code
rather than prose, which is what stops a code sample in a docstring from being
reported as a vulnerability.

But some rules need the *inside* of a literal: the algorithm name in
`createHash("md5")`, the `%s` in a formatted SQL string, the `"*"` in
`ALLOWED_HOSTS = ["*"]`. Those declare `matchScope: "literal"` and are matched
against a view where only comments are blanked.

Both views preserve length and line count, so offsets and line numbers remain
valid against the original source. **If you change masking, preserve that
invariant**: `renderLineContent()` relies on it to redact secrets.

### Secrets are redacted at the point of detection

Findings travel into Markdown reports, SARIF uploaded to code-scanning
dashboards, MCP responses read by a model, and CI logs. A finding that echoed
the credential would turn each of those into a new place the secret is stored,
the tool would widen the exposure it exists to report.

`redactLine()` masks the value everywhere `lineContent` is produced, keeping a
four-character prefix so the credential type stays identifiable.

### No shell, anywhere

Subprocesses use `execFile`/`execFileSync` with argument arrays. Nothing is
interpolated into a command string. Beyond removing the injection surface, this
is what makes repository paths containing spaces or quotes work on Windows,
where POSIX-style shell quoting is not quoting at all.

### Registry rules are opt-in

Semgrep `p/*` packs are fetched at scan time, which makes results depend on
network access and on whatever the registry currently serves. Two runs against
one commit can disagree. Default is the versioned packs in `rules/`; see the
README for the opt-in.

### Symlinks are resolved and bounded

The walker follows a symlink only when its real path stays inside the scan root,
and de-duplicates directories by real path so a link cycle terminates. Without
the containment check, a repository could redirect the scanner at arbitrary host
files and have their contents returned in findings.

## Concurrency and resource bounds

| Bound | Default | Why |
| :--- | :--- | :--- |
| Parallel file reads | 16 | Keeps throughput high without exhausting file descriptors. |
| Max file size | 1 MB | Generated bundles dominate cost and yield nothing actionable. |
| Max line length | 5 000 | The practical ReDoS control for a regex engine. |
| Max files | 25 000 | Bounds a runaway monorepo; truncation is reported. |
| Max directory depth | 40 | Backstop against pathological trees. |
| OSV batch size | 500 | Stays a polite client of a shared public service. |
| OSV timeout / retries | 20 s, 3 attempts | A hung connection must not stall a scan. |

## Testing

`test/` holds the vitest suite; `test/fixtures/` holds the labelled corpus.

Scanner tests run with `offline: true` so no verdict depends on connectivity. A
suite that changes its answer based on the network cannot gate a release.

Tests that need `git` skip themselves when it is unavailable rather than
failing. Symlink tests skip when the platform forbids creating them
unprivileged.
