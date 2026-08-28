# Security model

Sentinel reads source code, spawns subprocesses, and returns results to an AI
client. This document states what it defends against, what it does not, and how
to report a problem.

## Reporting a vulnerability

Please report privately rather than opening a public issue. Include a
reproduction and the affected version. We aim to acknowledge within 72 hours.

## Trust boundaries

| Input | Trust | Handling |
| :--- | :--- | :--- |
| MCP tool arguments | **Untrusted** | The model producing them has been reading the repository under scan. Validated in `core/paths.ts`. |
| Scanned source code | **Untrusted** | Read as data. Never executed, never evaluated. |
| `sentinel.config.json` | Semi-trusted | Field-by-field validation; invalid values are rejected with a warning, not silently applied. |
| `.sentinel-baseline.json` | Semi-trusted | Schema-validated. It suppresses findings, so a malformed baseline throws rather than silently hiding results. |
| Semgrep registry packs | **Untrusted** | Off by default. See "Rule provenance". |
| OSV API responses | Semi-trusted | Parsed into typed structures; only known fields are read. |
| `GITHUB_TOKEN` | Secret | Read from the environment, never logged or echoed. |

## Controls

### Path validation

Every caller-supplied path is resolved, length-checked, rejected if it contains
a NUL byte, confirmed to be of the expected kind, and, when
`SENTINEL_ALLOWED_ROOTS` is set, confirmed to resolve inside an allowed root.

The allowlist is compared against the **real** path, so a symlink inside an
allowed directory cannot grant access to a target outside it.

A NUL byte matters specifically because it truncates the path at the libc
boundary: a value that passes JavaScript-side checks could otherwise address a
different file than the one that was validated.

### No shell execution

All subprocesses use `execFile`/`execFileSync` with argument arrays. No value is
interpolated into a command string, so no argument can be reinterpreted as a
command regardless of its contents (CWE-78).

Git receives `GIT_TERMINAL_PROMPT=0` so a repository with remotes cannot block
the scan on a credential prompt.

### Secret redaction

Detected credentials are masked wherever they are reported: Markdown, SARIF,
JSON tool responses, and logs. `maskSecretValue()` keeps a four-character prefix
so the credential type is identifiable without disclosing the value.

The logger independently redacts fields whose names look credential-bearing
(`token`, `secret`, `password`, `authorization`, `api_key`, `cookie`, …).

### Traversal containment

The walker follows a symlink only when its real path stays within the scan root,
and de-duplicates directories by real path so link cycles terminate. Sockets,
FIFOs, and device files are skipped, since reading them can block indefinitely.

### Resource bounds

File size, line length, file count, directory depth, subprocess timeouts, HTTP
timeouts, and warning counts are all capped. See the table in
[architecture.md](architecture.md).

Line-length capping is the practical control against catastrophic regex
backtracking: minified and generated single-line files are the realistic
trigger, and they contain nothing a reviewer can act on.

### Write operations

Sentinel writes in exactly three places, all of them intentional:

1. `sentinel-report.md` in the scanned project root. Suppress with `--no-report-file`.
2. The `--sarif` path, when requested.
3. `auto_fix` with `applyFixes: true`.

`auto_fix` defaults to a dry run. When it does write, it applies only
high-confidence single-line replacements, saves the original to
`<file>.sentinel.bak`, and writes through a temporary file and rename so an
interrupted write cannot truncate the user's source.

### Determinism and rule provenance

Findings are sorted by severity, then path, then line, so two runs over an
unchanged tree produce byte-identical output. A CI gate that flips between runs
is not a gate.

Rule packs ship in [`rules/`](../rules/) and are versioned with the code.
Semgrep registry packs are **not** used unless explicitly enabled, because they
are downloaded at scan time: results would depend on network access and on
whatever the registry currently serves, and a compromised registry would run
attacker-chosen rules against your source (CWE-829). When enabled, every scan
warns that it used them.

### Network behaviour

The only outbound request is a POST to `https://api.osv.dev/v1/querybatch`
containing package names and versions only, never source code, file paths,
or repository identifiers. Set `offline: true` or `SENTINEL_OFFLINE=1` to
disable it; the scan then reports that advisory lookups were skipped rather than
quietly returning no dependency findings.

There is no telemetry. Semgrep is invoked with `--metrics=off`.

## Known limitations

These are properties of the design, not defects:

* **Not a sandbox.** Sentinel runs with the privileges of the invoking user. In
  a shared or hosted deployment, confine it with `SENTINEL_ALLOWED_ROOTS` and OS
  controls.
* **No authentication or authorization.** The stdio transport inherits the trust
  of the local process that spawned it. Multi-user and RBAC deployments are out
  of scope.
* **No audit log.** Structured logs go to stderr; there is no tamper-evident
  audit trail.
* **Semgrep runs unsandboxed.** It is a separate tool with its own trust
  assumptions and receives a timeout only.
* **Static analysis cannot prove absence.** A clean scan means "these rules
  found nothing", not "this code is secure".
* **Without Semgrep, no dataflow.** The built-in engine matches one line at a
  time and will miss issues where a tainted value passes through a local
  variable. Every report states which engine ran.

## Dependency hygiene

`npm audit` is expected to be clean for runtime dependencies. Report findings in
transitive development dependencies as issues; they do not ship in the published
package, whose `files` field limits the artifact to `dist/` and `rules/`.
