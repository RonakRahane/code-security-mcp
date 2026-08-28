/**
 * Locates Semgrep, and installs it when it is missing.
 *
 * Semgrep is not an npm dependency - it is a Python program the user installs
 * separately - so the default state on a fresh machine is "absent". Without it
 * Sentinel falls back to the line-local pattern engine, which cannot follow a
 * value from an HTTP parameter through a variable into a sink. A scan that
 * silently runs in that mode reports "no findings" for whole classes of bug it
 * never looked for, which is worse than not scanning at all: it produces a
 * clean result the reader believes.
 *
 * So Semgrep is treated as a hard requirement that this module satisfies,
 * rather than a feature that degrades quietly.
 *
 * Constraints this installation path holds to, because a security scanner that
 * installs software is a supply-chain surface of its own:
 *
 *   - Never `sudo`, and never a system directory. Every strategy installs into
 *     the user's own prefix.
 *   - Never a shell. Commands are argv arrays, so no part of the environment
 *     or of a scanned repository can be interpreted as a command.
 *   - The installed binary is verified by running it and parsing its version,
 *     not by trusting the package manager's exit code.
 *   - Opt out with SENTINEL_NO_AUTO_INSTALL=1, for images and CI runners where
 *     installing anything at runtime is the wrong behaviour.
 *   - Nothing here writes to stdout. In MCP stdio mode stdout carries the
 *     JSON-RPC frames, and a stray byte from a package manager would corrupt
 *     the protocol.
 */

import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { promisify } from "util";
import { logger } from "./logger.js";

const execFileAsync = promisify(execFile);

/** Probing an installed binary is fast; anything slower than this is broken. */
const PROBE_TIMEOUT_MS = 15_000;

/** Semgrep pulls a large dependency tree, so a first install is measured in minutes. */
const INSTALL_TIMEOUT_MS = 600_000;

/**
 * Below this, `--json` output and the taint-mode fields Sentinel's rules use
 * are not dependable.
 */
const MIN_SEMGREP_VERSION: readonly [number, number, number] = [1, 0, 0];

export type SemgrepReadiness =
  | {
      status: "ready";
      /** Absolute path, or a bare name already resolvable on PATH. */
      binary: string;
      version: string;
      /** True when this process installed it rather than finding it. */
      installed: boolean;
    }
  | {
      status: "unavailable";
      message: string;
      /** Package managers tried, for a diagnostic that names what to fix. */
      attempted: string[];
    };

let readinessPromise: Promise<SemgrepReadiness> | undefined;

/**
 * Resolves Semgrep, installing it if required.
 *
 * Memoised on the promise rather than the result, so concurrent scans share a
 * single install instead of racing several package managers over the same
 * prefix.
 */
export function ensureSemgrep(): Promise<SemgrepReadiness> {
  readinessPromise ??= resolveSemgrep();
  return readinessPromise;
}

/** Test seam. Production code has no reason to re-run detection. */
export function resetSemgrepReadinessCache(): void {
  readinessPromise = undefined;
}

async function resolveSemgrep(): Promise<SemgrepReadiness> {
  const found = await locateSemgrep();
  if (isLocated(found)) {
    logger.debug("semgrep found", { binary: found.binary, version: found.version });
    return { status: "ready", binary: found.binary, version: found.version, installed: false };
  }

  // Semgrep is on the machine but would not run. Installing over it would add
  // a second copy without addressing why the first one is stuck, so this is
  // reported for a human to look at instead.
  if (found) {
    return {
      status: "unavailable",
      attempted: [],
      message:
        `Semgrep is present but did not run: ${found.blocked}. Sentinel did not install over it. ` +
        `Check that installation, or point SENTINEL_SEMGREP_BIN at a working one.`,
    };
  }

  // A pinned binary that does not run is an operator error, and installing
  // would not fix it: detection only ever looks at the pinned path, so a
  // successful install would still resolve to nothing. Say which path failed.
  const explicit = process.env.SENTINEL_SEMGREP_BIN?.trim();
  if (explicit) {
    return {
      status: "unavailable",
      attempted: [],
      message:
        `SENTINEL_SEMGREP_BIN is set to "${explicit}", but that is not a working Semgrep ` +
        `${MIN_SEMGREP_VERSION.join(".")} or newer. Correct the path, or unset it to let Sentinel find ` +
        `or install Semgrep itself.`,
    };
  }

  if (autoInstallDisabled()) {
    return {
      status: "unavailable",
      attempted: [],
      message:
        "Semgrep is not installed and SENTINEL_NO_AUTO_INSTALL is set, so it was not installed automatically. " +
        `Install it with one of: ${INSTALL_HINTS}`,
    };
  }

  logger.info("semgrep not found, installing", { timeoutMs: INSTALL_TIMEOUT_MS });
  const attempted: string[] = [];

  for (const strategy of installStrategies()) {
    const command = await strategy.resolveCommand();
    // Its own package manager is absent; that is not a failure worth reporting.
    if (!command) continue;

    attempted.push(strategy.name);
    logger.info("installing semgrep", { via: strategy.name });

    const outcome = await runInstall(command.file, command.args);
    if (!outcome.ok) {
      logger.warn("semgrep install failed", { via: strategy.name, reason: outcome.reason });
      continue;
    }

    // The manager's exit code says it thinks it succeeded. Whether Semgrep now
    // runs is a separate question, and the only one that matters.
    const installed = await locateSemgrep();
    if (isLocated(installed)) {
      logger.info("semgrep installed", {
        via: strategy.name,
        binary: installed.binary,
        version: installed.version,
      });
      return { status: "ready", binary: installed.binary, version: installed.version, installed: true };
    }

    logger.warn("semgrep install reported success but no working binary was found", {
      via: strategy.name,
    });
  }

  return {
    status: "unavailable",
    attempted,
    message:
      attempted.length === 0
        ? "Semgrep is not installed, and no supported installer (uv, pipx, pip, brew) was available to install it. " +
          `Install it manually with one of: ${INSTALL_HINTS}`
        : `Semgrep is not installed, and installing it failed (tried: ${attempted.join(", ")}). ` +
          `Install it manually with one of: ${INSTALL_HINTS}`,
  };
}

const INSTALL_HINTS =
  "`pipx install semgrep`, `uv tool install semgrep`, `python3 -m pip install --user semgrep`, or `brew install semgrep`.";

function autoInstallDisabled(): boolean {
  const value = process.env.SENTINEL_NO_AUTO_INSTALL;
  return value !== undefined && value !== "" && value !== "0" && value.toLowerCase() !== "false";
}

/**
 * The package specifier passed to pip-family installers.
 *
 * Runtime-installing an unpinned package is a supply-chain surface, so
 * SENTINEL_SEMGREP_VERSION exists to pin it. The default takes the current
 * release, because a scanner pinned to an old rule engine goes stale in a way
 * that is also a security problem.
 */
function packageSpec(): string {
  const pinned = process.env.SENTINEL_SEMGREP_VERSION?.trim();
  // Anything outside a plain version would otherwise let the environment
  // inject a specifier of its own - a URL, a local path, an extra index.
  if (pinned && /^\d+(\.\d+){0,2}$/.test(pinned)) return `semgrep==${pinned}`;
  if (pinned) logger.warn("ignoring malformed SENTINEL_SEMGREP_VERSION", { value: pinned });
  return "semgrep";
}

interface InstallStrategy {
  name: string;
  resolveCommand: () => Promise<{ file: string; args: string[] } | undefined>;
}

/**
 * Ordered by isolation. uv and pipx each give Semgrep its own environment;
 * `pip --user` shares the user's site-packages; brew is last because it is the
 * slowest and the most likely to pull unrelated upgrades.
 */
function installStrategies(): InstallStrategy[] {
  const spec = packageSpec();

  return [
    {
      name: "uv",
      resolveCommand: async () =>
        (await commandExists("uv")) ? { file: "uv", args: ["tool", "install", spec] } : undefined,
    },
    {
      name: "pipx",
      resolveCommand: async () =>
        (await commandExists("pipx")) ? { file: "pipx", args: ["install", spec] } : undefined,
    },
    {
      name: "pip",
      resolveCommand: async () => {
        const python = await findPython();
        if (!python) return undefined;
        // --user keeps this out of any system prefix. On a PEP 668
        // "externally managed" interpreter it is refused outright, which is
        // the correct outcome: the next strategy handles it.
        return { file: python, args: ["-m", "pip", "install", "--user", spec] };
      },
    },
    {
      name: "brew",
      resolveCommand: async () =>
        process.platform === "darwin" && (await commandExists("brew"))
          ? { file: "brew", args: ["install", "semgrep"] }
          : undefined,
    },
  ];
}

async function runInstall(
  file: string,
  args: string[]
): Promise<{ ok: true } | { ok: false; reason: string }> {
  try {
    await execFileAsync(file, args, {
      timeout: INSTALL_TIMEOUT_MS,
      // SIGTERM is a request. An installer that traps it would hold the scan
      // open past its deadline.
      killSignal: "SIGKILL",
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024,
      // A package manager that decides to prompt would otherwise block
      // forever behind a terminal nobody is watching.
      env: { ...process.env, PIP_DISABLE_PIP_VERSION_CHECK: "1", NONINTERACTIVE: "1" },
    });
    return { ok: true };
  } catch (error) {
    const failure = error as NodeJS.ErrnoException & { stderr?: string; killed?: boolean };
    if (failure.killed) return { ok: false, reason: "install timed out" };
    const stderr = (failure.stderr || "").trim();
    if (stderr.includes("externally-managed-environment")) {
      return { ok: false, reason: "interpreter is externally managed (PEP 668)" };
    }
    return { ok: false, reason: firstLine(stderr) || failure.message || "unknown install failure" };
  }
}

interface LocatedSemgrep {
  binary: string;
  version: string;
}

/**
 * Finds a Semgrep that actually runs and is new enough.
 *
 * Candidates are probed by execution rather than by existence: a file at
 * ~/.local/bin/semgrep may be a broken symlink from a removed virtualenv, and
 * a stale one is indistinguishable from a working one on disk.
 */
async function locateSemgrep(): Promise<LocatedSemgrep | { blocked: string } | undefined> {
  let blocked: string | undefined;

  for (const candidate of semgrepCandidates()) {
    const probe = await probeSemgrep(candidate);
    if (probe.kind === "absent") continue;

    if (probe.kind === "unusable") {
      // Remembered rather than returned: a later candidate may still work, and
      // only a full sweep with no working binary makes this the answer.
      blocked ??= `${candidate} ${probe.reason}`;
      logger.warn("semgrep candidate did not run", { binary: candidate, reason: probe.reason });
      continue;
    }

    if (!meetsMinimumVersion(probe.version)) {
      logger.warn("ignoring Semgrep older than the minimum supported version", {
        binary: candidate,
        version: probe.version,
        minimum: MIN_SEMGREP_VERSION.join("."),
      });
      continue;
    }

    return { binary: candidate, version: probe.version };
  }

  return blocked ? { blocked } : undefined;
}

function isLocated(value: LocatedSemgrep | { blocked: string } | undefined): value is LocatedSemgrep {
  return value !== undefined && "binary" in value;
}

/**
 * PATH first, then the user-prefix directories the supported installers write
 * to. Those are probed explicitly because a GUI-launched MCP client inherits a
 * minimal PATH from the desktop session, so a perfectly good ~/.local/bin
 * install is invisible to `semgrep` alone.
 */
function semgrepCandidates(): string[] {
  // An explicitly named binary is the whole list. Falling back to a different
  // Semgrep than the one an operator pinned would quietly run something other
  // than what they vetted, and a wrong binary is better reported than
  // substituted.
  const explicit = process.env.SENTINEL_SEMGREP_BIN?.trim();
  if (explicit) return [explicit];

  const candidates = ["semgrep"];
  const home = os.homedir();
  const exe = process.platform === "win32" ? "semgrep.exe" : "semgrep";
  const prefixes = [
    path.join(home, ".local", "bin"),
    path.join(home, "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
  ];

  if (process.platform === "win32" && process.env.APPDATA) {
    prefixes.push(path.join(process.env.APPDATA, "Python", "Scripts"));
  }

  for (const prefix of prefixes) {
    const candidate = path.join(prefix, exe);
    if (!candidates.includes(candidate) && fs.existsSync(candidate)) candidates.push(candidate);
  }

  return candidates;
}

type ProbeResult =
  | { kind: "ok"; version: string }
  /** Nothing at that path. The only outcome that justifies installing. */
  | { kind: "absent" }
  /** Present but did not answer: a timeout under load, or a broken install. */
  | { kind: "unusable"; reason: string };

async function probeSemgrep(binary: string): Promise<ProbeResult> {
  try {
    const { stdout } = await execFileAsync(binary, ["--version"], {
      timeout: PROBE_TIMEOUT_MS,
      killSignal: "SIGKILL",
      windowsHide: true,
      encoding: "utf-8",
    });
    // Semgrep prints a bare version, but a wrapper script may add a banner
    // first, so take the first thing shaped like a version anywhere in it.
    const match = /(\d+)\.(\d+)\.(\d+)/.exec(stdout);
    return match ? { kind: "ok", version: match[0] } : { kind: "unusable", reason: "no version in output" };
  } catch (error) {
    const failure = error as NodeJS.ErrnoException & { killed?: boolean };
    if (failure.code === "ENOENT") return { kind: "absent" };
    // A machine under load can take longer than the probe allows. Reading that
    // as "not installed" would install a second copy of a Semgrep that is
    // already there, so the two cases are kept apart.
    if (failure.killed) return { kind: "unusable", reason: "did not respond to --version in time" };
    return { kind: "unusable", reason: failure.message || "could not be run" };
  }
}

function meetsMinimumVersion(version: string): boolean {
  const parts = version.split(".").map((part) => Number.parseInt(part, 10));
  for (let index = 0; index < MIN_SEMGREP_VERSION.length; index++) {
    const actual = parts[index] ?? 0;
    const required = MIN_SEMGREP_VERSION[index];
    if (actual > required) return true;
    if (actual < required) return false;
  }
  return true;
}

async function commandExists(command: string): Promise<boolean> {
  try {
    await execFileAsync(command, ["--version"], {
      timeout: PROBE_TIMEOUT_MS,
      killSignal: "SIGKILL",
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}

/** The first interpreter that runs. `python` may be absent, or may be Python 2. */
async function findPython(): Promise<string | undefined> {
  for (const candidate of ["python3", "python"]) {
    try {
      const { stdout, stderr } = await execFileAsync(candidate, ["--version"], {
        timeout: PROBE_TIMEOUT_MS,
        killSignal: "SIGKILL",
        windowsHide: true,
        encoding: "utf-8",
      });
      // Python 2 printed its version to stderr; either stream may carry it.
      const major = /Python (\d+)\./.exec(`${stdout}${stderr}`);
      if (major && Number.parseInt(major[1], 10) >= 3) return candidate;
    } catch {
      continue;
    }
  }
  return undefined;
}

function firstLine(text: string): string {
  const line = text.split("\n").find((entry) => entry.trim());
  return line ? line.trim().slice(0, 300) : "";
}
