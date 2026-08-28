/**
 * Structured logger. Every record goes to stderr: in MCP stdio mode stdout
 * carries the JSON-RPC framing, and one stray write there corrupts the stream.
 */

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

/** Keys whose values are replaced with a redaction marker before they are logged. */
const SENSITIVE_KEY = /(token|secret|password|passwd|credential|authorization|api[-_]?key|cookie|session)/i;

const REDACTED = "[redacted]";

function resolveLevel(): LogLevel {
  const configured = (process.env.SENTINEL_LOG_LEVEL || "").toLowerCase();
  if (configured in LEVEL_RANK) return configured as LogLevel;
  return "warn";
}

let activeLevel: LogLevel = resolveLevel();

export function setLogLevel(level: LogLevel): void {
  activeLevel = level;
}

export type LogFields = Record<string, unknown>;

/** Strips credential-looking values so diagnostic logs do not become a leak. */
function redact(fields: LogFields): LogFields {
  const safe: LogFields = {};
  for (const [key, value] of Object.entries(fields)) {
    if (SENSITIVE_KEY.test(key)) {
      safe[key] = REDACTED;
    } else if (value instanceof Error) {
      safe[key] = value.message;
    } else if (typeof value === "string") {
      safe[key] = value.length > 500 ? `${value.slice(0, 500)}…` : value;
    } else {
      safe[key] = value;
    }
  }
  return safe;
}

function emit(level: Exclude<LogLevel, "silent">, message: string, fields?: LogFields): void {
  if (LEVEL_RANK[level] < LEVEL_RANK[activeLevel]) return;

  const record = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...(fields ? redact(fields) : {}),
  };

  try {
    process.stderr.write(`${JSON.stringify(record)}\n`);
  } catch {
    // A logger must never take down a scan. If stderr is closed (piped and the
    // reader exited), dropping the record is the only correct behaviour.
  }
}

export const logger = {
  debug: (message: string, fields?: LogFields) => emit("debug", message, fields),
  info: (message: string, fields?: LogFields) => emit("info", message, fields),
  warn: (message: string, fields?: LogFields) => emit("warn", message, fields),
  error: (message: string, fields?: LogFields) => emit("error", message, fields),
};

/** Normalises unknown throwables into a message suitable for users and logs. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "unknown error";
}
