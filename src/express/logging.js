const levels = new Set(["info", "trace", "warn", "error"]);

export function normalizeLogging(logging) {
  const disabled = { info: false, trace: false, warn: false, error: false };
  const defaults = {
    info: console.log.bind(console),
    trace: console.log.bind(console),
    warn: console.log.bind(console),
    error: console.error.bind(console)
  };

  if (logging === undefined || logging === true) return { ...defaults };
  if (logging === false || logging === null || (typeof logging !== "object" && typeof logging !== "function")) return disabled;
  return {
    info: logging.info ?? defaults.info,
    trace: logging.trace ?? defaults.trace,
    warn: logging.warn ?? defaults.warn,
    error: logging.error ?? defaults.error,
    target: logging
  };
}

export function log(logging, level, message, details) {
  const logger = logging?.[levels.has(level) ? level : "info"];
  if (typeof logger !== "function") return;
  logger.call(logging.target ?? logging, "[IAM]", message, redact(details));
}

function redact(details) {
  if (!details || typeof details !== "object") return details;
  return Object.fromEntries(Object.entries(details).map(([key, value]) => [
    key,
    /password|passwd|token|secret|api[_-]?key/i.test(key) ? "[REDACTED]" : value
  ]));
}
