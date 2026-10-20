const levels = new Set(["info", "trace", "warn", "error"]);

export function normalizeLogging(logging = true, getContext) {
  if (logging !== true && !["object", "function"].includes(typeof logging)) return null;
  if (logging === null) return null;

  const normalized = { getContext, target: logging };
  for (const level of levels) {
    const fallback = level === "error" ? console.error : console.log;
    normalized[level] = logging[level] ?? fallback.bind(console);
  }
  return normalized;
}

export function log(logging, level, path, message, details) {
  const logger = logging?.[levels.has(level) ? level : "info"];
  if (typeof logger !== "function") return;
  const txId = logging.getContext?.()?.txId || '';
  logger.call(logging.target ?? logging, "[IAM]", `[${path}]`, txId, message, redact(details));
}

function redact(details) {
  if (!details || typeof details !== "object") return details;
  return Object.fromEntries(Object.entries(details).map(([key, value]) => [
    key,
    /password|passwd|token|secret|api[_-]?key/i.test(key) ? "[REDACTED]" : value
  ]));
}
