import { jwtVerify, SignJWT } from 'jose';
import { randomBytes, randomUUID, createHash } from 'node:crypto';

class RbacError extends Error {
  constructor(message, status = 400, code = "RBAC_ERROR", errors = {}, stack) {
    super(message);

    this.name = this.constructor.name;
    this.status = status;
    this.code = code;
    this.errors = errors;
    this.isOperational = true;
    if (stack) this.stack = stack;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

class AuthRequiredError extends RbacError {
  constructor(message = "Usuario y clave son necesarios") {
    super(message, 401, "AUTH_REQUIRED");
  }
}

class AuthError extends RbacError {
  constructor(message = "Credenciales inválidas") {
    super(message, 401, "AUTH_ERROR");
  }
}

class TokenRequiredError extends RbacError {
  constructor(message = "Token requerido") {
    super(message, 401, "TOKEN_REQUIRED");
  }
}

class TokenInvalidError extends RbacError {
  constructor(message = "Token inválido") {
    super(message, 401, "TOKEN_INVALID");
  }
}

class SessionRequiredError extends RbacError {
  constructor(message = "Sesión requerida") {
    super(message, 401, "SESSION_REQUIRED");
  }
}

class SessionInactiveError extends RbacError {
  constructor(message = "Sesión inactiva") {
    super(message, 401, "SESSION_INACTIVE");
  }
}

class PermissionRequiredError extends RbacError {
  constructor(message = "Permiso requerido") {
    super(message, 403, "PERMISSION_REQUIRED");
  }
}

class ForbiddenError extends RbacError {
  constructor(message = "No tiene permisos para realizar esta acción") {
    super(message, 403, "FORBIDDEN");
  }
}

class NotFoundError extends RbacError {
  constructor(message = "Registro no encontrado") {
    super(message, 404, "NOT_FOUND");
  }
}

class AdapterError extends RbacError {
  constructor(message = "Adapter requerido", errors = {}) {
    super(message, 500, "ADAPTER_ERROR", errors);
  }
}

class ValidationError extends RbacError {
  constructor(message = "Error de validación", errors = {}) {
    super(message, 400, "VALIDATION_ERROR", errors);
  }
}

function now() {
  return new Date();
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    options: user.options ?? {}
  };
}

function publicSession(session, user, extras = {}) {
  return {
    id: session.id,
    user: publicUser(user),
    options: session.options ?? {},
    ...extras
  };
}

function createSessionId() {
  const time = Date.now().toString(36).toUpperCase().padStart(10, "0");
  const random = Math.random().toString(36).slice(2, 18).toUpperCase().padEnd(16, "0");
  return `${time}${random}`.slice(0, 26);
}

function ensureAdapter(adapter) {
  if (!adapter) {
    throw new AdapterError("Adapter requerido");
  }
}

/**
 * Role-based access helper backed by an IAM adapter.
 */
class RBAC {
  /**
   * @param {{ adapter: import("../types.js").Adapter }} options
   */
  constructor({ adapter } = {}) {
    ensureAdapter(adapter);
    this.adapter = adapter;
  }

  /**
   * @param {import("../types.js").Id} userId
   * @returns {Promise<import("../types.js").RoleData[]>}
   */
  async getRoles(userId) {
    return this.adapter.findRolesByUserId(userId);
  }

  /**
   * @param {import("../types.js").Id} userId
   * @param {string} [permission]
   * @returns {Promise<import("../types.js").PermissionData[]>}
   */
  async getPermissions(userId, permission) {
    return this.adapter.findPermissionsByUserId(userId, permission);
  }

  /**
   * @param {import("../types.js").Id} userId
   * @param {string} role
   * @returns {Promise<boolean>}
   */
  async hasRole(userId, role) {
    const roles = await this.getRoles(userId);
    return roles.some((item) => item.role === role && item.active !== false);
  }

  /**
   * @param {import("../types.js").Id} userId
   * @param {string} permission
   * @returns {Promise<boolean>}
   */
  async can(userId, permission) {
    const permissions = await this.getPermissions(userId, permission);
    return permissions.some((item) => item.permission === permission && item.active !== false);
  }
}

const expressContext = Symbol("iam.expressContext");

function setContext(req, context) {
  req[expressContext] = context;
}

function getContext(req) {
  return req[expressContext];
}

const levels = new Set(["info", "trace", "warn", "error"]);

function normalizeLogging(logging = true, getContext) {
  if (logging !== true && !["object", "function"].includes(typeof logging)) return null;
  if (logging === null) return null;

  const normalized = { getContext, target: logging };
  for (const level of levels) {
    const fallback = level === "error" ? console.error : console.log;
    normalized[level] = logging[level] ?? fallback.bind(console);
  }
  return normalized;
}

function log(logging, level, path, message, details) {
  const logger = logging?.[levels.has(level) ? level : "info"];
  if (typeof logger !== "function") return;
  const txId = logging.getContext?.()?.txId || '';
  logger.call(logging.target ?? logging, "[IAM]", path, txId, message, redact(details));
}

function redact(details) {
  if (!details || typeof details !== "object") return details;
  return Object.fromEntries(Object.entries(details).map(([key, value]) => [
    key,
    /password|passwd|token|secret|api[_-]?key/i.test(key) ? "[REDACTED]" : value
  ]));
}

function requireMethods(adapter, ...methods) {
  for (const method of methods) {
    if (typeof adapter?.[method] !== "function") throw new AdapterError(`Adapter requiere ${method}`);
  }
}

function bodyFields(body, allowed) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new ValidationError("Cuerpo requerido");
  if (Object.keys(body).some(key => !allowed.includes(key))) throw new ValidationError("Campo no permitido");
}

function passwordValue(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 255) throw new ValidationError("Contrasena requerida (maximo 255 caracteres)");
  return value;
}

function profileValues(body, required = false) {
  const values = {};
  for (const field of ["name", "email"]) {
    if (required || Object.hasOwn(body, field)) {
      if (typeof body[field] !== "string" || !body[field].trim() || body[field].trim().length > 150) throw new ValidationError(`${field} requerido (maximo 150 caracteres)`);
      values[field] = body[field].trim();
    }
  }
  if (values.email !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) throw new ValidationError("Email invalido");
  return values;
}

async function register(adapter, body) {
  requireMethods(adapter, "createUser");
  bodyFields(body, ["name", "email", "password"]);
  const values = profileValues(body, true);
  const password = passwordValue(body.password);
  return publicUser(await adapter.createUser({ id: randomUUID(), ...values, password, active: true, options: {} }));
}

async function updateProfile(adapter, userId, body) {
  requireMethods(adapter, "updateUser");
  bodyFields(body, ["name", "email"]);
  const values = profileValues(body);
  if (!Object.keys(values).length) throw new ValidationError("Indique name o email");
  const user = await adapter.updateUser(userId, values);
  if (!user) throw new NotFoundError();
  return publicUser(user);
}

async function changePassword(adapter, userId, body) {
  requireMethods(adapter, "changePassword");
  bodyFields(body, ["currentPassword", "password"]);
  const currentPassword = passwordValue(body.currentPassword);
  const password = passwordValue(body.password);
  const user = await adapter.findUserById(userId);
  if (!user || user.active === false) throw new AuthError();
  const valid = typeof adapter.verifyPassword === "function"
    ? await adapter.verifyPassword(user, currentPassword)
    : user.password === currentPassword;
  if (!valid) throw new AuthError();
  if (!await adapter.changePassword(userId, user.password, password)) throw new AuthError();
}

function tokenHash(token) {
  return createHash("sha256").update(token).digest("hex");
}

/** Server-only: the caller must authorize recovery for the exact userId. */
async function createPasswordReset({ adapter, userId, resetUrl, expiresIn = 1800 } = {}) {
  requireMethods(adapter, "findUserById", "createPasswordReset");
  if (!Number.isSafeInteger(expiresIn) || expiresIn <= 0) throw new ValidationError("expiresIn debe ser segundos positivos");
  let url;
  try { url = new URL(resetUrl); } catch { throw new ValidationError("resetUrl debe ser una URL absoluta"); }
  if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) throw new ValidationError("resetUrl invalida");
  if (!await adapter.findUserById(userId)) throw new NotFoundError();
  const token = randomBytes(32).toString("base64url");
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
  if (!Number.isSafeInteger(expiresAt)) throw new ValidationError("expiresIn fuera de rango");
  await adapter.createPasswordReset({ id: tokenHash(token), userId, expiresAt });
  url.searchParams.set("token", token);
  return { url: url.href, expiresAt };
}

async function resetPassword(adapter, body) {
  requireMethods(adapter, "resetPassword");
  bodyFields(body, ["token", "password"]);
  const password = passwordValue(body.password);
  if (typeof body.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.token)) throw new TokenInvalidError();
  if (!await adapter.resetPassword(tokenHash(body.token), password, Math.floor(Date.now() / 1000))) throw new TokenInvalidError();
}

const basicRealm = "IAM";
const defaultExpiresIn = 365 * 24 * 60 * 60;

/**
 * Express authentication middleware with built-in /login, /session and /logout.
 *
 * @param {import("../types.js").ExpressAuthOptions} options
 * @returns {import("../types.js").ExpressMiddleware}
 */
function auth(options = {}) {
  const { adapter } = options;
  if (!adapter) throw new AdapterError();

  const jwt = resolveJwtConfig(options);
  const rbac = new RBAC({ adapter });
  const authCore = { adapter, rbac, getContext: options.getContext, logging: normalizeLogging(options.logging, options.getContext) };

  return async function iamAuth(req, res, next) {
    try {
      if (matches(req, "POST", "/register") && options.registration === true) {
        return sendData(res.status(201), await register(adapter, req.body));
      }
      if (matches(req, "POST", "/reset-password")) {
        await resetPassword(adapter, req.body);
        return sendData(res, {});
      }
      if (matches(req, "POST", "/login")) return handleLogin(req, res, next, { authCore, jwt, options });
      if (matches(req, "GET", "/session")) {
        const session = await authenticateRequest(req, { authCore, jwt, options });
        attach(req, { authCore, rbac, session });
        log(authCore.logging, "trace", "auth", "Sesión consultada", { sessionId: session.id, userId: session.user.id });
        return sendData(res, session);
      }
      if (matches(req, "POST", "/logout")) return await handleLogout(req, res, { authCore, jwt, options, rbac });
      const session = await authenticateRequest(req, { authCore, jwt, options });
      attach(req, { authCore, rbac, session });
      if (matches(req, "PATCH", "/me")) return sendData(res, await updateProfile(adapter, session.user.id, req.body));
      if (matches(req, "POST", "/me/password")) {
        await changePassword(adapter, session.user.id, req.body);
        return sendData(res, {});
      }
      log(authCore.logging, "trace", "auth", "Acceso autenticado", { method: req.method, path: req.path, userId: session.user.id });
      return next();
    } catch (error) {
      log(authCore.logging, "error", "auth", "Error de autenticación", { method: req.method, path: req.path, error: error.message, status: error.status ?? 500 });
      if (!(Number(error?.status ?? 500) < 500)) return next(error);
      return sendError$1(res, error, shouldChallenge(error, req));
    }
  };
}

async function handleLogin(req, res, next, { authCore, jwt, options }) {
  try {
    const credentials = credentialsFromBody(req) ?? credentialsFromBasicHeader(req, options);
    if (!credentials) throw new AuthRequiredError();

    const user = await validateCredentials(authCore.adapter, credentials.username, credentials.password);
    const session = await createSession(authCore.adapter, user.id, sessionOptions(user, credentials.options), options);
    const publicValue = await createPublicSession(authCore, session, user);
    const expiresIn = normalizeExpiresIn(jwt.expiresIn);
    const token = await signJwt({ sessionId: session.id }, jwt.secret, { expiresIn });
    if (session.id) await authCore.adapter.updateSession(session.id, { token });
    log(authCore.logging, "info", "auth", "Sesión iniciada", { sessionId: session.id, userId: user.id });

    return sendData(res, { ...publicValue, token, expiresIn });
  } catch (error) {
    log(authCore.logging, "error", "auth", "Error de inicio de sesión", { method: req.method, path: req.path, error: error.message, status: error.status ?? 500 });
    if (!shouldSendError(error)) return next(error);
    return sendLoginError(res, error);
  }
}

async function handleLogout(req, res, { authCore, jwt, options, rbac }) {
  if (!hasBearerToken(req)) throw new TokenRequiredError();

  const session = await authenticateRequest(req, { authCore, jwt, options });
  attach(req, { authCore, rbac, session });
  await authCore.adapter.deactivateSession(session.id);
  log(authCore.logging, "info", "auth", "Sesión cerrada", { sessionId: session.id, userId: session.user.id });
  return sendData(res, {});
}

async function authenticateRequest(req, { authCore, jwt, options }) {
  const header = req.headers?.authorization ?? "";
  const strategy = resolveStrategy(header, options);

  if (!strategy) throw new TokenRequiredError();
  if (strategy === "jwt") return authenticateJwt(header, authCore, jwt);
  return authenticateBasic(header, authCore, options);
}

async function authenticateJwt(header, authCore, jwt) {
  if (!jwt.secret) throw new ValidationError("Secret requerido para JWT");
  if (!header.startsWith("Bearer ")) throw new TokenRequiredError();

  const token = header.slice("Bearer ".length).trim();
  if (!token) throw new TokenRequiredError();

  const payload = await verifyJwt(token, jwt.secret);
  const sessionId = payload.sessionId ?? payload.id;
  if (!sessionId) throw new TokenInvalidError();

  return getActivePublicSession(authCore, sessionId);
}

async function authenticateBasic(header, authCore, options) {
  const credentials = credentialsFromBasicValue(header.slice("Basic ".length).trim());
  const user = await validateCredentials(authCore.adapter, credentials.username, credentials.password);
  const session = await createOrReuseSession(authCore.adapter, user.id, sessionOptions(user), options);
  return createPublicSession(authCore, session, user);
}

function resolveStrategy(header, options) {
  const allowed = options.strategies ?? (options.strategy ? [options.strategy] : ["jwt", "basic"]);

  if (options.strategy) {
    if (options.strategy === "jwt" && header.startsWith("Bearer ")) return "jwt";
    if (options.strategy === "basic" && header.startsWith("Basic ")) return "basic";
    return null;
  }

  if (header.startsWith("Bearer ") && allowed.includes("jwt")) return "jwt";
  if (header.startsWith("Basic ") && allowed.includes("basic")) return "basic";
  return null;
}

function credentialsFromBody(req) {
  const { username, password, options } = req.body ?? {};
  if (!username || password === undefined) return null;
  return { username, password, options };
}

function credentialsFromBasicHeader(req, options) {
  const header = req.headers?.authorization ?? "";
  if (!resolveStrategy(header, { ...options, strategy: "basic" })) return null;
  return credentialsFromBasicValue(header.slice("Basic ".length).trim());
}

function credentialsFromBasicValue(value) {
  if (!value) throw new AuthRequiredError();

  const decoded = Buffer.from(value, "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator === -1) throw new AuthError();

  return {
    username: decoded.slice(0, separator),
    password: decoded.slice(separator + 1)
  };
}

function sessionOptions(user, options = {}) {
  return { ...(user?.options || {}), ...(options || {}) };
}

async function validateCredentials(adapter, username, password) {
  if (!username || password === undefined) throw new AuthRequiredError();

  const user = await adapter.findUserByUsername(username);
  if (!user || user.active === false) throw new AuthError();

  if (typeof adapter.verifyPassword === "function") {
    const valid = await adapter.verifyPassword(user, password);
    if (!valid) throw new AuthError();
    return user;
  }

  if (user.password !== password) throw new AuthError();
  return user;
}

async function createOrReuseSession(adapter, userId, options, authOptions) {
  if (authOptions.createSession === false) return {id: null, userId, options, active: true};
  if (typeof adapter.findActiveSessionByUserId === "function") {
    const activeSession = await adapter.findActiveSessionByUserId(userId);
    if (activeSession) return activeSession;
  }
  const date = now();
  return adapter.createSession({id: createSessionId(), userId, token: null, options, active: true, createdAt: date, updatedAt: date});
}

async function createSession(adapter, userId, options, authOptions) {
  if (authOptions.createSession === false) return {id: null, userId, options, active: true};
  const date = now();
  return adapter.createSession({id: createSessionId(), userId, token: null, options, active: true, createdAt: date, updatedAt: date});
}

async function getActivePublicSession(authCore, sessionId) {
  if (!sessionId) throw new SessionRequiredError();
  const session = await authCore.adapter.findSessionById(sessionId);
  if (!session) throw new SessionRequiredError();
  if (session.active === false) throw new SessionInactiveError();
  const user = await authCore.adapter.findUserById(session.userId);
  if (!user || user.active === false) throw new AuthError();
  return createPublicSession(authCore, session, user);
}

async function createPublicSession(authCore, session, user) {
  const permissions = await authCore.rbac.getPermissions(user.id);
  return publicSession(session, user, {
    permissions: Array.from(new Set(
      permissions.filter((item) => item?.active !== false && item.permission).map((item) => item.permission)
    ))
  });
}

function attach(req, { authCore, rbac, session }) {
  req.session = session;
  setContext(req, { auth: authCore, adapter: authCore.adapter, rbac, session });
}

async function signJwt(payload, secret, options = {}) {
  if (!secret) throw new ValidationError("Secret requerido para JWT");

  const jwt = new SignJWT(payload).setProtectedHeader({ alg: "HS256", typ: "JWT" });
  const expiresIn = normalizeExpiresIn(options.expiresIn);

  if (expiresIn) {
    const issuedAt = Math.floor(Date.now() / 1000);
    jwt.setIssuedAt(issuedAt).setExpirationTime(issuedAt + expiresIn);
  }

  return jwt.sign(createSecretKey(secret));
}

/**
 * Verifies an HS256 JWT and returns its verified payload.
 *
 * @param {string} token
 * @param {string} secret
 * @returns {Promise<import("jose").JWTPayload>}
 */
async function verifyJwt(token, secret) {
  try {
    const { payload } = await jwtVerify(token, createSecretKey(secret), {algorithms: ["HS256"]});
    return payload;
  } catch {
    throw new TokenInvalidError();
  }
}

function resolveJwtConfig(options) {
  return {secret: options.jwt?.secret, expiresIn: options.jwt?.expiresIn};
}

function normalizeExpiresIn(expiresIn) {
  if (expiresIn === undefined || expiresIn === null) return defaultExpiresIn;

  if (typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0) return Math.floor(expiresIn);

  if (typeof expiresIn === "string") {
    const match = expiresIn.trim().match(/^(\d+)\s*([smhd])?$/i);
    if (!match) throw new ValidationError("expiresIn JWT invalido");

    const value = Number(match[1]);
    const unit = match[2]?.toLowerCase() ?? "s";
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
    return value * multipliers[unit];
  }

  throw new ValidationError("expiresIn JWT invalido");
}

function matches(req, method, path) {
  return req.method === method && getPath(req) === path;
}

function getPath(req) {
  return req.path ?? req.url?.split("?")[0] ?? "";
}

function createSecretKey(secret) {
  return new TextEncoder().encode(secret);
}

function shouldChallenge(error, req) {
  return [401, undefined].includes(error.status) && !hasBearerToken(req);
}

function hasBearerToken(req) {
  const header = req.headers?.authorization ?? "";
  if (!header.startsWith("Bearer ")) return false;
  return Boolean(header.slice("Bearer ".length).trim());
}

function sendError$1(res, error, challenge = false) {
  if (challenge && typeof res.setHeader === "function") {
    res.setHeader("WWW-Authenticate", `Basic realm="${basicRealm}"`);
  } else if (challenge && typeof res.set === "function") {
    res.set("WWW-Authenticate", `Basic realm="${basicRealm}"`);
  }

  const status = error.status ?? 500;
  const message = error.message ?? "Error";
  return res.status(status).json(errorResponse(error, message));
}

function sendLoginError(res, error, req) {
  const status = error.status ?? 500;
  const message = error.message ?? "Error";
  return res.status(status).json({...errorResponse(error, message)});
}

function sendData(res, data) {
  return res.json({ ok: true, data });
}

function errorResponse(error, message) {
  return {ok: false, message, stack: error.stack};
}

function shouldSendError(error) {
  return Number(error?.status ?? 500) < 500;
}

/**
 * Express authorization middleware for a single permission.
 *
 * @param {string} permission
 * @returns {import("../types.js").ExpressMiddleware}
 */
function can(permission) {
  async function iamCan(req, res, next) {
    try {
      if (!permission) throw new PermissionRequiredError();

      const context = getContext(req);
      const userId = req.session?.user?.id;
      if (!context || !userId) throw new SessionRequiredError();

      const allowed = await context.rbac.can(userId, permission);
      if (!allowed) {
        log(context.auth.logging, "info", "can", "Permiso denegado", { userId, permission });
        throw new ForbiddenError();
      }

      log(context.auth.logging, "trace", "can", "Permiso concedido", { userId, permission });

      return next();
    } catch (error) {
      const context = getContext(req);
      if (Number(error?.status ?? 500) >= 500) log(context?.auth?.logging, "error", "can", "Error de autorización", { userId: req.session?.user?.id, permission, error: error.message, status: error.status ?? 500 });
      if (!(Number(error?.status ?? 500) < 500)) return next(error);
      return sendError(res, error);
    }
  }

  iamCan.permission = permission;
  iamCan.permissions = [permission];
  iamCan.iam = { permission, permissions: [permission] };

  return iamCan;
}

function sendError(res, error) {
  const status = error.status ?? 500;
  const message = error.message ?? "Error";
  return res.status(status).json({ ok: false, message, stack: error.stack});
}

export { auth, can, createPasswordReset, verifyJwt };
