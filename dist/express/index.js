import { SignJWT, jwtVerify } from 'jose';

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

const basicRealm = "IAM";

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
  const authCore = { adapter, rbac };

  return async function iamAuth(req, res, next) {
    try {
      if (matches(req, "POST", "/login")) {
        return handleLogin(req, res, { authCore, jwt, options });
      }

      if (matches(req, "GET", "/session")) {
        const session = await authenticateRequest(req, { authCore, jwt, options });
        attach(req, { authCore, rbac, session });
        return sendData(res, session);
      }

      if (matches(req, "POST", "/logout")) {
        return handleLogout(req, res, { authCore, jwt, options, rbac });
      }

      const session = await authenticateRequest(req, { authCore, jwt, options });
      attach(req, { authCore, rbac, session });
      return next();
    } catch (error) {
      return sendError$1(res, error, shouldChallenge(error, req));
    }
  };
}

async function handleLogin(req, res, { authCore, jwt, options }) {
  try {
    const credentials = credentialsFromBody(req) ?? credentialsFromBasicHeader(req, options);
    if (!credentials) throw new AuthRequiredError();

    const user = await validateCredentials(authCore.adapter, credentials.username, credentials.password);
    const session = await createSession(authCore.adapter, user.id, credentials.options ?? {}, options);
    const publicValue = await createPublicSession(authCore, session, user);
    const expiresIn = normalizeExpiresIn(jwt.expiresIn);
    const token = await signJwt({ sessionId: session.id }, jwt.secret, { expiresIn });

    return sendData(res, { ...publicValue, token, expiresIn });
  } catch (error) {
    return sendLoginError(res, error);
  }
}

async function handleLogout(req, res, { authCore, jwt, options, rbac }) {
  const sessionId = req.body?.sessionId;

  if (sessionId) {
    await authCore.adapter.deactivateSession(sessionId);
    return sendData(res, {});
  }

  const session = await authenticateRequest(req, { authCore, jwt, options });
  attach(req, { authCore, rbac, session });
  await authCore.adapter.deactivateSession(session.id);
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
  const session = await createOrReuseSession(authCore.adapter, user.id, {}, options);
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
      permissions
        .filter((item) => item?.active !== false && item.permission)
        .map((item) => item.permission)
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
  if (expiresIn === undefined || expiresIn === null) return undefined;

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
      if (!allowed) throw new ForbiddenError();

      return next();
    } catch (error) {
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
  return res.status(status).json({
    ok: false,
    message,
    stack: error.stack
  });
}

export { auth, can };
