import { SignJWT, jwtVerify } from "jose";
import { RBAC } from "../core/RBAC.js";
import {
  AdapterError,
  AuthError,
  AuthRequiredError,
  SessionInactiveError,
  SessionRequiredError,
  TokenInvalidError,
  TokenRequiredError,
  ValidationError
} from "../core/errors.js";
import { createSessionId, now, publicSession } from "../core/utils.js";
import { setContext } from "./context.js";

const basicRealm = "IAM";

/**
 * Express authentication middleware with built-in /login, /session and /logout.
 *
 * @param {import("../types.js").ExpressAuthOptions} options
 * @returns {import("../types.js").ExpressMiddleware}
 */
export function auth(options = {}) {
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
      return sendError(res, error, shouldChallenge(error));
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
    return sendLoginError(res, error, req);
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

function shouldChallenge(error) {
  return [401, undefined].includes(error.status);
}

function sendError(res, error, challenge = false) {
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

function loginErrorDetails(error, req) {
  if (error.code === "AUTH_REQUIRED") return missingCredentialDetails(req);
  if (error.code === "AUTH_ERROR") return {credentials: "Usuario o clave invalidos"};
  return error.errors ?? {};
}

function missingCredentialDetails(req) {
  const body = req.body ?? {};
  const details = {};

  if (!body.username) details.username = "Usuario requerido";
  if (body.password === undefined) details.password = "Clave requerida";

  return Object.keys(details).length ? details : {credentials: "Usuario y clave requeridos"};
}
