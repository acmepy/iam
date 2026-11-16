import { signJwt, verifyJwt, normalizeExpiresIn } from "../core/jwt.js";
export { verifyJwt } from "../core/jwt.js";
import { sessionOptions, validateCredentials, createOrReuseSession, createSession, getActivePublicSession, createPublicSession } from "../core/sessions.js";
import { RBAC } from "../core/RBAC.js";
import {
  AdapterError,
  AuthError,
  AuthRequiredError,
  TokenInvalidError,
  TokenRequiredError,
  ValidationError
} from "../core/errors.js";
import { setContext } from "./context.js";
import { log, normalizeLogging } from "../core/logging.js";
import { register, updateProfile, changePassword, resetPassword } from "../core/accounts.js";

import { requireTenant, requireMethods, setTenantContext, updateOwnSettings } from "../core/tenants.js";

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

  if (options.tenant !== undefined && typeof options.tenant !== "boolean") throw new ValidationError("tenant debe ser booleano");
  if (options.tenant && options.createSession === false) throw new ValidationError("tenant requiere sesiones persistidas");
  if (options.tenant) requireMethods(adapter, "findTenantById", "findTenantsByUserId");
  const jwt = resolveJwtConfig(options);
  const rbac = new RBAC({ adapter });
  const authCore = { adapter, rbac, tenant: options.tenant === true, getContext: options.getContext, logging: normalizeLogging(options.logging, options.getContext) };

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
      if (matches(req, "GET", "/me/tenants")) {
        requireTenant(authCore.tenant);
        const tenants = await adapter.findTenantsByUserId(session.user.id);
        return sendData(res, tenants.map(({ id, name }) => ({ id, name })));
      }
      for (const [path, scope, field] of [["/me/options", "user", "options"], ["/session/options", "session", "options"],
        ["/me/tenant", "user", "tenantId"], ["/session/tenant", "session", "tenantId"]]) {
        if (!matches(req, "PATCH", path)) continue;
        const updated = await updateOwnSettings(adapter, session, req.body, { tenant: authCore.tenant, scope, field });
        if (scope === "user") return sendData(res, updated);
        const nextSession = await createPublicSession(authCore, updated, session.user);
        attach(req, { authCore, rbac, session: nextSession });
        return sendData(res, nextSession);
      }
      if (matches(req, "PATCH", "/me")) return sendData(res, await updateProfile(adapter, session.user.id, req.body));
      if (matches(req, "POST", "/me/password")) {
        await changePassword(adapter, session.user.id, req.body);
        return sendData(res, {});
      }
      log(authCore.logging, "trace", "auth", "Acceso autenticado", { method: req.method, path: req.baseUrl, userId: session.user.id });
      return next();
    } catch (error) {
      log(authCore.logging, "error", "auth", "Error de autenticación", { method: req.method, path: req.baseUrl, error: error.message, status: error.status ?? 500 });
      if (!(Number(error?.status ?? 500) < 500)) return next(error);
      return sendError(res, error, shouldChallenge(error, req));
    }
  };
}

async function handleLogin(req, res, next, { authCore, jwt, options }) {
  try {
    const credentials = credentialsFromBody(req) ?? credentialsFromBasicHeader(req, options);
    if (!credentials) throw new AuthRequiredError();

    const user = await validateCredentials(authCore.adapter, credentials.username, credentials.password);
    const session = await createSession(authCore.adapter, user, sessionOptions(user, credentials.options), options);
    const publicValue = await createPublicSession(authCore, session, user);
    const expiresIn = normalizeExpiresIn(jwt.expiresIn);
    const token = await signJwt({ sessionId: session.id }, jwt.secret, { expiresIn });
    if (session.id) await authCore.adapter.updateSession(session.id, { token });
    log(authCore.logging, "info", "auth", "Sesión iniciada", { sessionId: session.id, userId: user.id });

    return sendData(res, { ...publicValue, token, expiresIn });
  } catch (error) {
    log(authCore.logging, "error", "auth", "Error de inicio de sesión", { method: req.method, path: req.baseUrl, error: error.message, status: error.status ?? 500 });
    if (!shouldSendError(error)) return next(error);
    return sendLoginError(res, error, req);
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
  const session = await createOrReuseSession(authCore.adapter, user, sessionOptions(user), options);
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

function attach(req, { authCore, rbac, session }) {
  req.session = session;
  if (authCore.tenant) setTenantContext(authCore.getContext, session.tenantId);
  setContext(req, { auth: authCore, adapter: authCore.adapter, rbac, session });
}

function resolveJwtConfig(options) {
  return {secret: options.jwt?.secret, expiresIn: options.jwt?.expiresIn};
}

function matches(req, method, path) {
  return req.method === method && getPath(req) === path;
}

function getPath(req) {
  return req.path ?? req.url?.split("?")[0] ?? "";
}

function shouldChallenge(error, req) {
  return [401, undefined].includes(error.status) && !hasBearerToken(req);
}

function hasBearerToken(req) {
  const header = req.headers?.authorization ?? "";
  if (!header.startsWith("Bearer ")) return false;
  return Boolean(header.slice("Bearer ".length).trim());
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
  return {ok: false, code: error.code, message, stack: error.stack};
}

function shouldSendError(error) {
  return Number(error?.status ?? 500) < 500;
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
