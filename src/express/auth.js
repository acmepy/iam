import { RBAC } from "../core/RBAC.js";
import {
  AdapterError,
  AuthError,
  TokenRequiredError,
  TokenInvalidError,
  ValidationError
} from "../core/errors.js";
import { publicUser } from "../core/utils.js";
import { Auth } from "./AuthService.js";
import { setContext } from "./context.js";
import { verifyJwt } from "./jwt.js";

export function auth(options = {}) {
  const { adapter, secret } = options;

  if (!adapter) {
    throw new AdapterError();
  }

  const rbac = new RBAC({ adapter });
  const authCore = new Auth({ adapter, rbac });

  return async function rbacAuth(req, res, next) {
    try {
      const header = req.headers?.authorization ?? "";
      const strategy = resolveStrategy(header, options);

      if (!strategy) {
        throw new TokenRequiredError();
      }

      const session = strategy === "jwt"
        ? await authenticateJwt({ header, secret, authCore })
        : await authenticateBasic({ header, authCore, adapter, createSession: options.createSession });

      req.session = session;
      setContext(req, {
        adapter,
        auth: authCore,
        rbac,
        session
      });

      return next();
    } catch (error) {
      return sendError(res, error);
    }
  };
}

function resolveStrategy(header, options) {
  const allowed = options.strategies ?? (options.strategy ? [options.strategy] : ["jwt", "basic"]);

  if (options.strategy) {
    return options.strategy;
  }

  if (header.startsWith("Bearer ") && allowed.includes("jwt")) {
    return "jwt";
  }

  if (header.startsWith("Basic ") && allowed.includes("basic")) {
    return "basic";
  }

  return null;
}

async function authenticateJwt({ header, secret, authCore }) {
  if (!secret) {
    throw new ValidationError("Secret requerido para JWT");
  }

  if (!header.startsWith("Bearer ")) {
    throw new TokenRequiredError();
  }

  const token = header.slice("Bearer ".length).trim();
  if (!token) {
    throw new TokenRequiredError();
  }

  const payload = await verifyJwt(token, secret);
  const sessionId = payload.sessionId ?? payload.id;

  if (!sessionId) {
    throw new TokenInvalidError();
  }

  return authCore.getSession(sessionId);
}

async function authenticateBasic({ header, authCore, adapter, createSession = true }) {
  const value = header.slice("Basic ".length).trim();
  const decoded = Buffer.from(value, "base64").toString("utf8");
  const separator = decoded.indexOf(":");

  if (separator === -1) {
    throw new AuthError();
  }

  const username = decoded.slice(0, separator);
  const password = decoded.slice(separator + 1);
  const user = await adapter.findUserByUsername(username);

  await authCore.validateUser(user);
  await authCore.validatePassword(user, password);

  if (createSession !== false) {
    const activeSession = await getExistingSession(adapter, user.id);

    if (activeSession) {
      return authCore.getSession(activeSession.id);
    }

    return authCore.login({ username, password, options: {} });
  }

  return {
    id: null,
    user: publicUser(user),
    options: {}
  };
}

async function getExistingSession(adapter, userId) {
  if (typeof adapter.findActiveSessionByUserId !== "function") {
    return null;
  }

  return adapter.findActiveSessionByUserId(userId);
}

function sendError(res, error) {
  const status = error.status ?? 500;
  const code = error.code ?? "RBAC_ERROR";
  const message = error.message ?? "Error";

  return res.status(status).json({ error: message, code });
}
