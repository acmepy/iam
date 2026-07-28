import {
  ForbiddenError,
  PermissionRequiredError,
  SessionRequiredError
} from "../core/errors.js";
import { getContext } from "./context.js";

/**
 * Express authorization middleware for a single permission.
 *
 * @param {string} permission
 * @returns {import("../types.js").ExpressMiddleware}
 */
export function can(permission) {
  return async function iamCan(req, res, next) {
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
  };
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
