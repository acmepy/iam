import {
  ForbiddenError,
  PermissionRequiredError,
  SessionRequiredError
} from "../core/errors.js";
import { getContext } from "./context.js";
import { log } from "./logging.js";

/**
 * Express authorization middleware for a single permission.
 *
 * @param {string} permission
 * @returns {import("../types.js").ExpressMiddleware}
 */
export function can(permission) {
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
