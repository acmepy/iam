import {
  ForbiddenError,
  PermissionRequiredError,
  SessionRequiredError
} from "../core/errors.js";
import { getContext } from "./context.js";

export function can(permission) {
  return async function rbacCan(req, res, next) {
    try {
      if (!permission) {
        throw new PermissionRequiredError();
      }

      const context = getContext(req);
      const userId = req.session?.user?.id;

      if (!context || !userId) {
        throw new SessionRequiredError();
      }

      const allowed = await context.rbac.can(userId, permission);

      if (!allowed) {
        throw new ForbiddenError();
      }

      return next();
    } catch (error) {
      return res.status(error.status ?? 500).json({
        error: error.message ?? "Error",
        code: error.code ?? "RBAC_ERROR"
      });
    }
  };
}
