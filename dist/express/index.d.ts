import type {
  AuthStrategy,
  ExpressAuthOptions,
  ExpressMiddleware
} from "../types.js";

export type { AuthStrategy, ExpressAuthOptions, ExpressMiddleware } from "../types.js";

export type PermissionMiddleware = ExpressMiddleware & {
  permission: string;
  permissions: string[];
  iam: {
    permission: string;
    permissions: string[];
  };
};

export function auth(options: ExpressAuthOptions): ExpressMiddleware;
export function can(permission: string): PermissionMiddleware;
