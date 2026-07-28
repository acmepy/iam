import type {
  AuthStrategy,
  ExpressAuthOptions,
  ExpressMiddleware
} from "../types.js";

export type { AuthStrategy, ExpressAuthOptions, ExpressMiddleware } from "../types.js";

export function auth(options: ExpressAuthOptions): ExpressMiddleware;
export function can(permission: string): ExpressMiddleware;
