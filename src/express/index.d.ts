import type {
  AuthStrategy,
  ExpressAuthOptions,
  ExpressMiddleware
} from "../types.js";
import type { JWTPayload } from "jose";
import type { Adapter, Id } from "../types.js";

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
export function verifyJwt(token: string, secret: string): Promise<JWTPayload>;
export function can(permission: string): PermissionMiddleware;
/** Server-only; caller must authorize recovery for userId. expiresIn is seconds. */
export function createPasswordReset(options: {
  adapter: Adapter;
  userId: Id;
  resetUrl: string;
  expiresIn?: number;
}): Promise<{ url: string; expiresAt: number }>;
