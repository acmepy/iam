import type {
  Adapter,
  Dict,
  ExpressAuthOptions,
  ExpressMiddleware,
  Id,
  PublicSession,
  SessionData,
  UserData
} from "../types.js";

export type { AuthStrategy, ExpressAuthOptions, ExpressMiddleware } from "../types.js";

export class Auth {
  constructor(options?: { adapter?: Adapter; rbac?: unknown });
  adapter: Adapter;
  rbac?: unknown;
  login(credentials?: {
    username?: string;
    password?: string;
    options?: Dict;
  }): Promise<PublicSession>;
  logout(sessionId: Id): Promise<SessionData | null>;
  getSession(sessionId: Id): Promise<PublicSession>;
  validateUser(user: UserData | null): Promise<void>;
  validatePassword(user: UserData, password: string): Promise<void>;
  createSession(values?: {
    userId?: Id;
    token?: string | null;
    options?: Dict;
  }): Promise<SessionData>;
  createTemporarySession(user: UserData, options?: Dict): Promise<PublicSession>;
}

export function createAuth(adapter: Adapter): Auth;
export function auth(options?: ExpressAuthOptions): ExpressMiddleware;
export function can(permission: string): ExpressMiddleware;
export function signJwt(payload: Dict, secret: string): Promise<string>;
export function verifyJwt(token: string, secret: string): Promise<Dict>;
