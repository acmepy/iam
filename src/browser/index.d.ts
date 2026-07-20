import type { BrowserAuthOptions, BrowserCredentials, PublicSession } from "../types.js";

export type { BrowserAuthOptions, BrowserCredentials } from "../types.js";

export const auth: {
  configure(options?: BrowserAuthOptions): typeof auth;
  login(credentials?: BrowserCredentials): Promise<PublicSession>;
  logout(): Promise<void>;
  getSession(): PublicSession | null;
};

export function can(permission: string): Promise<boolean>;
