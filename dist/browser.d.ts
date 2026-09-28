import type { BrowserAuthOptions, BrowserCredentials, PublicSession, PublicUser } from "./types.js";

export type { BrowserAuthOptions, BrowserCredentials } from "./types.js";

export const auth: {
  configure(options?: BrowserAuthOptions): typeof auth;
  login(credentials?: BrowserCredentials): Promise<PublicSession>;
  register(values: { name: string; email: string; password: string }): Promise<PublicUser>;
  updateProfile(values: { name?: string; email?: string }): Promise<PublicUser>;
  changePassword(currentPassword: string, password: string): Promise<void>;
  resetPassword(token: string, password: string): Promise<void>;
  logout(): Promise<void>;
  getSession(): PublicSession | null;
};

export function can(permission: string): Promise<boolean>;
