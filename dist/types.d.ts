export type Id = string | number;

export type Dict = Record<string, unknown>;

export interface KeyValueStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export type ExpressMiddleware = (
  req: any,
  res: any,
  next: (error?: unknown) => void
) => unknown;

export type AuthStrategy = "jwt" | "basic";

export type Logging = boolean | {
  info?: ((...args: unknown[]) => void) | false;
  trace?: ((...args: unknown[]) => void) | false;
  warn?: ((...args: unknown[]) => void) | false;
  error?: ((...args: unknown[]) => void) | false;
};

export interface ExpressAuthOptions {
  adapter: Adapter;
  registration?: boolean;
  jwt?: {
    secret: string;
    expiresIn?: number | string;
  };
  strategy?: AuthStrategy;
  strategies?: AuthStrategy[];
  createSession?: boolean;
  logging?: Logging;
}

export interface BrowserAuthOptions {
  baseUrl?: string;
  storageKey?: string;
  storage?: KeyValueStorage | null;
}

export interface BrowserCredentials {
  username?: string;
  password?: string;
  token?: string;
  options?: Dict;
}

export interface UserData {
  id: Id;
  password?: string;
  name?: string;
  email?: string;
  options?: Dict;
  active?: boolean;
  [key: string]: unknown;
}

export interface RoleData {
  id: Id;
  role: string;
  active?: boolean;
  [key: string]: unknown;
}

export interface PermissionData {
  id: Id;
  permission: string;
  active?: boolean;
  [key: string]: unknown;
}

export interface UserRoleData {
  id?: Id;
  userId: Id;
  roleId: Id;
  active?: boolean;
  [key: string]: unknown;
}

export interface RolePermissionData {
  id?: Id;
  roleId: Id;
  permissionId: Id;
  active?: boolean;
  [key: string]: unknown;
}

export interface SessionData {
  id: Id | null;
  userId: Id;
  token?: string | null;
  options?: Dict;
  active?: boolean;
  createdAt?: Date | string;
  updatedAt?: Date | string;
  [key: string]: unknown;
}

export interface PublicUser {
  id: Id;
  name?: string;
  email?: string;
  options?: Dict;
  [key: string]: unknown;
}

export interface PublicSession {
  id: Id | null;
  user: PublicUser;
  token?: string | null;
  options?: Dict;
  permissions?: string[];
  [key: string]: unknown;
}

export interface Adapter {
  createUser?(user: UserData): Promise<UserData>;
  updateUser?(id: Id, values: Partial<Pick<UserData, "name" | "email">>): Promise<UserData | null>;
  createPasswordReset?(reset: PasswordResetData): Promise<void>;
  changePassword?(userId: Id, expectedPassword: string | undefined, password: string): Promise<boolean>;
  resetPassword?(id: string, password: string, timestamp: number): Promise<boolean>;
  findUserByUsername(username: string): Promise<UserData | null>;
  findUserById(id: Id): Promise<UserData | null>;
  verifyPassword?(user: UserData, password: string): Promise<boolean> | boolean;
  createSession(session: SessionData): Promise<SessionData>;
  findSessionById(id: Id): Promise<SessionData | null>;
  findSessionByToken?(token: string): Promise<SessionData | null>;
  findActiveSessionByUserId?(userId: Id): Promise<SessionData | null>;
  deactivateSession(id: Id): Promise<SessionData | null>;
  updateSession?(id: Id, values: Partial<SessionData>): Promise<SessionData | null>;
  findRolesByUserId(userId: Id): Promise<RoleData[]>;
  findPermissionsByUserId(userId: Id, permission?: string): Promise<PermissionData[]>;
}

export interface AdapterData {
  passwordResets?: PasswordResetData[];
  users?: UserData[];
  roles?: RoleData[];
  permissions?: PermissionData[];
  usersRoles?: UserRoleData[];
  rolesPermissions?: RolePermissionData[];
  sessions?: SessionData[];
}

export interface AuditChange {
  module: string;
  resource: string;
  tableName: string;
  action: string;
  rowId?: Id | null;
  old?: Dict;
  new?: Dict;
}

export interface PasswordResetData {
  id: string;
  userId: Id;
  expiresAt: number;
}

export type Auditable =
  | ((change: AuditChange) => unknown | Promise<unknown>)
  | {
      tableName?: string;
      write?: (change: AuditChange) => unknown | Promise<unknown>;
      onChange?: (change: AuditChange) => unknown | Promise<unknown>;
    };
