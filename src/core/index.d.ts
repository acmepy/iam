export type {
  Adapter,
  AdapterData,
  Dict,
  Id,
  PermissionData,
  PublicSession,
  PublicUser,
  RoleData,
  RolePermissionData,
  SessionData,
  UserData,
  UserRoleData
} from "../types.js";

import type {
  Adapter,
  Id,
  PermissionData,
  RoleData
} from "../types.js";

export class RBAC {
  constructor(options?: { adapter?: Adapter });
  adapter: Adapter;
  getRoles(userId: Id): Promise<RoleData[]>;
  getPermissions(userId: Id): Promise<PermissionData[]>;
  hasRole(userId: Id, role: string): Promise<boolean>;
  can(userId: Id, permission: string): Promise<boolean>;
}

export class Session {
  constructor(values?: Record<string, unknown>);
  [key: string]: unknown;
}

export class User {
  constructor(values?: Record<string, unknown>);
  [key: string]: unknown;
}

export class Role {
  constructor(values?: Record<string, unknown>);
  [key: string]: unknown;
}

export class Permission {
  constructor(values?: Record<string, unknown>);
  [key: string]: unknown;
}

export class UserRole {
  constructor(values?: Record<string, unknown>);
  [key: string]: unknown;
}

export class RolePermission {
  constructor(values?: Record<string, unknown>);
  [key: string]: unknown;
}

export class RbacError extends Error {
  constructor(
    message?: string,
    status?: number,
    code?: string,
    errors?: Record<string, unknown>,
    stack?: string
  );
  status: number;
  code: string;
  errors: Record<string, unknown>;
  isOperational: boolean;
}

export class AuthRequiredError extends RbacError {}
export class AuthError extends RbacError {}
export class TokenRequiredError extends RbacError {}
export class TokenInvalidError extends RbacError {}
export class SessionRequiredError extends RbacError {}
export class SessionInactiveError extends RbacError {}
export class PermissionRequiredError extends RbacError {}
export class ForbiddenError extends RbacError {}
export class NotFoundError extends RbacError {}
export class AdapterError extends RbacError {}
export class ValidationError extends RbacError {}
