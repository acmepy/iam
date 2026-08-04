import type { PermissionData } from "../types.js";

export interface PermissionFilterOptions {
  includePublic?: boolean;
  requireAll?: boolean;
}

export function filterOpenApiByPermissions<T>(
  document: T,
  permissions?: Array<string | PermissionData>,
  options?: PermissionFilterOptions
): T;

export const filterOpenAPIByPermissions: typeof filterOpenApiByPermissions;
export const filterOpenapiByPermissions: typeof filterOpenApiByPermissions;

export function filterPostmanByPermissions<T>(
  collection: T,
  permissions?: Array<string | PermissionData>,
  options?: PermissionFilterOptions
): T;
