const httpMethods = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);
const permissionKeys = ["x-permissions", "x-permission", "x-iam-permissions", "x-iam-permission", "permissions", "permission"];

/**
 * Return a copy of an OpenAPI document with operations filtered by permissions.
 *
 * Operations can declare permissions with x-permission, x-permissions,
 * x-iam-permission or x-iam-permissions. Path-level permissions are inherited.
 *
 * @param {object} document
 * @param {string[] | import("../types.js").PermissionData[]} permissions
 * @param {{ includePublic?: boolean, requireAll?: boolean }} [options]
 * @returns {object}
 */
function filterOpenApiByPermissions(document, permissions = [], options = {}) {
  const granted = permissionSet(permissions);
  const includePublic = options.includePublic !== false;
  const requireAll = options.requireAll !== false;
  const next = clone(document);

  if (!next?.paths || typeof next.paths !== "object") return next;

  for (const [path, pathItem] of Object.entries(next.paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;

    const pathPermissions = readPermissions(pathItem);

    for (const [method, operation] of Object.entries(pathItem)) {
      if (!httpMethods.has(method.toLowerCase()) || !operation || typeof operation !== "object") continue;

      const required = mergePermissions(pathPermissions, readPermissions(operation));
      if (!isAllowed(required, granted, { includePublic, requireAll })) {
        delete pathItem[method];
      }
    }

    if (!Object.keys(pathItem).some((key) => httpMethods.has(key.toLowerCase()))) {
      delete next.paths[path];
    }
  }

  return next;
}

const filterOpenAPIByPermissions = filterOpenApiByPermissions;
const filterOpenapiByPermissions = filterOpenApiByPermissions;

/**
 * Return a copy of a Postman collection with items filtered by permissions.
 *
 * Items or requests can declare permissions with x-permission, x-permissions,
 * x-iam-permission or x-iam-permissions. Folder permissions are inherited.
 *
 * @param {object} collection
 * @param {string[] | import("../types.js").PermissionData[]} permissions
 * @param {{ includePublic?: boolean, requireAll?: boolean }} [options]
 * @returns {object}
 */
function filterPostmanByPermissions(collection, permissions = [], options = {}) {
  const granted = permissionSet(permissions);
  const includePublic = options.includePublic !== false;
  const requireAll = options.requireAll !== false;
  const next = clone(collection);

  if (!Array.isArray(next?.item)) return next;

  next.item = filterPostmanItems(next.item, [], granted, { includePublic, requireAll });
  return next;
}

function filterPostmanItems(items, inherited, granted, options) {
  return items.flatMap((item) => {
    if (!item || typeof item !== "object") return [];

    const itemPermissions = mergePermissions(inherited, readPermissions(item), readPermissions(item.request));

    if (Array.isArray(item.item)) {
      item.item = filterPostmanItems(item.item, itemPermissions, granted, options);
      return item.item.length || isAllowed(itemPermissions, granted, options) ? [item] : [];
    }

    return isAllowed(itemPermissions, granted, options) ? [item] : [];
  });
}

function isAllowed(required, granted, { includePublic, requireAll }) {
  if (!required.length) return includePublic;
  if (requireAll) return required.every((permission) => granted.has(permission));
  return required.some((permission) => granted.has(permission));
}

function readPermissions(source) {
  if (!source || typeof source !== "object") return [];

  for (const key of permissionKeys) {
    if (source[key] !== undefined) return normalizePermissions(source[key]);
  }

  return [];
}

function normalizePermissions(value) {
  if (typeof value === "string") return value ? [value] : [];
  if (Array.isArray(value)) {
    return Array.from(new Set(value.flatMap((item) => normalizePermissions(item))));
  }
  if (value && typeof value === "object" && typeof value.permission === "string") {
    return [value.permission];
  }
  return [];
}

function permissionSet(permissions) {
  return new Set(normalizePermissions(permissions));
}

function mergePermissions(...groups) {
  return Array.from(new Set(groups.flat()));
}

function clone(value) {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

export { filterOpenAPIByPermissions, filterOpenApiByPermissions, filterOpenapiByPermissions, filterPostmanByPermissions };
