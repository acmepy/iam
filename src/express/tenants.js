import { AdapterError, NotFoundError, RbacError, SessionRequiredError, ValidationError } from "../core/errors.js";
import { publicUser } from "../core/utils.js";

export function requireTenant(enabled) {
  if (!enabled) throw new RbacError("El soporte de tenants no esta habilitado", 400, "TENANT_DISABLED");
}

export function setTenantContext(getContext, tenantId) {
  if (!getContext) return;
  const context = getContext();
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    throw new RbacError("No hay contexto de tenant para la peticion", 403, "TENANT_CONTEXT_MISSING");
  }
  context.tenantId = tenantId;
}

export async function assertTenantAccess(adapter, userId, tenantId) {
  if (tenantId === undefined || tenantId === null || tenantId === "") {
    throw new RbacError("La sesion o el usuario no tiene tenantId", 403, "TENANT_REQUIRED");
  }
  if (!(typeof tenantId === "string" && tenantId.trim() && tenantId.length <= 100)
      && !(typeof tenantId === "number" && Number.isSafeInteger(tenantId) && tenantId >= 0)) {
    throw new RbacError("tenantId invalido", 400, "TENANT_INVALID");
  }
  requireMethods(adapter, "findTenantById", "findTenantsByUserId");
  const tenant = await adapter.findTenantById(tenantId);
  if (!tenant || tenant.active === false || tenant.id !== tenantId) {
    throw new RbacError("El tenant no existe o esta inactivo", 403, "TENANT_UNAVAILABLE");
  }
  const allowed = await adapter.findTenantsByUserId(userId);
  if (!allowed.some(item => item.id === tenantId && item.active !== false)) {
    throw new RbacError("El usuario no tiene acceso al tenant solicitado", 403, "TENANT_FORBIDDEN");
  }
  return tenant;
}

export function requireMethods(adapter, ...methods) {
  for (const method of methods) {
    if (typeof adapter[method] !== "function") throw new AdapterError(`Adapter requiere ${method}`);
  }
}

function bodyFields(body, allowed) {
  if (!body || typeof body !== "object" || Array.isArray(body)
      || Object.keys(body).length !== 1 || !Object.hasOwn(body, allowed)) {
    throw new ValidationError(`Indique solamente ${allowed}`);
  }
}

function preferences(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ValidationError("options debe ser un objeto");
  const inspect = item => {
    if (!item || typeof item !== "object") return;
    for (const [key, nested] of Object.entries(item)) {
      if (["__proto__", "constructor", "prototype", "tenantId"].includes(key)) throw new ValidationError(`Opcion no permitida: ${key}`);
      inspect(nested);
    }
  };
  inspect(value);
  return value;
}

/** Only edits the authenticated user's defaults or the current persisted session. */
export async function updateOwnSettings(adapter, session, body, { tenant, scope, field }) {
  bodyFields(body, field);
  if (field === "tenantId") {
    requireTenant(tenant);
    await assertTenantAccess(adapter, session.user.id, body.tenantId);
  } else {
    preferences(body.options);
  }
  const method = scope === "user" ? "updateUser" : "updateSession";
  requireMethods(adapter, method);
  if (scope === "session" && !session.id) throw new SessionRequiredError("El cambio requiere una sesion persistida");
  const current = scope === "user" ? await adapter.findUserById(session.user.id) : await adapter.findSessionById(session.id);
  if (!current) throw new NotFoundError();
  const values = field === "options" ? { options: { ...current.options, ...body.options } } : { tenantId: body.tenantId };
  const updated = await adapter[method](current.id, values);
  if (!updated) throw new NotFoundError();
  return scope === "user" ? publicUser(updated) : updated;
}
