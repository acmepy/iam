import { AuthError, AuthRequiredError, SessionInactiveError, SessionRequiredError } from "./errors.js";
import { createSessionId, now, publicSession } from "./utils.js";
import { assertTenantAccess, setTenantContext } from "./tenants.js";

export function sessionOptions(user, options = {}) {
  return { ...(user?.options || {}), ...(options || {}) };
}

export async function validateCredentials(adapter, username, password) {
  if (!username || password === undefined) throw new AuthRequiredError();

  const user = await adapter.findUserByUsername(username);
  if (!user || user.active === false) throw new AuthError();

  if (typeof adapter.verifyPassword === "function") {
    const valid = await adapter.verifyPassword(user, password);
    if (!valid) throw new AuthError();
    return user;
  }

  if (user.password !== password) throw new AuthError();
  return user;
}

export async function createOrReuseSession(adapter, user, options, authOptions) {
  const userId = user.id;
  if (authOptions.createSession === false) return {id: null, userId, options, active: true};
  if (typeof adapter.findActiveSessionByUserId === "function") {
    const activeSession = await adapter.findActiveSessionByUserId(userId);
    if (activeSession) return activeSession;
  }
  return createSession(adapter, user, options, authOptions);
}

export async function createSession(adapter, user, options, authOptions) {
  const userId = user.id;
  if (authOptions.tenant) {
    await assertTenantAccess(adapter, userId, user.tenantId);
    setTenantContext(authOptions.getContext, user.tenantId);
  }
  if (authOptions.createSession === false) return {id: null, userId, options, active: true};
  const date = now();
  return adapter.createSession({id: createSessionId(), userId, ...(authOptions.tenant && { tenantId: user.tenantId }), token: null, options, active: true, createdAt: date, updatedAt: date});
}

export async function getActivePublicSession(authCore, sessionId) {
  if (!sessionId) throw new SessionRequiredError();
  const session = await authCore.adapter.findSessionById(sessionId);
  if (!session) throw new SessionRequiredError();
  if (session.active === false) throw new SessionInactiveError();
  const user = await authCore.adapter.findUserById(session.userId);
  if (!user || user.active === false) throw new AuthError();
  return createPublicSession(authCore, session, user);
}

export async function createPublicSession(authCore, session, user) {
  if (authCore.tenant) await assertTenantAccess(authCore.adapter, user.id, session.tenantId);
  const permissions = await authCore.rbac.getPermissions(user.id);
  return publicSession(session, user, {
    permissions: Array.from(new Set(
      permissions.filter((item) => item?.active !== false && item.permission).map((item) => item.permission)
    ))
  });
}

