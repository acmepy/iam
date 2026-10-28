import { now } from "../core/utils.js";

const collections = ["users", "roles", "permissions", "usersRoles", "rolesPermissions", "sessions", "passwordResets", "tenants", "usersTenants"];

/**
 * In-memory IAM adapter, useful for tests, demos, and small embedded setups.
 */
export class MemoryAdapter {
  /**
   * @param {import("../types.js").AdapterData} data
   */
  constructor(data = {}) {
    for (const name of collections) this[name] = [...(data[name] ?? [])];
  }

  async findTenantById(id) {
    return this.tenants.find(tenant => tenant.id === id) ?? null;
  }

  async findTenantsByUserId(userId) {
    const ids = new Set(this.usersTenants.filter(item => item.userId === userId && item.active !== false).map(item => item.tenantId));
    return this.tenants.filter(item => ids.has(item.id) && item.active !== false);
  }

  async findUserByUsername(username) {
    return this.users.find((user) => {return user.id === username || user.email === username || user.name === username}) ?? null;
  }

  async findUserById(id) {
    return this.users.find((user) => user.id === id) ?? null;
  }

  async verifyPassword(user, password) {
    return user.password === password;
  }

  async createUser(user) {
    if (this.users.some(item => item.id === user.id)) throw new Error("User id duplicado");
    this.users.push({ ...user });
    return { ...user };
  }

  async updateUser(id, values) {
    const user = this.users.find(item => item.id === id);
    if (!user) return null;
    Object.assign(user, values, { updatedAt: now() });
    return { ...user };
  }

  async createPasswordReset(reset) {
    this.passwordResets.push({ ...reset });
  }

  async changePassword(userId, expectedPassword, password) {
    const user = this.users.find(item => item.id === userId);
    if (!user || user.password !== expectedPassword) return false;
    this.replacePassword(user, password);
    return true;
  }

  async resetPassword(id, password, timestamp) {
    const reset = this.passwordResets.find(item => item.id === id && item.expiresAt > timestamp);
    const user = reset && this.users.find(item => item.id === reset.userId);
    if (!user) return false;
    this.replacePassword(user, password);
    return true;
  }

  replacePassword(user, password) {
    user.password = password;
    user.updatedAt = now();
    this.passwordResets = this.passwordResets.filter(item => item.userId !== user.id);
    for (const session of this.sessions) {
      if (session.userId === user.id) Object.assign(session, { active: false, updatedAt: now() });
    }
  }

  async createSession(session) {
    this.sessions.push(session);
    return session;
  }

  async findSessionById(id) {
    return this.sessions.find((session) => session.id === id) ?? null;
  }

  async findSessionByToken(token) {
    return this.sessions.find((session) => session.token === token) ?? null;
  }

  async findActiveSessionByUserId(userId) {
    return this.sessions.find((session) => {return session.userId === userId && session.active !== false}) ?? null;
  }

  async deactivateSession(id) {
    const session = await this.findSessionById(id);
    if (!session) return null;
    session.active = false;
    session.updatedAt = now();
    return session;
  }

  async updateSession(id, values) {
    const session = await this.findSessionById(id);
    if (!session) return null;
    Object.assign(session, values, { updatedAt: now() });
    return session;
  }

  async findRolesByUserId(userId) {
    const roleIds = this.usersRoles.filter((userRole) => userRole.userId === userId && userRole.active !== false).map((userRole) => userRole.roleId);
    return this.roles.filter((role) => roleIds.includes(role.id) && role.active !== false);
  }

  async findPermissionsByUserId(userId, permission) {
    const roles = await this.findRolesByUserId(userId);
    const roleIds = roles.map((role) => role.id);
    const permissionIds = this.rolesPermissions.filter((rolePermission) => {return roleIds.includes(rolePermission.roleId) && rolePermission.active !== false}).map((rolePermission) => rolePermission.permissionId);
    return this.permissions.filter((item) => {return permissionIds.includes(item.id) && item.active !== false && (!permission || item.permission === permission);});
  }
}
