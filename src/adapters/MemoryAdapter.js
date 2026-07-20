import { now } from "../core/utils.js";

const collections = ["users", "roles", "permissions", "userRoles", "rolePermissions", "sessions"];

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

  async findUserByUsername(username) {
    return this.users.find((user) => {return user.id === username || user.email === username || user.name === username}) ?? null;
  }

  async findUserById(id) {
    return this.users.find((user) => user.id === id) ?? null;
  }

  async verifyPassword(user, password) {
    return user.password === password;
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
    const roleIds = this.userRoles.filter((userRole) => userRole.userId === userId && userRole.active !== false).map((userRole) => userRole.roleId);
    return this.roles.filter((role) => roleIds.includes(role.id) && role.active !== false);
  }

  async findPermissionsByUserId(userId) {
    const roles = await this.findRolesByUserId(userId);
    const roleIds = roles.map((role) => role.id);
    const permissionIds = this.rolePermissions.filter((rolePermission) => {return roleIds.includes(rolePermission.roleId) && rolePermission.active !== false}).map((rolePermission) => rolePermission.permissionId);
    return this.permissions.filter((permission) => {return permissionIds.includes(permission.id) && permission.active !== false;});
  }
}
