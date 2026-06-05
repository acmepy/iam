import { ensureAdapter } from "./utils.js";

export class RBAC {
  constructor({ adapter } = {}) {
    ensureAdapter(adapter);
    this.adapter = adapter;
  }

  async getRoles(userId) {
    return this.adapter.findRolesByUserId(userId);
  }

  async getPermissions(userId) {
    return this.adapter.findPermissionsByUserId(userId);
  }

  async hasRole(userId, role) {
    const roles = await this.getRoles(userId);
    return roles.some((item) => item.role === role && item.active !== false);
  }

  async can(userId, permission) {
    const permissions = await this.getPermissions(userId);
    return permissions.some((item) => item.permission === permission && item.active !== false);
  }
}
