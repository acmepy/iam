import { ensureAdapter } from "./utils.js";

/**
 * Role-based access helper backed by an IAM adapter.
 */
export class RBAC {
  /**
   * @param {{ adapter: import("../types.js").Adapter }} options
   */
  constructor({ adapter } = {}) {
    ensureAdapter(adapter);
    this.adapter = adapter;
  }

  /**
   * @param {import("../types.js").Id} userId
   * @returns {Promise<import("../types.js").RoleData[]>}
   */
  async getRoles(userId) {
    return this.adapter.findRolesByUserId(userId);
  }

  /**
   * @param {import("../types.js").Id} userId
   * @returns {Promise<import("../types.js").PermissionData[]>}
   */
  async getPermissions(userId) {
    return this.adapter.findPermissionsByUserId(userId);
  }

  /**
   * @param {import("../types.js").Id} userId
   * @param {string} role
   * @returns {Promise<boolean>}
   */
  async hasRole(userId, role) {
    const roles = await this.getRoles(userId);
    return roles.some((item) => item.role === role && item.active !== false);
  }

  /**
   * @param {import("../types.js").Id} userId
   * @param {string} permission
   * @returns {Promise<boolean>}
   */
  async can(userId, permission) {
    const permissions = await this.getPermissions(userId);
    return permissions.some((item) => item.permission === permission && item.active !== false);
  }
}
