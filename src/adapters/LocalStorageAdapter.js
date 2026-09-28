import { AdapterError } from "../core/errors.js";
import { MemoryAdapter } from "./MemoryAdapter.js";

const defaultKey = "iam";

export class LocalStorageAdapter extends MemoryAdapter {
  constructor({ storage = globalThis.localStorage, key = defaultKey, data = {} } = {}) {
    const loaded = load(storage, key);
    super(loaded ?? data);
    this.storage = storage;
    this.key = key;
  }

  async createUser(user) {
    const result = await super.createUser(user);
    await this.save();
    return result;
  }

  async updateUser(id, values) {
    const result = await super.updateUser(id, values);
    await this.save();
    return result;
  }

  async createPasswordReset(reset) {
    const result = await super.createPasswordReset(reset);
    await this.save();
    return result;
  }

  async changePassword(userId, expectedPassword, password) {
    const result = await super.changePassword(userId, expectedPassword, password);
    await this.save();
    return result;
  }

  async resetPassword(id, password, timestamp) {
    const result = await super.resetPassword(id, password, timestamp);
    await this.save();
    return result;
  }

  async createSession(session) {
    const result = await super.createSession(session);
    this.save();
    return result;
  }

  async deactivateSession(id) {
    const result = await super.deactivateSession(id);
    this.save();
    return result;
  }

  async updateSession(id, values) {
    const result = await super.updateSession(id, values);
    this.save();
    return result;
  }

  save() {
    if (!this.storage) throw new AdapterError("localStorage no está disponible");
    this.storage.setItem(this.key, JSON.stringify({users: this.users, roles: this.roles, permissions: this.permissions, usersRoles: this.usersRoles, rolesPermissions: this.rolesPermissions, sessions: this.sessions, passwordResets: this.passwordResets}));
  }
}

function load(storage, key) {
  if (!storage) return null;
  const value = storage.getItem(key);
  return value ? JSON.parse(value) : null;
}
