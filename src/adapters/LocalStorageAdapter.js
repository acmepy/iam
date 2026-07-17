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
    this.storage.setItem(this.key, JSON.stringify({users: this.users, roles: this.roles, permissions: this.permissions, userRoles: this.userRoles, rolePermissions: this.rolePermissions, sessions: this.sessions}));
  }
}

function load(storage, key) {
  if (!storage) return null;
  const value = storage.getItem(key);
  return value ? JSON.parse(value) : null;
}
