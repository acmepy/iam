import { Op, DataTypes } from 'seq';

class RbacError extends Error {
  constructor(message, status = 400, code = "RBAC_ERROR", errors = {}, stack) {
    super(message);

    this.name = this.constructor.name;
    this.status = status;
    this.code = code;
    this.errors = errors;
    this.isOperational = true;
    if (stack) this.stack = stack;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

class AdapterError extends RbacError {
  constructor(message = "Adapter requerido", errors = {}) {
    super(message, 500, "ADAPTER_ERROR", errors);
  }
}

function now() {
  return new Date();
}

function createSessionId() {
  const time = Date.now().toString(36).toUpperCase().padStart(10, "0");
  const random = Math.random().toString(36).slice(2, 18).toUpperCase().padEnd(16, "0");
  return `${time}${random}`.slice(0, 26);
}

const collections$1 = ["users", "roles", "permissions", "usersRoles", "rolesPermissions", "sessions", "passwordResets"];

/**
 * In-memory IAM adapter, useful for tests, demos, and small embedded setups.
 */
class MemoryAdapter {
  /**
   * @param {import("../types.js").AdapterData} data
   */
  constructor(data = {}) {
    for (const name of collections$1) this[name] = [...(data[name] ?? [])];
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

const defaultKey = "iam";

class LocalStorageAdapter extends MemoryAdapter {
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

const collections = ["users", "roles", "permissions", "usersRoles", "rolesPermissions", "sessions", "passwordResets"];
const defaultDbName = "iam";
const defaultStoreName = "collections";

class IndexedDBAdapter extends MemoryAdapter {
  constructor({indexedDB = globalThis.indexedDB, dbName = defaultDbName, storeName = defaultStoreName, data = {} } = {}) {
    super(data);
    this.indexedDB = indexedDB;
    this.dbName = dbName;
    this.storeName = storeName;
    this.db = null;
  }

  async init() {
    await this.load();
    return this;
  }

  async load() {
    const db = await this.open();
    const transaction = db.transaction(this.storeName, "readonly");
    const done = transactionToPromise(transaction);
    const store = transaction.objectStore(this.storeName);
    const requests = collections.map((name) => { return {name, request: store.get(name)}});
    for (const item of requests) {
      const value = await requestToPromise(item.request);
      const name = item.name;
      this[name] = [...(value?.items ?? this[name] ?? [])];
    }
    await done;
    return this;
  }

  async save() {
    const db = await this.open();
    const transaction = db.transaction(this.storeName, "readwrite");
    const done = transactionToPromise(transaction);
    const store = transaction.objectStore(this.storeName);
    for (const name of collections) store.put({ name, items: this[name] }, name);
    await done;
    return this;
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
    await this.save();
    return result;
  }

  async deactivateSession(id) {
    const result = await super.deactivateSession(id);
    await this.save();
    return result;
  }

  async updateSession(id, values) {
    const result = await super.updateSession(id, values);
    await this.save();
    return result;
  }

  async open() {
    if (!this.indexedDB) throw new AdapterError("IndexedDB no está disponible");
    if (this.db) return this.db;
    const request = this.indexedDB.open(this.dbName, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(this.storeName)) db.createObjectStore(this.storeName);
    };
    this.db = await requestToPromise(request);
    return this.db;
  }
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new AdapterError("Error en IndexedDB", request.error));
  });
}

function transactionToPromise(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(new AdapterError("Error en transacción IndexedDB", transaction.error));
    transaction.onabort = () => reject(new AdapterError("Transacción IndexedDB abortada", transaction.error));
  });
}

function defineIamModels({ define, DataTypes, tableNames = {}, references = false, associations = false }) {
  const models = Object.fromEntries(
    modelDefinitions.map((definition) => {
      const tableName = tableNames[definition.name] ?? definition.tableName;
      return [ definition.name, define(definition.name, mapAttributes(definition.attributes, DataTypes, references), { tableName, timestamps: true})];
    })
  );

  if (associations) associateIamModels(models);

  return models;
}

function associateIamModels(models) {
  models.users.hasMany(models.usersRoles, { foreignKey: "userId", as: "usersRoles" });
  models.users.hasMany(models.sessions, { foreignKey: "userId", as: "sessions" });
  models.users.belongsToMany(models.roles, { through: models.usersRoles, foreignKey: "userId", otherKey: "roleId", as: "roles" });

  models.roles.hasMany(models.usersRoles, { foreignKey: "roleId", as: "usersRoles" });
  models.roles.hasMany(models.rolesPermissions, { foreignKey: "roleId", as: "rolesPermissions" });
  models.roles.belongsToMany(models.users, { through: models.usersRoles, foreignKey: "roleId", otherKey: "userId", as: "users" });
  models.roles.belongsToMany(models.permissions, { through: models.rolesPermissions, foreignKey: "roleId", otherKey: "permissionId", as: "permissions" });

  models.permissions.hasMany(models.rolesPermissions, { foreignKey: "permissionId", as: "rolesPermissions" });
  models.permissions.belongsToMany(models.roles, { through: models.rolesPermissions, foreignKey: "permissionId", otherKey: "roleId", as: "roles" });

  models.usersRoles.belongsTo(models.users, { foreignKey: "userId", as: "user" });
  models.usersRoles.belongsTo(models.roles, { foreignKey: "roleId", as: "role" });

  models.rolesPermissions.belongsTo(models.roles, { foreignKey: "roleId", as: "role" });
  models.rolesPermissions.belongsTo(models.permissions, { foreignKey: "permissionId", as: "permission" });

  models.sessions.belongsTo(models.users, { foreignKey: "userId", as: "user" });
}

const modelDefinitions = [
  {
    name: "users",
    attributes: {
      id: { type: "string", length: 100, primaryKey: true, allowNull: false },
      password: { type: "string", length: 255, allowNull: false },
      name: { type: "string", length: 150, allowNull: true },
      email: { type: "string", length: 150, allowNull: true },
      options: { type: "json", allowNull: true, defaultValue: () => ({}) },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "passwordResets",
    attributes: {
      id: { type: "string", length: 64, primaryKey: true, allowNull: false },
      userId: { type: "string", length: 100, allowNull: false, references: { model: "users", key: "id" } },
      expiresAt: { type: "integer", allowNull: false }
    }
  },
  {
    name: "roles",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      role: { type: "string", length: 100, allowNull: false },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "permissions",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      permission: { type: "string", length: 150, allowNull: false },
      title: { type: "string", length: 150, allowNull: true },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "usersRoles",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      userId: { type: "string", length: 100, allowNull: false, references: { model: "users", key: "id" } },
      roleId: { type: "integer", allowNull: false, references: { model: "roles", key: "id" } },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "rolesPermissions",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      roleId: { type: "integer", allowNull: false, references: { model: "roles", key: "id" } },
      permissionId: { type: "integer", allowNull: false, references: { model: "permissions", key: "id" } },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "sessions",
    attributes: {
      id: { type: "string", length: 100, primaryKey: true, allowNull: false },
      userId: { type: "string", length: 100, allowNull: false, references: { model: "users", key: "id" } },
      token: { type: "string", length: 500, allowNull: true },
      options: { type: "json", allowNull: true, defaultValue: () => ({}) },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  }
];

function mapAttributes(attributes, DataTypes, references) {
  return Object.fromEntries(
    Object.entries(attributes).map(([name, attribute]) => {
      const { type, length, references: attributeReferences, ...options } = attribute;
      if (references && attributeReferences) options.references = attributeReferences;
      return [name, {...options, type: mapType(type, length, DataTypes)}];
    })
  );
}

function mapType(type, length, DataTypes) {
  if (type === "string") return typeof DataTypes.STRING === "function" ? DataTypes.STRING(length) : DataTypes.STRING;
  if (type === "integer") return DataTypes.INTEGER;
  if (type === "boolean") return DataTypes.BOOLEAN;
  if (type === "json") return DataTypes.JSON;
  throw new TypeError(`Tipo de modelo IAM no soportado: ${type}`);
}

class SequelizeAdapter {
  constructor({ sequelize, models, tableNames } = {}) {
    if (!sequelize && !models) throw new AdapterError("Sequelize o models son requeridos");
    this.sequelize = sequelize;
    this.models = models ?? defineIamModels({define: sequelize.define.bind(sequelize), DataTypes: sequelize.Sequelize.DataTypes, tableNames, associations: true});
  }

  async findUserByUsername(username) {
    return normalize(await this.models.users.findOne({where: {[this.opOr()]: [{ id: username }, { email: username }, { name: username }]}}));
  }

  async findUserById(id) {
    return normalize(await this.models.users.findByPk(id));
  }

  async verifyPassword(user, password) {
    if (typeof user.verifyPassword === "function") return user.verifyPassword(password);
    return user.password === password;
  }


  async createUser(user) {
    return (await this.models.users.create(user)).get({ plain: true });
  }

  async updateUser(id, values) {
    const user = await this.models.users.findByPk(id);
    if (!user) return null;
    await user.update(values);
    return user.get({ plain: true });
  }

  async createPasswordReset(reset) {
    if (!this.models.passwordResets) throw new AdapterError("Modelo passwordResets requerido");
    await this.models.passwordResets.create(reset);
  }

  async changePassword(userId, expectedPassword, password) {
    const engine = this.sequelize ?? this.models.users.sequelize;
    if (!engine?.transaction) throw new AdapterError("Transacciones requeridas para cambiar contrasena");
    return engine.transaction(async transaction => {
      const user = await this.models.users.findByPk(userId, { transaction, lock: transaction.LOCK.UPDATE });
      if (!user || user.get({ plain: true }).password !== expectedPassword) return false;
      await user.update({ password }, { transaction });
      await this.models.sessions.update({ active: false }, { where: { userId }, transaction });
      if (this.models.passwordResets) await this.models.passwordResets.destroy({ where: { userId }, transaction });
      return true;
    });
  }

  async resetPassword(id, password, timestamp) {
    const engine = this.sequelize ?? this.models.users.sequelize;
    if (!engine?.transaction || !this.models.passwordResets) throw new AdapterError("Transacciones y modelo passwordResets requeridos");
    return engine.transaction(async transaction => {
      const reset = await this.models.passwordResets.findByPk(id, { transaction });
      if (!reset) return false;
      const values = reset.get({ plain: true });
      if (values.expiresAt <= timestamp) return false;
      const user = await this.models.users.findByPk(values.userId, { transaction, lock: transaction.LOCK.UPDATE });
      if (!user) return false;
      const consumed = await this.models.passwordResets.destroy({ where: { id }, transaction });
      if (consumed !== 1) return false;
      await user.update({ password }, { transaction });
      await this.models.sessions.update({ active: false }, { where: { userId: values.userId }, transaction });
      await this.models.passwordResets.destroy({ where: { userId: values.userId }, transaction });
      return true;
    });
  }

  async createSession(session) {
    const values = { id: session.id ?? createSessionId(), ...session};

    return normalize(await this.models.sessions.create(values));
  }

  async findSessionById(id) {
    return normalize(await this.models.sessions.findByPk(id));
  }

  async findSessionByToken(token) {
    return normalize(await this.models.sessions.findOne({ where: { token } }));
  }

  async findActiveSessionByUserId(userId) {
    return normalize(await this.models.sessions.findOne({where: { userId, active: true }}));
  }

  async deactivateSession(id) {
    const session = await this.models.sessions.findByPk(id);
    if (!session) return null;
    await session.update({ active: false, updatedAt: now() });
    return normalize(session);
  }

  async updateSession(id, values) {
    const session = await this.models.sessions.findByPk(id);
    if (!session) return null;
    await session.update(values);
    return normalize(session);
  }

  async findRolesByUserId(userId) {
    const usersRoles = await this.models.usersRoles.findAll({where: { userId, active: true }});
    const roleIds = usersRoles.map((item) => item.roleId);
    if (roleIds.length === 0) return [];
    const roles = await this.models.roles.findAll({where: { id: roleIds, active: true}});
    return roles.map(normalize);
  }

  async findPermissionsByUserId(userId, permission) {
    const usersRoles = await this.models.usersRoles.findAll({
      where: { userId, active: true },
      attributes: ["roleId"],
      include: [{
        model: this.models.roles,
        as: "role",
        where: { active: true },
        attributes: ["id"],
        required: true
      }]
    });
    const assignedRoleIds = usersRoles.map((item) => readValue(item, "roleId"));
    if (assignedRoleIds.length === 0) return [];
    const where = {active: true};
    if (permission) where.permission = permission;
    const rolesPermissions = await this.models.rolesPermissions.findAll({
      where: {roleId: assignedRoleIds, active: true},
      attributes: ["permissionId"],
      include: [{
        model: this.models.permissions,
        as: "permission",
        where,
        required: true
      }]
    });

    return uniqueNormalized$1(rolesPermissions.map((item) => readValue(item, "permission")).filter(Boolean));
  }

  opOr() {
    return this.sequelize?.Sequelize?.Op?.or ?? "or";
  }
}

function normalize(model) {
  if (!model) return null;
  return typeof model.get === "function" ? model.get({ plain: true }) : model;
}

function readValue(model, key) {
  if (!model) return undefined;
  if (typeof model.get === "function") {
    const values = model.get({ plain: true });
    if (values && Object.prototype.hasOwnProperty.call(values, key)) return values[key];
  }
  return typeof model.getDataValue === "function" ? model.getDataValue(key) : model[key];
}

function uniqueNormalized$1(models) {
  const seen = new Set();
  const result = [];
  for (const model of models) {
    const item = normalize(model);
    if (!item || seen.has(item.id)) continue;
    seen.add(item.id);
    result.push(item);
  }
  return result;
}

class SeqAdapter {
  constructor({ seq, models, tableNames, auditable } = {}) {
    if (!seq && !models) throw new AdapterError("Seq o models son requeridos");
    this.seq = seq;
    this.models = models ?? defineIamModels({define: seq.define.bind(seq), DataTypes, tableNames, references: true, associations: true});
    this.auditable = normalizeAuditable(auditable);
  }

  async findUserByUsername(username) {
    return (await this.models.users.findOne({where: {[Op.or]: [{ id: username }, { email: username }, { name: username }]}}))?.get() ?? null;
  }

  async findUserById(id) {
    return (await this.models.users.findByPk(id))?.get() ?? null;
  }

  async verifyPassword(user, password) {
    if (typeof user.verifyPassword === "function") return user.verifyPassword(password);
    return user.password === password;
  }


  async createUser(user) {
    return (await this.models.users.create(user)).get();
  }

  async updateUser(id, values) {
    const user = await this.models.users.findByPk(id);
    if (!user) return null;
    await user.update(values);
    return user.get();
  }

  async createPasswordReset(reset) {
    if (!this.models.passwordResets) throw new AdapterError("Modelo passwordResets requerido");
    await this.models.passwordResets.create(reset);
  }

  async changePassword(userId, expectedPassword, password) {
    const engine = this.seq ?? this.models.users.seq;
    if (!engine?.transaction) throw new AdapterError("Transacciones requeridas para cambiar contrasena");
    return engine.transaction(async transaction => {
      const user = await this.models.users.findByPk(userId, { transaction });
      if (!user || user.get().password !== expectedPassword) return false;
      await user.update({ password }, { transaction });
      await this.models.sessions.update({ active: false }, { where: { userId }, transaction });
      if (this.models.passwordResets) await this.models.passwordResets.destroy({ where: { userId }, transaction });
      return true;
    });
  }

  async resetPassword(id, password, timestamp) {
    const engine = this.seq ?? this.models.users.seq;
    if (!engine?.transaction || !this.models.passwordResets) throw new AdapterError("Transacciones y modelo passwordResets requeridos");
    return engine.transaction(async transaction => {
      const reset = await this.models.passwordResets.findByPk(id, { transaction });
      if (!reset) return false;
      const values = reset.get();
      if (values.expiresAt <= timestamp) return false;
      const user = await this.models.users.findByPk(values.userId, { transaction });
      if (!user) return false;
      const consumed = await this.models.passwordResets.destroy({ where: { id }, transaction });
      if (consumed !== 1) return false;
      await user.update({ password }, { transaction });
      await this.models.sessions.update({ active: false }, { where: { userId: values.userId }, transaction });
      await this.models.passwordResets.destroy({ where: { userId: values.userId }, transaction });
      return true;
    });
  }

  async createSession(session) {
    const values = {id: session.id ?? createSessionId(), ...session};

    const created = await this.models.sessions.create(values);
    const next = created.get();
    await writeAudit(this.auditable, { action: "create", rowId: next?.id, old: {}, new: next });
    return next;
  }

  async findSessionById(id) {
    return (await this.models.sessions.findByPk(id))?.get() ?? null;
  }

  async findSessionByToken(token) {
    return (await this.models.sessions.findOne({ where: { token } }))?.get() ?? null;
  }

  async findActiveSessionByUserId(userId) {
    return (await this.models.sessions.findOne({where: { userId, active: true }}))?.get() ?? null;
  }

  async deactivateSession(id) {
    const session = await this.models.sessions.findByPk(id);
    if (!session) return null;
    const previous = session.get();
    await session.update({ active: false, updatedAt: now() });
    const next = session.get();
    await writeAudit(this.auditable, { action: "update", rowId: id, old: previous, new: next });
    return next;
  }

  async updateSession(id, values) {
    const session = await this.models.sessions.findByPk(id);
    if (!session) return null;
    const previous = session.get();
    await session.update(values);
    const next = session.get();
    await writeAudit(this.auditable, { action: "update", rowId: id, old: previous, new: next });
    return next;
  }

  async findRolesByUserId(userId) {
    const usersRoles = await this.models.usersRoles.findAll({where: { userId, active: true }});
    const roleIds = usersRoles.map((item) => item.getDataValue("roleId"));
    if (roleIds.length === 0) return [];
    const roles = await Promise.all(roleIds.map((id) => this.models.roles.findOne({ where: { id, active: true } })));
    return roles.filter(Boolean).map((role) => role.get());
  }

  async findPermissionsByUserId(userId, permission) {
    const where = { active: true };
    if (permission) where.permission = permission;
    const rolesPermissions = await this.models.rolesPermissions.findAll({
      where: {active: true},
      attributes: ["permissionId"],
      eager: true,
      include: [
        {model: this.models.permissions, as: "permission", where, required: true},
        {
          model: this.models.roles,
          as: "role",
          where: { active: true },
          attributes: ["id"],
          required: true,
          include: {model: this.models.usersRoles, as: "usersRoles", where: { userId, active: true }, attributes: ["id"], required: true}
        }
      ]
    });

    return uniqueNormalized(rolesPermissions.map((item) => item.getDataValue("permission")).filter(Boolean));
  }
}

function normalizeAuditable(auditable) {
  if (!auditable) return null;
  if (typeof auditable === "function") return { write: auditable };
  if (typeof auditable.write === "function") return auditable;
  if (typeof auditable.onChange === "function") return { ...auditable, write: auditable.onChange };
  return null;
}

async function writeAudit(auditable, change) {
  if (!auditable) return;
  await auditable.write({
    module: "iam",
    resource: "session",
    tableName: auditable.tableName || "sessions",
    ...change
  });
}

function uniqueNormalized(models) {
  const seen = new Set();
  const result = [];
  for (const model of models) {
    const item = model.get();
    if (!item || seen.has(item.id)) continue;
    seen.add(item.id);
    result.push(item);
  }
  return result;
}

export { IndexedDBAdapter, LocalStorageAdapter, MemoryAdapter, SeqAdapter, SequelizeAdapter };
