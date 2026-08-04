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

class AuthRequiredError extends RbacError {
  constructor(message = "Usuario y clave son necesarios") {
    super(message, 401, "AUTH_REQUIRED");
  }
}

class AuthError extends RbacError {
  constructor(message = "Credenciales inválidas") {
    super(message, 401, "AUTH_ERROR");
  }
}

class TokenRequiredError extends RbacError {
  constructor(message = "Token requerido") {
    super(message, 401, "TOKEN_REQUIRED");
  }
}

class TokenInvalidError extends RbacError {
  constructor(message = "Token inválido") {
    super(message, 401, "TOKEN_INVALID");
  }
}

class SessionRequiredError extends RbacError {
  constructor(message = "Sesión requerida") {
    super(message, 401, "SESSION_REQUIRED");
  }
}

class SessionInactiveError extends RbacError {
  constructor(message = "Sesión inactiva") {
    super(message, 401, "SESSION_INACTIVE");
  }
}

class PermissionRequiredError extends RbacError {
  constructor(message = "Permiso requerido") {
    super(message, 403, "PERMISSION_REQUIRED");
  }
}

class ForbiddenError extends RbacError {
  constructor(message = "No tiene permisos para realizar esta acción") {
    super(message, 403, "FORBIDDEN");
  }
}

class NotFoundError extends RbacError {
  constructor(message = "Registro no encontrado") {
    super(message, 404, "NOT_FOUND");
  }
}

class AdapterError extends RbacError {
  constructor(message = "Adapter requerido", errors = {}) {
    super(message, 500, "ADAPTER_ERROR", errors);
  }
}

class ValidationError extends RbacError {
  constructor(message = "Error de validación", errors = {}) {
    super(message, 400, "VALIDATION_ERROR", errors);
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

function ensureAdapter(adapter) {
  if (!adapter) {
    throw new AdapterError("Adapter requerido");
  }
}

/**
 * Role-based access helper backed by an IAM adapter.
 */
class RBAC {
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
   * @param {string} [permission]
   * @returns {Promise<import("../types.js").PermissionData[]>}
   */
  async getPermissions(userId, permission) {
    return this.adapter.findPermissionsByUserId(userId, permission);
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
    const permissions = await this.getPermissions(userId, permission);
    return permissions.some((item) => item.permission === permission && item.active !== false);
  }
}

class Session {
  constructor(values = {}) {
    Object.assign(this, values);
  }
}

class User {
  constructor(values = {}) {
    Object.assign(this, values);
  }
}

class Role {
  constructor(values = {}) {
    Object.assign(this, values);
  }
}

class Permission {
  constructor(values = {}) {
    Object.assign(this, values);
  }
}

class UserRole {
  constructor(values = {}) {
    Object.assign(this, values);
  }
}

class RolePermission {
  constructor(values = {}) {
    Object.assign(this, values);
  }
}

const collections$1 = ["users", "roles", "permissions", "userRoles", "rolePermissions", "sessions"];

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

  async findPermissionsByUserId(userId, permission) {
    const roles = await this.findRolesByUserId(userId);
    const roleIds = roles.map((role) => role.id);
    const permissionIds = this.rolePermissions.filter((rolePermission) => {return roleIds.includes(rolePermission.roleId) && rolePermission.active !== false}).map((rolePermission) => rolePermission.permissionId);
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

const collections = ["users", "roles", "permissions", "userRoles", "rolePermissions", "sessions"];
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
  models.User.hasMany(models.UserRole, { foreignKey: "userId", as: "userRoles" });
  models.User.hasMany(models.Session, { foreignKey: "userId", as: "sessions" });
  models.User.belongsToMany(models.Role, { through: models.UserRole, foreignKey: "userId", otherKey: "roleId", as: "roles" });

  models.Role.hasMany(models.UserRole, { foreignKey: "roleId", as: "userRoles" });
  models.Role.hasMany(models.RolePermission, { foreignKey: "roleId", as: "rolePermissions" });
  models.Role.belongsToMany(models.User, { through: models.UserRole, foreignKey: "roleId", otherKey: "userId", as: "users" });
  models.Role.belongsToMany(models.Permission, { through: models.RolePermission, foreignKey: "roleId", otherKey: "permissionId", as: "permissions" });

  models.Permission.hasMany(models.RolePermission, { foreignKey: "permissionId", as: "rolePermissions" });
  models.Permission.belongsToMany(models.Role, { through: models.RolePermission, foreignKey: "permissionId", otherKey: "roleId", as: "roles" });

  models.UserRole.belongsTo(models.User, { foreignKey: "userId", as: "user" });
  models.UserRole.belongsTo(models.Role, { foreignKey: "roleId", as: "role" });

  models.RolePermission.belongsTo(models.Role, { foreignKey: "roleId", as: "role" });
  models.RolePermission.belongsTo(models.Permission, { foreignKey: "permissionId", as: "permission" });

  models.Session.belongsTo(models.User, { foreignKey: "userId", as: "user" });
}

const modelDefinitions = [
  {
    name: "User",
    //tableName: "users",
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
    name: "Role",
    //tableName: "roles",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      role: { type: "string", length: 100, allowNull: false },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "Permission",
    //tableName: "permissions",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      permission: { type: "string", length: 150, allowNull: false },
      title: { type: "string", length: 150, allowNull: true },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "UserRole",
    //tableName: "user_roles",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      userId: { type: "string", length: 100, allowNull: false, references: { model: "User", key: "id" } },
      roleId: { type: "integer", allowNull: false, references: { model: "Role", key: "id" } },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "RolePermission",
    //tableName: "role_permissions",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      roleId: { type: "integer", allowNull: false, references: { model: "Role", key: "id" } },
      permissionId: { type: "integer", allowNull: false, references: { model: "Permission", key: "id" } },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "Session",
    //tableName: "sessions",
    attributes: {
      id: { type: "string", length: 100, primaryKey: true, allowNull: false },
      userId: { type: "string", length: 100, allowNull: false, references: { model: "User", key: "id" } },
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
    return normalize$1(await this.models.User.findOne({where: {[this.opOr()]: [{ id: username }, { email: username }, { name: username }]}}));
  }

  async findUserById(id) {
    return normalize$1(await this.models.User.findByPk(id));
  }

  async verifyPassword(user, password) {
    if (typeof user.verifyPassword === "function") return user.verifyPassword(password);
    return user.password === password;
  }

  async createSession(session) {
    const values = { id: session.id ?? createSessionId(), ...session};

    return normalize$1(await this.models.Session.create(values));
  }

  async findSessionById(id) {
    return normalize$1(await this.models.Session.findByPk(id));
  }

  async findSessionByToken(token) {
    return normalize$1(await this.models.Session.findOne({ where: { token } }));
  }

  async findActiveSessionByUserId(userId) {
    return normalize$1(await this.models.Session.findOne({where: { userId, active: true }}));
  }

  async deactivateSession(id) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    await session.update({ active: false, updatedAt: now() });
    return normalize$1(session);
  }

  async updateSession(id, values) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    await session.update(values);
    return normalize$1(session);
  }

  async findRolesByUserId(userId) {
    const userRoles = await this.models.UserRole.findAll({where: { userId, active: true }});
    const roleIds = userRoles.map((item) => item.roleId);
    if (roleIds.length === 0) return [];
    const roles = await this.models.Role.findAll({where: { id: roleIds, active: true}});
    return roles.map(normalize$1);
  }

  async findPermissionsByUserId(userId, permission) {
    const userRoles = await this.models.UserRole.findAll({
      where: { userId, active: true },
      attributes: ["roleId"],
      include: [{
        model: this.models.Role,
        as: "role",
        where: { active: true },
        attributes: ["id"],
        required: true
      }]
    });
    const assignedRoleIds = userRoles.map((item) => readValue(item, "roleId"));
    if (assignedRoleIds.length === 0) return [];
    const where = {active: true};
    if (permission) where.permission = permission;
    const rolePermissions = await this.models.RolePermission.findAll({
      where: {roleId: assignedRoleIds, active: true},
      attributes: ["permissionId"],
      include: [{
        model: this.models.Permission,
        as: "permission",
        where,
        required: true
      }]
    });

    return uniqueNormalized$1(rolePermissions.map((item) => readValue(item, "permission")).filter(Boolean));
  }

  opOr() {
    return this.sequelize?.Sequelize?.Op?.or ?? "or";
  }
}

function normalize$1(model) {
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
    const item = normalize$1(model);
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
    return normalize(await this.models.User.findOne({where: {[Op.or]: [{ id: username },{ email: username },{ name: username }]}}));
  }

  async findUserById(id) {
    return normalize(await this.models.User.findByPk(id));
  }

  async verifyPassword(user, password) {
    if (typeof user.verifyPassword === "function") return user.verifyPassword(password);
    return user.password === password;
  }

  async createSession(session) {
    const values = {id: session.id ?? createSessionId(), ...session};

    const created = await this.models.Session.create(values);
    const next = normalize(created);
    await writeAudit(this.auditable, { action: "create", rowId: next?.id, old: {}, new: next });
    return next;
  }

  async findSessionById(id) {
    return normalize(await this.models.Session.findByPk(id));
  }

  async findSessionByToken(token) {
    return normalize(await this.models.Session.findOne({ where: { token } }));
  }

  async findActiveSessionByUserId(userId) {
    return normalize(await this.models.Session.findOne({where: { userId, active: true }}));
  }

  async deactivateSession(id) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    const previous = normalize(session);
    await session.update({ active: false, updatedAt: now() });
    const next = normalize(session);
    await writeAudit(this.auditable, { action: "update", rowId: id, old: previous, new: next });
    return next;
  }

  async updateSession(id, values) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    const previous = normalize(session);
    await session.update(values);
    const next = normalize(session);
    await writeAudit(this.auditable, { action: "update", rowId: id, old: previous, new: next });
    return next;
  }

  async findRolesByUserId(userId) {
    const userRoles = await this.models.UserRole.findAll({where: { userId, active: true }});
    const roleIds = userRoles.map((item) => item.getDataValue("roleId"));
    if (roleIds.length === 0) return [];
    const roles = await this.models.Role.findAll({where: {id: { [Op.in]: roleIds },active: true}});
    return roles.map(normalize);
  }

  async findPermissionsByUserId(userId, permission) {
    const where = { active: true };
    if (permission) where.permission = permission;
    const rolePermissions = await this.models.RolePermission.findAll({
      where: {active: true},
      attributes: ["permissionId"],
      //eager: false,
      include: [
        {model: this.models.Permission, as: "permission", where, required: true},
        {
          model: this.models.Role,
          as: "role",
          where: { active: true },
          attributes: ["id"],
          required: true,
          include: {model: this.models.UserRole, as: "userRoles", where: { userId, active: true }, attributes: ["id"], required: true}
        }
      ]
    });

    return uniqueNormalized(rolePermissions.map((item) => item.getDataValue("permission")).filter(Boolean));
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
    tableName: auditable.tableName || "Session",
    ...change
  });
}

function normalize(model) {
  if (!model)  return null;
  return typeof model.get === "function" ? model.get() : model;
}

function uniqueNormalized(models) {
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

export { AdapterError, AuthError, AuthRequiredError, ForbiddenError, IndexedDBAdapter, LocalStorageAdapter, MemoryAdapter, NotFoundError, Permission, PermissionRequiredError, RBAC, RbacError, Role, RolePermission, SeqAdapter, SequelizeAdapter, Session, SessionInactiveError, SessionRequiredError, TokenInvalidError, TokenRequiredError, User, UserRole, ValidationError };
