import { AdapterError } from "../core/errors.js";
import { createSessionId, now } from "../core/utils.js";
import { defineIamModels } from "./models/iamModels.js";

export class SequelizeAdapter {
  constructor({ sequelize, models, tableNames, tenant = false } = {}) {
    if (!sequelize && !models) throw new AdapterError("Sequelize o models son requeridos");
    this.sequelize = sequelize;
    this.models = models ?? defineIamModels({define: sequelize.define.bind(sequelize), DataTypes: sequelize.Sequelize.DataTypes, tableNames, associations: true, tenant});
  }

  async findTenantById(id) {
    if (!this.models.tenants) throw new AdapterError("Modelo tenants requerido: habilite tenant en SequelizeAdapter");
    return normalize(await this.models.tenants.findByPk(id));
  }

  async findTenantsByUserId(userId) {
    if (!this.models.usersTenants) throw new AdapterError("Modelo usersTenants requerido");
    const assignments = await this.models.usersTenants.findAll({ where: { userId, active: true } });
    const tenants = await Promise.all(assignments.map(item => this.findTenantById(readValue(item, "tenantId"))));
    return tenants.filter(item => item && item.active !== false);
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

    return uniqueNormalized(rolesPermissions.map((item) => readValue(item, "permission")).filter(Boolean));
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
