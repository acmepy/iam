import { AdapterError } from "../core/errors.js";
import { createSessionId, now } from "../core/utils.js";
import { defineIamModels } from "./models/iamModels.js";

export class SequelizeAdapter {
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
    const userRoles = await this.models.userRoles.findAll({where: { userId, active: true }});
    const roleIds = userRoles.map((item) => item.roleId);
    if (roleIds.length === 0) return [];
    const roles = await this.models.roles.findAll({where: { id: roleIds, active: true}});
    return roles.map(normalize);
  }

  async findPermissionsByUserId(userId, permission) {
    const userRoles = await this.models.userRoles.findAll({
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
    const assignedRoleIds = userRoles.map((item) => readValue(item, "roleId"));
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
