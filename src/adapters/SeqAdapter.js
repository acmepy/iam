import { DataTypes, Op } from "seq";
import { AdapterError } from "../core/errors.js";
import { createSessionId, now } from "../core/utils.js";
import { defineIamModels } from "./models/iamModels.js";

export class SeqAdapter {
  constructor({ seq, models } = {}) {
    if (!seq && !models) throw new AdapterError("Seq o models son requeridos");
    this.seq = seq;
    this.models = models ?? defineIamModels({define: seq.define.bind(seq), DataTypes});
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

    return normalize(await this.models.Session.create(values));
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
    await session.update({ active: false, updatedAt: now() });
    return normalize(session);
  }

  async updateSession(id, values) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    await session.update(values);
    return normalize(session);
  }

  async findRolesByUserId(userId) {
    const userRoles = await this.models.UserRole.findAll({where: { userId, active: true }});
    const roleIds = userRoles.map((item) => item.getDataValue("roleId"));
    if (roleIds.length === 0) return [];
    const roles = await this.models.Role.findAll({where: {id: { [Op.in]: roleIds },active: true}});
    return roles.map(normalize);
  }

  async findPermissionsByUserId(userId) {
    const roles = await this.findRolesByUserId(userId);
    const roleIds = roles.map((role) => role.id);
    if (roleIds.length === 0) return [];
    const rolePermissions = await this.models.RolePermission.findAll({where: {roleId: { [Op.in]: roleIds },active: true}});
    const permissionIds = rolePermissions.map((item) => item.getDataValue("permissionId"));
    if (permissionIds.length === 0) return [];
    const permissions = await this.models.Permission.findAll({where: {id: { [Op.in]: permissionIds }, active: true}});
    return permissions.map(normalize);
  }
}

function normalize(model) {
  if (!model)  return null;
  return typeof model.get === "function" ? model.get() : model;
}
