import { DataTypes, Op } from "seq";
import { AdapterError } from "../core/errors.js";
import { createSessionId, now } from "../core/utils.js";
import { defineIamModels } from "./models/iamModels.js";

export class SeqAdapter {
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
