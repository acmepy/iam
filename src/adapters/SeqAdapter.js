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
    return (await this.models.User.findOne({where: {[Op.or]: [{ id: username }, { email: username }, { name: username }]}}))?.get() ?? null;
  }

  async findUserById(id) {
    return (await this.models.User.findByPk(id))?.get() ?? null;
  }

  async verifyPassword(user, password) {
    if (typeof user.verifyPassword === "function") return user.verifyPassword(password);
    return user.password === password;
  }

  async createSession(session) {
    const values = {id: session.id ?? createSessionId(), ...session};

    const created = await this.models.Session.create(values);
    const next = created.get();
    await writeAudit(this.auditable, { action: "create", rowId: next?.id, old: {}, new: next });
    return next;
  }

  async findSessionById(id) {
    return (await this.models.Session.findByPk(id))?.get() ?? null;
  }

  async findSessionByToken(token) {
    return (await this.models.Session.findOne({ where: { token } }))?.get() ?? null;
  }

  async findActiveSessionByUserId(userId) {
    return (await this.models.Session.findOne({where: { userId, active: true }}))?.get() ?? null;
  }

  async deactivateSession(id) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    const previous = session.get();
    await session.update({ active: false, updatedAt: now() });
    const next = session.get();
    await writeAudit(this.auditable, { action: "update", rowId: id, old: previous, new: next });
    return next;
  }

  async updateSession(id, values) {
    const session = await this.models.Session.findByPk(id);
    if (!session) return null;
    const previous = session.get();
    await session.update(values);
    const next = session.get();
    await writeAudit(this.auditable, { action: "update", rowId: id, old: previous, new: next });
    return next;
  }

  async findRolesByUserId(userId) {
    const userRoles = await this.models.UserRole.findAll({where: { userId, active: true }});
    const roleIds = userRoles.map((item) => item.getDataValue("roleId"));
    if (roleIds.length === 0) return [];
    const roles = await Promise.all(roleIds.map((id) => this.models.Role.findOne({ where: { id, active: true } })));
    return roles.filter(Boolean).map((role) => role.get());
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
