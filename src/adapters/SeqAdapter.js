import { DataTypes, Op } from "seq";
import { AdapterError } from "../core/errors.js";
import { createSessionId, now } from "../core/utils.js";
import { defineIamModels } from "./models/iamModels.js";

export class SeqAdapter {
  constructor({ seq, models, tableNames, auditable, tenant = false } = {}) {
    if (!seq && !models) throw new AdapterError("Seq o models son requeridos");
    this.seq = seq;
    this.models = models ?? defineIamModels({define: seq.define.bind(seq), DataTypes, tableNames, references: true, associations: true, tenant});
    this.auditable = normalizeAuditable(auditable);
  }

  async findTenantById(id) {
    if (!this.models.tenants) throw new AdapterError("Modelo tenants requerido: habilite tenant en SeqAdapter");
    return (await this.models.tenants.findByPk(id))?.get() ?? null;
  }

  async findTenantsByUserId(userId) {
    if (!this.models.usersTenants) throw new AdapterError("Modelo usersTenants requerido");
    const assignments = await this.models.usersTenants.findAll({ where: { userId, active: true } });
    const tenants = await Promise.all(assignments.map(item => this.findTenantById(item.getDataValue("tenantId"))));
    return tenants.filter(item => item && item.active !== false);
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
        {
          model: this.models.permissions, 
          as: "permission", 
          where, 
          attributes: ["id", "permission"],
          required: true
        },
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
