import { AdapterError } from "../core/errors.js";
import { createSessionId, now } from "../core/utils.js";

export class SequelizeAdapter {
  constructor({ sequelize, models } = {}) {
    if (!sequelize && !models) {
      throw new AdapterError("Sequelize o models son requeridos");
    }

    this.sequelize = sequelize;
    this.models = models ?? defineModels(sequelize);
  }

  async findUserByUsername(username) {
    return normalize(await this.models.User.findOne({
      where: {
        [this.opOr()]: [
          { id: username },
          { email: username },
          { name: username }
        ]
      }
    }));
  }

  async findUserById(id) {
    return normalize(await this.models.User.findByPk(id));
  }

  async verifyPassword(user, password) {
    if (typeof user.verifyPassword === "function") {
      return user.verifyPassword(password);
    }

    return user.password === password;
  }

  async createSession(session) {
    const values = {
      id: session.id ?? createSessionId(),
      ...session
    };

    return normalize(await this.models.Session.create(values));
  }

  async findSessionById(id) {
    return normalize(await this.models.Session.findByPk(id));
  }

  async findSessionByToken(token) {
    return normalize(await this.models.Session.findOne({ where: { token } }));
  }

  async findActiveSessionByUserId(userId) {
    return normalize(await this.models.Session.findOne({
      where: { userId, active: true }
    }));
  }

  async deactivateSession(id) {
    const session = await this.models.Session.findByPk(id);

    if (!session) {
      return null;
    }

    await session.update({ active: false, updatedAt: now() });
    return normalize(session);
  }

  async updateSession(id, values) {
    const session = await this.models.Session.findByPk(id);

    if (!session) {
      return null;
    }

    await session.update(values);
    return normalize(session);
  }

  async findRolesByUserId(userId) {
    const userRoles = await this.models.UserRole.findAll({
      where: { userId, active: true }
    });
    const roleIds = userRoles.map((item) => item.roleId);

    if (roleIds.length === 0) {
      return [];
    }

    const roles = await this.models.Role.findAll({
      where: {
        id: roleIds,
        active: true
      }
    });

    return roles.map(normalize);
  }

  async findPermissionsByUserId(userId) {
    const roles = await this.findRolesByUserId(userId);
    const roleIds = roles.map((role) => role.id);

    if (roleIds.length === 0) {
      return [];
    }

    const rolePermissions = await this.models.RolePermission.findAll({
      where: {
        roleId: roleIds,
        active: true
      }
    });
    const permissionIds = rolePermissions.map((item) => item.permissionId);

    if (permissionIds.length === 0) {
      return [];
    }

    const permissions = await this.models.Permission.findAll({
      where: {
        id: permissionIds,
        active: true
      }
    });

    return permissions.map(normalize);
  }

  opOr() {
    return this.sequelize?.Sequelize?.Op?.or ?? "or";
  }
}

function normalize(model) {
  if (!model) {
    return null;
  }

  return typeof model.get === "function" ? model.get({ plain: true }) : model;
}

function defineModels(sequelize) {
  const { DataTypes } = sequelize.Sequelize;

  return {
    User: sequelize.define("User", {
      id: { type: DataTypes.STRING, primaryKey: true },
      password: DataTypes.STRING,
      name: DataTypes.STRING,
      email: DataTypes.STRING,
      options: DataTypes.JSON,
      active: DataTypes.BOOLEAN
    }),
    Role: sequelize.define("Role", {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      role: DataTypes.STRING,
      active: DataTypes.BOOLEAN
    }),
    Permission: sequelize.define("Permission", {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      permission: DataTypes.STRING,
      title: DataTypes.STRING,
      active: DataTypes.BOOLEAN
    }),
    UserRole: sequelize.define("UserRole", {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      userId: DataTypes.STRING,
      roleId: DataTypes.INTEGER,
      active: DataTypes.BOOLEAN
    }),
    RolePermission: sequelize.define("RolePermission", {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      roleId: DataTypes.INTEGER,
      permissionId: DataTypes.INTEGER,
      active: DataTypes.BOOLEAN
    }),
    Session: sequelize.define("Session", {
      id: { type: DataTypes.STRING, primaryKey: true },
      userId: DataTypes.STRING,
      token: DataTypes.STRING,
      options: DataTypes.JSON,
      active: DataTypes.BOOLEAN
    })
  };
}
