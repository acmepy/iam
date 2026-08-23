export function defineIamModels({ define, DataTypes, tableNames = {}, references = false, associations = false }) {
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
  models.users.hasMany(models.userRoles, { foreignKey: "userId", as: "userRoles" });
  models.users.hasMany(models.sessions, { foreignKey: "userId", as: "sessions" });
  models.users.belongsToMany(models.roles, { through: models.userRoles, foreignKey: "userId", otherKey: "roleId", as: "roles" });

  models.roles.hasMany(models.userRoles, { foreignKey: "roleId", as: "userRoles" });
  models.roles.hasMany(models.rolesPermissions, { foreignKey: "roleId", as: "rolesPermissions" });
  models.roles.belongsToMany(models.users, { through: models.userRoles, foreignKey: "roleId", otherKey: "userId", as: "users" });
  models.roles.belongsToMany(models.permissions, { through: models.rolesPermissions, foreignKey: "roleId", otherKey: "permissionId", as: "permissions" });

  models.permissions.hasMany(models.rolesPermissions, { foreignKey: "permissionId", as: "rolesPermissions" });
  models.permissions.belongsToMany(models.roles, { through: models.rolesPermissions, foreignKey: "permissionId", otherKey: "roleId", as: "roles" });

  models.userRoles.belongsTo(models.users, { foreignKey: "userId", as: "user" });
  models.userRoles.belongsTo(models.roles, { foreignKey: "roleId", as: "role" });

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
    name: "userRoles",
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
