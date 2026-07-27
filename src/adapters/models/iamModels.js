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
