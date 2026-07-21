export function defineIamModels({ define, DataTypes, tableNames = {} }) {
  return Object.fromEntries(
    modelDefinitions.map((definition) => {
      const tableName = tableNames[definition.name] ?? definition.tableName;

      return [ definition.name, define(definition.name, mapAttributes(definition.attributes, DataTypes), { tableName, timestamps: true})];
    })
  );
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
      userId: { type: "string", length: 100, allowNull: false },
      roleId: { type: "integer", allowNull: false },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "RolePermission",
    //tableName: "role_permissions",
    attributes: {
      id: { type: "integer", primaryKey: true, autoIncrement: true },
      roleId: { type: "integer", allowNull: false },
      permissionId: { type: "integer", allowNull: false },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  },
  {
    name: "Session",
    //tableName: "sessions",
    attributes: {
      id: { type: "string", length: 100, primaryKey: true, allowNull: false },
      userId: { type: "string", length: 100, allowNull: false },
      token: { type: "string", length: 500, allowNull: true },
      options: { type: "json", allowNull: true, defaultValue: () => ({}) },
      active: { type: "boolean", allowNull: false, defaultValue: true }
    }
  }
];

function mapAttributes(attributes, DataTypes) {
  return Object.fromEntries(
    Object.entries(attributes).map(([name, attribute]) => {
      const { type, length, ...options } = attribute;

      return [
        name,
        {
          ...options,
          type: mapType(type, length, DataTypes)
        }
      ];
    })
  );
}

function mapType(type, length, DataTypes) {
  if (type === "string") {
    return typeof DataTypes.STRING === "function" ? DataTypes.STRING(length) : DataTypes.STRING;
  }

  if (type === "integer") {
    return DataTypes.INTEGER;
  }

  if (type === "boolean") {
    return DataTypes.BOOLEAN;
  }

  if (type === "json") {
    return DataTypes.JSON;
  }

  throw new TypeError(`Tipo de modelo IAM no soportado: ${type}`);
}
