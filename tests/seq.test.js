import assert from "node:assert/strict";
import test from "node:test";
import { Seq, SQLiteAdapter } from "seq";
import { SeqAdapter } from "../src/adapters/index.js";
import { auth, can } from "../src/express/index.js";

test("SeqAdapter works with in-memory sqlite", async () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const adapter = new SeqAdapter({ seq });

  try {
    await seq.init();
    await seq.sync();
    await seed(adapter.models);

    const session = await adapter.createSession({
      id: "session-1",
      userId: "admin",
      token: null,
      options: { empresa: 1 },
      active: true
    });

    assert.equal(session.userId, "admin");
    assert.deepEqual(session.options, { empresa: 1 });

    const permissions = await adapter.findPermissionsByUserId("admin");
    assert.deepEqual(permissions.map((item) => item.permission), ["users.list"]);

    const active = await adapter.findActiveSessionByUserId("admin");
    assert.equal(active.id, session.id);

    await adapter.updateSession(session.id, { token: "session-token" });
    assert.equal((await adapter.findSessionByToken("session-token")).id, session.id);

    await adapter.deactivateSession(session.id);
    assert.equal((await adapter.findSessionById(session.id)).active, false);
  } finally {
    await seq.close();
  }
});

test("SeqAdapter accepts custom IAM table names", () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const adapter = new SeqAdapter({
    seq,
    tableNames: {
      users: "iam_users",
      roles: "iam_roles",
      permissions: "iam_permissions",
      usersRoles: "iam_user_roles",
      rolesPermissions: "iam_role_permissions",
      sessions: "iam_sessions"
    }
  });

  assert.equal(adapter.models.users.tableName, "iam_users");
  assert.equal(adapter.models.roles.tableName, "iam_roles");
  assert.equal(adapter.models.permissions.tableName, "iam_permissions");
  assert.equal(adapter.models.usersRoles.tableName, "iam_user_roles");
  assert.equal(adapter.models.rolesPermissions.tableName, "iam_role_permissions");
  assert.equal(adapter.models.sessions.tableName, "iam_sessions");
});

test("SeqAdapter can emit auditable session changes", async () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const changes = [];
  const adapter = new SeqAdapter({ seq, auditable: { tableName: "iam_sessions", write: (change) => changes.push(change) } });

  try {
    await seq.init();
    await seq.sync();
    await adapter.models.users.create({
      id: "admin",
      password: "1234",
      name: "Administrador",
      email: "admin@app.com",
      options: {},
      active: true
    });

    const session = await adapter.createSession({
      id: "session-1",
      userId: "admin",
      token: null,
      options: {},
      active: true
    });
    await adapter.updateSession(session.id, { token: "session-token" });
    await adapter.deactivateSession(session.id);

    assert.deepEqual(changes.map((change) => change.action), ["create", "update", "update"]);
    assert.deepEqual(changes.map((change) => change.tableName), ["iam_sessions", "iam_sessions", "iam_sessions"]);
    assert.equal(changes[0].rowId, "session-1");
    assert.deepEqual(changes[0].old, {});
    assert.equal(changes[0].new.userId, "admin");
    assert.equal(changes[1].old.token, null);
    assert.equal(changes[1].new.token, "session-token");
    assert.equal(changes[2].old.active, true);
    assert.equal(changes[2].new.active, false);
  } finally {
    await seq.close();
  }
});

test("SeqAdapter defines IAM foreign key references", async () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const adapter = new SeqAdapter({ seq });

  try {
    await seq.init();
    await seq.sync();

    assertReferences(seq, "usersRoles", [
      ["userId", "users", "id"],
      ["roleId", "roles", "id"]
    ]);
    assertReferences(seq, "rolesPermissions", [
      ["roleId", "roles", "id"],
      ["permissionId", "permissions", "id"]
    ]);
    assertReferences(seq, "sessions", [["userId", "users", "id"]]);
  } finally {
    await seq.close();
  }
});

test("SeqAdapter associates IAM models", () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const { models } = new SeqAdapter({ seq });

  assertAssociation(models.users, "usersRoles", "hasMany", models.usersRoles, "userId");
  assertAssociation(models.users, "sessions", "hasMany", models.sessions, "userId");
  assertAssociation(models.users, "roles", "belongsToMany", models.roles, "userId", "roleId");

  assertAssociation(models.roles, "usersRoles", "hasMany", models.usersRoles, "roleId");
  assertAssociation(models.roles, "rolesPermissions", "hasMany", models.rolesPermissions, "roleId");
  assertAssociation(models.roles, "users", "belongsToMany", models.users, "roleId", "userId");
  assertAssociation(models.roles, "permissions", "belongsToMany", models.permissions, "roleId", "permissionId");

  assertAssociation(models.permissions, "rolesPermissions", "hasMany", models.rolesPermissions, "permissionId");
  assertAssociation(models.permissions, "roles", "belongsToMany", models.roles, "permissionId", "roleId");

  assertAssociation(models.usersRoles, "user", "belongsTo", models.users, "userId");
  assertAssociation(models.usersRoles, "role", "belongsTo", models.roles, "roleId");
  assertAssociation(models.rolesPermissions, "role", "belongsTo", models.roles, "roleId");
  assertAssociation(models.rolesPermissions, "permission", "belongsTo", models.permissions, "permissionId");
  assertAssociation(models.sessions, "user", "belongsTo", models.users, "userId");
});

test("SeqAdapter filters permissions with include", async () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const adapter = new SeqAdapter({ seq });

  try {
    await seq.init();
    await seq.sync();
    await seedPermissionFiltering(adapter.models);
    const calls = [];
    const rolePermissionFindAll = adapter.models.rolesPermissions.findAll.bind(adapter.models.rolesPermissions);
    adapter.models.rolesPermissions.findAll = (options) => {
      calls.push(["RolePermission", options]);
      return rolePermissionFindAll(options);
    };

    assert.deepEqual(
      (await adapter.findPermissionsByUserId("admin")).map((item) => item.permission).sort(),
      ["users.create", "users.list"]
    );
    assert.deepEqual(
      (await adapter.findPermissionsByUserId("admin", "users.list")).map((item) => item.permission),
      ["users.list"]
    );
    assert.deepEqual(await adapter.findPermissionsByUserId("admin", "users.delete"), []);
    assert.ok(calls.every(([model]) => model === "RolePermission"));
    assert.ok(calls.some(([, options]) => includedModels(options).includes(adapter.models.permissions)));
    assert.ok(calls.some(([, options]) => includedModels(options).includes(adapter.models.roles)));
    assert.ok(calls.some(([, options]) => nestedIncludedModels(options).includes(adapter.models.usersRoles)));
  } finally {
    await seq.close();
  }
});

test("express middleware can use SeqAdapter", async () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const adapter = new SeqAdapter({ seq });

  try {
    await seq.init();
    await seq.sync();
    await seed(adapter.models);

    const req = {
      headers: {
        authorization: `Basic ${Buffer.from("admin:1234").toString("base64")}`
      }
    };
    const res = createResponse();
    let allowed = false;

    await auth({ strategy: "basic", adapter })(req, res, async () => {
      await can("users.list")(req, res, () => {
        allowed = true;
      });
    });

    assert.equal(allowed, true);
    assert.equal(req.session.user.id, "admin");
  } finally {
    await seq.close();
  }
});

async function seed(models) {
  await models.users.create({
    id: "admin",
    password: "1234",
    name: "Administrador",
    email: "admin@app.com",
    options: {},
    active: true
  });
  const role = await models.roles.create({ role: "admin", active: true });
  const permission = await models.permissions.create({
    permission: "users.list",
    title: "List users",
    active: true
  });

  await models.usersRoles.create({
    userId: "admin",
    roleId: role.getDataValue("id"),
    active: true
  });
  await models.rolesPermissions.create({
    roleId: role.getDataValue("id"),
    permissionId: permission.getDataValue("id"),
    active: true
  });
}

async function seedPermissionFiltering(models) {
  await models.users.create({
    id: "admin",
    password: "1234",
    name: "Administrador",
    email: "admin@app.com",
    options: {},
    active: true
  });
  await models.users.create({
    id: "other",
    password: "1234",
    name: "Otro",
    email: "other@app.com",
    options: {},
    active: true
  });
  const adminRole = await models.roles.create({ role: "admin", active: true });
  const editorRole = await models.roles.create({ role: "editor", active: true });
  const inactiveRole = await models.roles.create({ role: "inactive", active: false });
  const otherRole = await models.roles.create({ role: "other", active: true });
  const listPermission = await models.permissions.create({
    permission: "users.list",
    title: "List users",
    active: true
  });
  const createPermission = await models.permissions.create({
    permission: "users.create",
    title: "Create users",
    active: true
  });
  const inactivePermission = await models.permissions.create({
    permission: "users.inactive",
    title: "Inactive role permission",
    active: true
  });
  const otherPermission = await models.permissions.create({
    permission: "users.other",
    title: "Other user permission",
    active: true
  });

  await models.usersRoles.create({
    userId: "admin",
    roleId: adminRole.getDataValue("id"),
    active: true
  });
  await models.usersRoles.create({
    userId: "admin",
    roleId: editorRole.getDataValue("id"),
    active: true
  });
  await models.usersRoles.create({
    userId: "admin",
    roleId: inactiveRole.getDataValue("id"),
    active: true
  });
  await models.usersRoles.create({
    userId: "other",
    roleId: otherRole.getDataValue("id"),
    active: true
  });
  await models.rolesPermissions.create({
    roleId: adminRole.getDataValue("id"),
    permissionId: listPermission.getDataValue("id"),
    active: true
  });
  await models.rolesPermissions.create({
    roleId: editorRole.getDataValue("id"),
    permissionId: createPermission.getDataValue("id"),
    active: true
  });
  await models.rolesPermissions.create({
    roleId: inactiveRole.getDataValue("id"),
    permissionId: inactivePermission.getDataValue("id"),
    active: true
  });
  await models.rolesPermissions.create({
    roleId: otherRole.getDataValue("id"),
    permissionId: otherPermission.getDataValue("id"),
    active: true
  });
}

function assertAssociation(model, name, type, target, foreignKey, otherKey) {
  const association = model.associations[name];

  assert.equal(association.type, type);
  assert.equal(association.target, target);
  assert.equal(association.foreignKey, foreignKey);
  if (otherKey) assert.equal(association.otherKey, otherKey);
}

function includedModels(options) {
  return asArray(options.include).map((include) => include?.model);
}

function nestedIncludedModels(options) {
  return asArray(options.include).flatMap((include) => asArray(include?.include).map((nested) => nested?.model));
}

function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function assertReferences(seq, modelName, expected) {
  const tableName = seq.models[modelName]._resolvedTableName;
  const schema = seq.adapter.schemas.get(tableName);
  const foreignKeys = schema.foreignKeys.map((fk) => [
    fk.attributeName,
    fk.references.model,
    fk.references.key
  ]);

  assert.deepEqual(foreignKeys, expected);
}

function createResponse() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    }
  };
}

function createApp() {
  return {
    get() {
      return this;
    },
    post() {
      return this;
    }
  };
}
