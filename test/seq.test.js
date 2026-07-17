import assert from "node:assert/strict";
import test from "node:test";
import { Seq, SQLiteAdapter } from "seq";
import { SeqAdapter } from "../src/adapters/index.js";
import { Auth, auth, can } from "../src/express/index.js";

test("SeqAdapter works with in-memory sqlite", async () => {
  const sqlite = new SQLiteAdapter({ database: ":memory:" });
  const seq = new Seq({ adapter: sqlite, logging: false });
  const adapter = new SeqAdapter({ seq });

  try {
    await seq.init();
    await seq.sync();
    await seed(adapter.models);

    const service = new Auth({ adapter });
    const session = await service.login({
      username: "admin@app.com",
      password: "1234",
      options: { empresa: 1 }
    });

    assert.equal(session.user.id, "admin");
    assert.deepEqual(session.options, { empresa: 1 });

    const permissions = await adapter.findPermissionsByUserId("admin");
    assert.deepEqual(permissions.map((item) => item.permission), ["users.list"]);

    const active = await adapter.findActiveSessionByUserId("admin");
    assert.equal(active.id, session.id);

    await adapter.updateSession(session.id, { token: "session-token" });
    assert.equal((await adapter.findSessionByToken("session-token")).id, session.id);

    await service.logout(session.id);
    assert.equal((await adapter.findSessionById(session.id)).active, false);
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
  await models.User.create({
    id: "admin",
    password: "1234",
    name: "Administrador",
    email: "admin@app.com",
    options: {},
    active: true
  });
  const role = await models.Role.create({ role: "admin", active: true });
  const permission = await models.Permission.create({
    permission: "users.list",
    title: "List users",
    active: true
  });

  await models.UserRole.create({
    userId: "admin",
    roleId: role.getDataValue("id"),
    active: true
  });
  await models.RolePermission.create({
    roleId: role.getDataValue("id"),
    permissionId: permission.getDataValue("id"),
    active: true
  });
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
