import assert from "node:assert/strict";
import test from "node:test";
import { /*Auth, */createAuth, MemoryAdapter, RBAC, SessionInactiveError } from "../src/index.js";

function createAdapter() {
  return new MemoryAdapter({
    users: [
      {
        id: "admin",
        password: "1234",
        name: "Administrador",
        email: "admin@app.com",
        options: {},
        active: true
      }
    ],
    roles: [
      { id: 1, role: "admin", active: true }
    ],
    permissions: [
      { id: 1, permission: "users.list", title: "List users", active: true }
    ],
    userRoles: [
      { id: 1, userId: "admin", roleId: 1, active: true }
    ],
    rolePermissions: [
      { id: 1, roleId: 1, permissionId: 1, active: true }
    ]
  });
}

test("Auth login returns a public session", async () => {
  //const adapter = createAdapter();
  //const auth = new Auth({ adapter });
  const auth = createAuth(createAdapter());
  const session = await auth.login({
    username: "admin",
    password: "1234",
    options: { empresa: 1, sucursal: 2 }
  });

  assert.equal(typeof session.id, "string");
  assert.deepEqual(session.user, {
    id: "admin",
    name: "Administrador",
    email: "admin@app.com",
    options: {}
  });
  assert.deepEqual(session.options, { empresa: 1, sucursal: 2 });
  assert.equal(session.user.password, undefined);
});

test("Auth logout deactivates a session", async () => {
  //const adapter = createAdapter();
  //const auth = new Auth({ adapter });
  const auth = createAuth(createAdapter());
  const session = await auth.login({ username: "admin", password: "1234" });

  await auth.logout(session.id);

  await assert.rejects(() => auth.getSession(session.id), {
    name: "SessionInactiveError",
    status: 401,
    code: "SESSION_INACTIVE",
    message: new SessionInactiveError().message
  });
});

test("RBAC checks roles and permissions", async () => {
  const rbac = new RBAC({ adapter: createAdapter() });

  assert.equal(await rbac.hasRole("admin", "admin"), true);
  assert.equal(await rbac.hasRole("admin", "guest"), false);
  assert.equal(await rbac.can("admin", "users.list"), true);
  assert.equal(await rbac.can("admin", "users.delete"), false);
});
