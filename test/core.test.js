import assert from "node:assert/strict";
import test from "node:test";
import { MemoryAdapter, RBAC } from "../src/index.js";

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

test("RBAC checks roles and permissions", async () => {
  const rbac = new RBAC({ adapter: createAdapter() });

  assert.equal(await rbac.hasRole("admin", "admin"), true);
  assert.equal(await rbac.hasRole("admin", "guest"), false);
  assert.equal(await rbac.can("admin", "users.list"), true);
  assert.equal(await rbac.can("admin", "users.delete"), false);
});

test("RBAC passes permission filter to adapter", async () => {
  let requestedPermission;
  const adapter = {
    async findRolesByUserId() {
      return [];
    },
    async findPermissionsByUserId(userId, permission) {
      requestedPermission = permission;
      assert.equal(userId, "admin");
      return [{ id: 1, permission: "users.list", active: true }];
    }
  };
  const rbac = new RBAC({ adapter });

  assert.equal(await rbac.can("admin", "users.list"), true);
  assert.equal(requestedPermission, "users.list");
});

test("RBAC getPermissions keeps full-list behavior", async () => {
  const rbac = new RBAC({ adapter: createAdapter() });

  assert.deepEqual(
    (await rbac.getPermissions("admin")).map((item) => item.permission),
    ["users.list"]
  );
});
