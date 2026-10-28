import assert from "node:assert/strict";
import test from "node:test";
import { SequelizeAdapter } from "../src/adapters/index.js";

test("SequelizeAdapter reads tenants and active memberships using its native models", async () => {
  const adapter = new SequelizeAdapter({ models: {
    tenants: { async findByPk(id) { return { get: () => ({ id, name: `Tenant ${id}`, active: id !== 2 }) }; } },
    usersTenants: { async findAll(options) {
      assert.deepEqual(options, { where: { userId: "one", active: true } });
      return [1, 2].map(tenantId => ({ get: () => ({ userId: "one", tenantId }) }));
    } },
  } });
  assert.deepEqual(await adapter.findTenantById(1), { id: 1, name: "Tenant 1", active: true });
  assert.deepEqual(await adapter.findTenantsByUserId("one"), [{ id: 1, name: "Tenant 1", active: true }]);
});

test("SequelizeAdapter filters permissions with include", async () => {
  const calls = [];
  const adapter = new SequelizeAdapter({
    models: {
      usersRoles: {
        async findAll(options) {
          calls.push(["UserRole", options]);
          return [{ roleId: 1 }, { roleId: 2 }];
        }
      },
      roles: {
        async findAll(options) {
          calls.push(["Role", options]);
          return [{ id: 1 }];
        }
      },
      rolesPermissions: {
        async findAll(options) {
          calls.push(["RolePermission", options]);
          return [{ permissionId: 7, permission: { id: 7, permission: "users.list", active: true } }];
        }
      },
      permissions: {
        async findAll(options) {
          calls.push(["Permission", options]);
          return [{ get: () => ({ id: 7, permission: "users.list", active: true }) }];
        }
      }
    }
  });
  adapter.findRolesByUserId = async () => {
    throw new Error("findRolesByUserId should not be called");
  };

  const permissions = await adapter.findPermissionsByUserId("admin", "users.list");

  assert.deepEqual(permissions, [{ id: 7, permission: "users.list", active: true }]);
  assert.deepEqual(calls, [
    ["UserRole", {
      where: { userId: "admin", active: true },
      attributes: ["roleId"],
      include: [{
        model: adapter.models.roles,
        as: "role",
        where: { active: true },
        attributes: ["id"],
        required: true
      }]
    }],
    ["RolePermission", {
      where: { roleId: [1, 2], active: true },
      attributes: ["permissionId"],
      include: [{
        model: adapter.models.permissions,
        as: "permission",
        where: { active: true, permission: "users.list" },
        required: true
      }]
    }]
  ]);
});
