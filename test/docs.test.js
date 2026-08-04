import assert from "node:assert/strict";
import test from "node:test";
import { filterOpenApiByPermissions, filterPostmanByPermissions } from "../src/docs/index.js";
import { can } from "../src/express/index.js";

test("can exposes permission metadata for documentation tools", () => {
  const middleware = can("users.list");

  assert.equal(middleware.permission, "users.list");
  assert.deepEqual(middleware.permissions, ["users.list"]);
  assert.deepEqual(middleware.iam, {
    permission: "users.list",
    permissions: ["users.list"]
  });
});

test("filterOpenApiByPermissions hides operations without granted permissions", () => {
  const spec = {
    openapi: "3.0.0",
    paths: {
      "/public": {
        get: { responses: {} }
      },
      "/users": {
        get: { "x-permission": "users.list", responses: {} },
        post: { "x-permission": "users.create", responses: {} }
      },
      "/admin": {
        "x-permissions": ["admin.access"],
        get: { responses: {} }
      }
    }
  };

  const filtered = filterOpenApiByPermissions(spec, ["users.list"]);

  assert.ok(filtered.paths["/public"].get);
  assert.ok(filtered.paths["/users"].get);
  assert.equal(filtered.paths["/users"].post, undefined);
  assert.equal(filtered.paths["/admin"], undefined);
  assert.ok(spec.paths["/users"].post);
});

test("filterPostmanByPermissions hides items without granted permissions", () => {
  const collection = {
    info: { name: "API" },
    item: [
      { name: "Public", request: { method: "GET", url: "/public" } },
      { name: "List users", "x-permission": "users.list", request: { method: "GET", url: "/users" } },
      { name: "Create users", request: { method: "POST", url: "/users", "x-permission": "users.create" } },
      {
        name: "Admin",
        "x-permission": "admin.access",
        item: [
          { name: "Dashboard", request: { method: "GET", url: "/admin" } }
        ]
      }
    ]
  };

  const filtered = filterPostmanByPermissions(collection, [{ permission: "users.list", id: 1 }]);

  assert.deepEqual(filtered.item.map((item) => item.name), ["Public", "List users"]);
  assert.equal(collection.item.length, 4);
});
