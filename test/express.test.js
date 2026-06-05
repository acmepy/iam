import assert from "node:assert/strict";
import test from "node:test";
import { MemoryAdapter } from "../src/adapters/index.js";
import { auth, can, signJwt } from "../src/express/index.js";

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
    ],
    sessions: [
      {
        id: "session-1",
        userId: "admin",
        token: null,
        options: { empresa: 1 },
        active: true
      }
    ]
  });
}

test("express auth accepts jwt bearer tokens", async () => {
  const secret = "secret";
  const token = signJwt({ sessionId: "session-1" }, secret);
  const req = {
    headers: {
      authorization: `Bearer ${token}`
    }
  };
  const res = createResponse();
  let called = false;

  await auth({ strategy: "jwt", secret, adapter: createAdapter() })(req, res, () => {
    called = true;
  });

  assert.equal(called, true);
  assert.equal(req.session.id, "session-1");
  assert.equal(req.session.user.id, "admin");
});

test("express can allows a permitted request", async () => {
  const req = {
    headers: {
      authorization: `Basic ${Buffer.from("admin:1234").toString("base64")}`
    }
  };
  const res = createResponse();
  const adapter = createAdapter();
  let allowed = false;

  await auth({ strategy: "basic", adapter })(req, res, async () => {
    await can("users.list")(req, res, () => {
      allowed = true;
    });
  });

  assert.equal(allowed, true);
});

test("express can rejects a missing permission", async () => {
  const req = {
    headers: {
      authorization: `Basic ${Buffer.from("admin:1234").toString("base64")}`
    }
  };
  const res = createResponse();
  const adapter = createAdapter();

  await auth({ strategy: "basic", adapter })(req, res, async () => {
    await can("users.delete")(req, res, () => {});
  });

  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, {
    error: "No tiene permisos para realizar esta acción",
    code: "FORBIDDEN"
  });
});

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
