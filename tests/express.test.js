import assert from "node:assert/strict";
import test from "node:test";
import { SignJWT } from "jose";
import { MemoryAdapter } from "../src/adapters/index.js";
import { auth, can } from "../src/express/index.js";
import { getContext } from "../src/express/context.js";

const secret = "secret";

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

test("auth returns middleware for app.use", () => {
  const middleware = auth({ adapter: createAdapter(), jwt: { secret, expiresIn: "1h" } });

  assert.equal(typeof middleware, "function");
});

test("auth challenges missing credentials", async () => {
  const req = createRequest({ method: "GET", path: "/users" });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.headers["WWW-Authenticate"], "Basic realm=\"IAM\"");
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "Token requerido");
  assert.equal(typeof res.body.stack, "string");
});

test("basic auth allows a permitted request", async () => {
  const req = createRequest({
    method: "GET",
    path: "/users",
    headers: {
      authorization: basic("admin", "1234")
    }
  });
  const res = createResponse();
  let allowed = false;

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, async () => {
    await can("users.list")(req, res, () => {
      allowed = true;
    });
  });

  assert.equal(allowed, true);
  assert.equal(req.session.user.id, "admin");
  assert.deepEqual(req.session.permissions, ["users.list"]);
});

test("application list responses use data as the collection", async () => {
  const req = createRequest({
    method: "GET",
    path: "/users",
    headers: {
      authorization: basic("admin", "1234")
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, async () => {
    await can("users.list")(req, res, () => {
      res.json({
        ok: true,
        data: [
          { id: "admin", name: "Administrador", email: "admin@app.com" }
        ]
      });
    });
  });

  assert.deepEqual(res.body, {
    ok: true,
    data: [
      { id: "admin", name: "Administrador", email: "admin@app.com" }
    ]
  });
});

test("basic auth rejects invalid credentials", async () => {
  const req = createRequest({
    method: "GET",
    path: "/users",
    headers: {
      authorization: basic("admin", "wrong")
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.headers["WWW-Authenticate"], "Basic realm=\"IAM\"");
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "Credenciales inválidas");
  assert.equal(typeof res.body.stack, "string");
});

test("post login returns json details for invalid credentials", async () => {
  const req = createRequest({
    method: "POST",
    path: "/login",
    body: {
      username: "admin",
      password: "wrong"
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "Credenciales inválidas");
  assert.equal(typeof res.body.stack, "string");
});

test("post login returns json details for missing credentials", async () => {
  const req = createRequest({
    method: "POST",
    path: "/login",
    body: {
      username: "admin"
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "Usuario y clave son necesarios");
  assert.equal(typeof res.body.stack, "string");
});

test("post login forwards internal errors to next", async () => {
  const error = new Error("database down");
  const adapter = {
    ...createAdapter(),
    async findUserByUsername() {
      throw error;
    }
  };
  const req = createRequest({
    method: "POST",
    path: "/login",
    body: {
      username: "admin",
      password: "1234"
    }
  });
  const res = createResponse();
  let forwarded = null;

  await auth({ adapter, jwt: { secret } })(req, res, (err) => {
    forwarded = err;
  });

  assert.equal(forwarded, error);
  assert.equal(res.body, null);
});

test("post login returns public session with jwt token and expiresIn", async () => {
  const adapter = createAdapter();
  const req = createRequest({
    method: "POST",
    path: "/login",
    body: {
      username: "admin",
      password: "1234",
      options: { empresa: 2 }
    }
  });
  const res = createResponse();

  await auth({ adapter, jwt: { secret, expiresIn: "1h" } })(req, res, () => {});

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.data.user.id, "admin");
  assert.deepEqual(res.body.data.permissions, ["users.list"]);
  assert.deepEqual(res.body.data.options, { empresa: 2 });
  assert.equal(typeof res.body.data.token, "string");
  assert.equal(res.body.data.expiresIn, 3600);
});

test("get session accepts bearer jwt tokens", async () => {
  const adapter = createAdapter();
  const login = await loginWithPassword(adapter);
  const req = createRequest({
    method: "GET",
    path: "/session",
    headers: {
      authorization: `Bearer ${login.body.data.token}`
    }
  });
  const res = createResponse();

  await auth({ adapter, jwt: { secret, expiresIn: "1h" } })(req, res, () => {});

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.data.id, login.body.data.id);
  assert.equal(res.body.data.user.id, "admin");
  assert.deepEqual(res.body.data.permissions, ["users.list"]);
});

test("expired jwt tokens are rejected", async () => {
  const token = await new SignJWT({ sessionId: "session-1" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(Math.floor(Date.now() / 1000) - 120)
    .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
    .sign(new TextEncoder().encode(secret));
  const req = createRequest({
    method: "GET",
    path: "/session",
    headers: {
      authorization: `Bearer ${token}`
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.headers["WWW-Authenticate"], undefined);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "Token inválido");
  assert.equal(typeof res.body.stack, "string");
});

test("invalid jwt tokens are rejected", async () => {
  const req = createRequest({
    method: "GET",
    path: "/session",
    headers: {
      authorization: "Bearer invalid"
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.headers["WWW-Authenticate"], undefined);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "Token inválido");
  assert.equal(typeof res.body.stack, "string");
});

test("post logout deactivates the current session", async () => {
  const adapter = createAdapter();
  const login = await loginWithPassword(adapter);
  const req = createRequest({
    method: "POST",
    path: "/logout",
    headers: {
      authorization: `Bearer ${login.body.data.token}`
    }
  });
  const res = createResponse();

  await auth({ adapter, jwt: { secret } })(req, res, () => {});

  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { ok: true, data: {} });
  assert.equal((await adapter.findSessionById(login.body.data.id)).active, false);
});

test("can rejects missing permissions", async () => {
  const req = createRequest({
    method: "GET",
    path: "/users",
    headers: {
      authorization: basic("admin", "1234")
    }
  });
  const res = createResponse();

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, async () => {
    await can("users.delete")(req, res, () => {});
  });

  assert.equal(res.statusCode, 403);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.message, "No tiene permisos para realizar esta acción");
  assert.equal(typeof res.body.stack, "string");
});

test("can forwards internal errors to next", async () => {
  const error = new Error("rbac unavailable");
  const req = createRequest({
    method: "GET",
    path: "/users",
    headers: {
      authorization: basic("admin", "1234")
    }
  });
  const res = createResponse();
  let forwarded = null;

  await auth({ adapter: createAdapter(), jwt: { secret } })(req, res, async () => {
    getContext(req).rbac.can = async () => {
      throw error;
    };

    await can("users.list")(req, res, (err) => {
      forwarded = err;
    });
  });

  assert.equal(forwarded, error);
  assert.equal(res.body, null);
});

async function loginWithPassword(adapter) {
  const req = createRequest({
    method: "POST",
    path: "/login",
    body: {
      username: "admin",
      password: "1234"
    }
  });
  const res = createResponse();

  await auth({ adapter, jwt: { secret, expiresIn: "1h" } })(req, res, () => {});
  return res;
}

function createRequest({ method, path, headers = {}, body = undefined } = {}) {
  return {
    method,
    path,
    url: path,
    headers,
    body
  };
}

function createResponse() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    setHeader(name, value) {
      this.headers[name] = value;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
    end() {
      return this;
    }
  };
}

function basic(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
}
