import assert from "node:assert/strict";
import test from "node:test";

test("package exports expose root, adapters and express subpaths", async () => {
  const root = await import("iam");
  const adapters = await import("iam/adapters");
  const express = await import("iam/express");

  assert.equal(typeof root.RBAC, "function");
  assert.equal(typeof adapters.SeqAdapter, "function");
  assert.equal(typeof express.auth, "function");
  assert.equal(typeof express.verifyJwt, "function");
  assert.equal(typeof express.createPasswordReset, "function");
});

test("published package generates a reset link consumed by its middleware", async () => {
  const { MemoryAdapter } = await import("iam/adapters");
  const { auth, createPasswordReset } = await import("iam/express");
  const adapter = new MemoryAdapter({ users: [{ id: "user", password: "old", active: true }] });
  const { url } = await createPasswordReset({ adapter, userId: "user", resetUrl: "https://example.com/reset" });
  const res = {
    json(value) { this.body = value; return this; },
    status(value) { this.statusCode = value; return this; },
    setHeader() {}
  };
  const middleware = auth({ adapter, logging: false });
  const req = { method: "POST", path: "/reset-password", body: { token: new URL(url).searchParams.get("token"), password: "new" } };
  await middleware(req, res, error => { if (error) throw error; });
  assert.equal(res.body.ok, true);
  assert.equal((await adapter.findUserById("user")).password, "new");
  await middleware(req, res, error => { if (error) throw error; });
  assert.equal(res.statusCode, 401);
});

test("published tenant middleware validates and persists the current session selection", async () => {
  const { MemoryAdapter } = await import("iam/adapters");
  const { auth } = await import("iam/express");
  const adapter = new MemoryAdapter({
    users: [{ id: "user", password: "old", tenantId: 1, active: true }],
    tenants: [{ id: 1, name: "One", active: true }, { id: 2, name: "Two", active: true }],
    usersTenants: [{ userId: "user", tenantId: 1, active: true }, { userId: "user", tenantId: 2, active: true }],
  });
  const middleware = auth({ adapter, tenant: true, logging: false, jwt: { secret: "test-secret" } });
  const res = { statusCode: 200, json(body) { this.body = body; return this; }, status(value) { this.statusCode = value; return this; } };
  const next = error => { if (error) throw error; };
  await middleware({ method: "POST", path: "/login", body: { username: "user", password: "old" }, headers: {} }, res, next);
  assert.equal(res.body.data.tenantId, 1);
  const session = res.body.data;
  await middleware({ method: "PATCH", path: "/session/tenant", body: { tenantId: 2 }, headers: { authorization: `Bearer ${session.token}` } }, res, next);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.data.tenantId, 2);
  assert.equal((await adapter.findSessionById(session.id)).tenantId, 2);
  assert.equal((await adapter.findUserById("user")).tenantId, 1);
});
