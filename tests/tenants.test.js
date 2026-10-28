import assert from "node:assert/strict";
import test from "node:test";
import { AsyncLocalStorage } from "node:async_hooks";
import { Seq, SQLiteAdapter, Model, DataTypes } from "seq";
import express from "express";
import { MemoryAdapter, LocalStorageAdapter, SeqAdapter } from "../src/adapters/index.js";
import { auth } from "../src/express/index.js";
import { auth as browserAuth } from "../src/browser/auth.js";

const secret = "tenant-test-secret";
const data = () => ({
  tenants: [0, 1, 2, 3, 4].map(id => ({ id, name: `Tenant ${id}`, active: id !== 4 })),
  users: [
    { id: "one", password: "old", active: true, tenantId: 1, options: { theme: "dark" } },
    { id: "two", password: "old", active: true, tenantId: 2, options: {} },
    { id: "missing", password: "old", active: true, options: {} },
  ],
  usersTenants: [0, 1, 2, 4].map(tenantId => ({ userId: "one", tenantId, active: true }))
    .concat([{ userId: "two", tenantId: 2, active: true }]),
});

async function fixture(kind, seqOptions = {}, adapterOptions = {}) {
  if (kind === "seq") {
    const seq = new Seq({ adapter: new SQLiteAdapter({ database: ":memory:" }), logging: false, ...seqOptions });
    const adapter = new SeqAdapter({ seq, tenant: true, ...adapterOptions });
    await seq.init();
    await seq.sync();
    const seed = data();
    for (const name of ["tenants", "users", "usersTenants"]) {
      for (const values of seed[name]) await adapter.models[name].create(values);
    }
    return { adapter, seq, close: () => seq.close() };
  }
  const storage = new Map();
  const local = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  const adapter = kind === "local" ? new LocalStorageAdapter({ storage: local, data: data() }) : new MemoryAdapter(data());
  return { adapter, local, close() {} };
}

async function request(adapter, method, path, body, token, config = {}, headers = {}) {
  const req = { method, path, url: path, baseUrl: "/iam", body,
    headers: { ...headers, ...(token && { authorization: `Bearer ${token}` }) } };
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; }, setHeader() {} };
  await auth({ adapter, tenant: true, jwt: { secret }, logging: false, ...config })(req, res,
    error => { if (error) throw error; res.next = true; });
  return { ...res, req };
}

async function login(adapter, username = "one", config = {}) {
  const res = await request(adapter, "POST", "/login", { username, password: "old" }, null, config);
  assert.equal(res.statusCode, 200, JSON.stringify(res.body));
  return res.body.data;
}

for (const kind of ["memory", "local", "seq"]) {
  test(`${kind}: login copies the default tenant and ignores untrusted selectors`, async t => {
    const f = await fixture(kind); t.after(f.close);
    const { adapter } = f;
    const res = await request(adapter, "POST", "/login", {
      username: "one", password: "old", tenantId: 2, options: { theme: "light", tenantId: 3 },
    }, null, {}, { "x-tenant-id": "2", tenantId: "3" });
    assert.equal(res.statusCode, 200);
    const session = res.body.data;
    assert.equal(session.tenantId, 1);
    assert.equal(session.user.tenantId, 1);
    assert.equal((await adapter.findSessionById(session.id)).tenantId, 1);
    const result = await request(adapter, "GET", "/me/tenants", undefined, session.token);
    assert.deepEqual(result.body.data.map(item => item.id).sort(), [0, 1, 2]);
    const protectedRoute = await request(adapter, "GET", "/business", undefined, session.token, {}, { "x-tenant-id": "2" });
    assert.equal(protectedRoute.req.session.tenantId, 1);
    assert.equal(protectedRoute.next, true);
    assert.equal(protectedRoute.req.session.user.password, undefined);
  });

  test(`${kind}: changing a session tenant is independent of user defaults and other sessions`, async t => {
    const { adapter, close } = await fixture(kind); t.after(close);
    const one = await login(adapter);
    const another = await login(adapter);
    const otherUser = await login(adapter, "two");
    const changed = await request(adapter, "PATCH", "/session/tenant", { tenantId: 2 }, one.token);
    assert.equal(changed.body.data.tenantId, 2);
    assert.equal((await adapter.findUserById("one")).tenantId, 1);
    assert.equal((await adapter.findSessionById(another.id)).tenantId, 1);
    assert.equal((await adapter.findSessionById(otherUser.id)).tenantId, 2);
    const defaultChanged = await request(adapter, "PATCH", "/me/tenant", { tenantId: 0 }, one.token);
    assert.equal(defaultChanged.body.data.tenantId, 0);
    assert.equal((await adapter.findSessionById(one.id)).tenantId, 2);
    assert.equal((await login(adapter)).tenantId, 0);
    const session = await request(adapter, "GET", "/session", undefined, another.token);
    assert.equal(session.body.data.tenantId, 1);
    assert.equal(session.body.data.user.tenantId, 0);
  });

  test(`${kind}: missing, inactive, unassigned or differently typed tenants fail closed`, async t => {
    const { adapter, close } = await fixture(kind); t.after(close);
    const session = await login(adapter);
    for (const path of ["/me/tenant", "/session/tenant"]) {
      for (const tenantId of [3, 4, 999, "2", null, {}, true]) {
        const res = await request(adapter, "PATCH", path, { tenantId }, session.token);
        assert.ok([400, 403].includes(res.statusCode), JSON.stringify(res.body));
        assert.match(res.body.code, /^TENANT_/);
      }
      assert.equal((await request(adapter, "PATCH", path, { tenantId: 2, userId: "two" }, session.token)).statusCode, 400);
    }
    assert.equal((await adapter.findUserById("one")).tenantId, 1);
    assert.equal((await adapter.findSessionById(session.id)).tenantId, 1);
    const missing = await request(adapter, "POST", "/login", { username: "missing", password: "old" });
    assert.equal(missing.body.code, "TENANT_REQUIRED");
    await adapter.updateSession(session.id, { tenantId: null });
    const noContext = await request(adapter, "GET", "/business", undefined, session.token);
    assert.equal(noContext.statusCode, 403);
    assert.equal(noContext.body.code, "TENANT_REQUIRED");
    assert.equal(noContext.next, undefined);
  });

  test(`${kind}: revoking assignments or deactivating a tenant blocks an existing token`, async t => {
    const { adapter, close } = await fixture(kind); t.after(close);
    const session = await login(adapter);
    if (adapter.models) await adapter.models.usersTenants.update({ active: false }, { where: { userId: "one", tenantId: 1 } });
    else adapter.usersTenants.find(item => item.userId === "one" && item.tenantId === 1).active = false;
    const denied = await request(adapter, "GET", "/session", undefined, session.token);
    assert.equal(denied.body.code, "TENANT_FORBIDDEN");
    if (adapter.models) await adapter.models.tenants.update({ active: false }, { where: { id: 1 } });
    else adapter.tenants.find(item => item.id === 1).active = false;
    assert.equal((await request(adapter, "GET", "/session", undefined, session.token)).body.code, "TENANT_UNAVAILABLE");
  });

  test(`${kind}: options updates affect only their owner and cannot change tenant or identity`, async t => {
    const { adapter, close, local } = await fixture(kind); t.after(close);
    const session = await login(adapter);
    const another = await login(adapter);
    const user = await request(adapter, "PATCH", "/me/options", { options: { language: "es" } }, session.token);
    assert.deepEqual(user.body.data.options, { theme: "dark", language: "es" });
    assert.deepEqual((await adapter.findSessionById(session.id)).options, { theme: "dark" });
    const updated = await request(adapter, "PATCH", "/session/options", { options: { theme: "light" } }, session.token);
    assert.deepEqual(updated.body.data.options, { theme: "light" });
    assert.deepEqual((await adapter.findSessionById(another.id)).options, { theme: "dark" });
    for (const path of ["/me/options", "/session/options"]) {
      for (const body of [{ options: [] }, { options: null }, { options: { tenantId: 2 } },
        { options: { nested: { tenantId: 2 } } }, JSON.parse('{"options":{"__proto__":{"polluted":true}}}'),
        { options: {}, active: false }, { options: {}, userId: "two" }]) {
        assert.equal((await request(adapter, "PATCH", path, body, session.token)).statusCode, 400);
      }
      assert.equal((await request(adapter, "PATCH", path, { options: {} })).statusCode, 401);
    }
    assert.equal((await adapter.findSessionById(session.id)).tenantId, 1);
    assert.equal((await adapter.findUserById("one")).tenantId, 1);
    assert.equal({}.polluted, undefined);
    if (kind === "local") {
      const reloaded = new LocalStorageAdapter({ storage: local });
      assert.equal((await reloaded.findTenantById(1)).name, "Tenant 1");
      assert.equal((await reloaded.findTenantsByUserId("one")).length, 3);
      assert.deepEqual((await reloaded.findUserById("one")).options, { theme: "dark", language: "es" });
    }
  });
}

test("tenant remains optional and IAM SQL models stay global", async t => {
  const adapter = new MemoryAdapter({ users: [{ id: "one", password: "old", active: true }] });
  const session = await login(adapter, "one", { tenant: false });
  assert.equal(session.tenantId, undefined);
  assert.equal((await request(adapter, "PATCH", "/session/tenant", { tenantId: 1 }, session.token, { tenant: false })).body.code, "TENANT_DISABLED");
  assert.equal((await request(adapter, "PATCH", "/session/options", { options: { theme: "light" } }, session.token, { tenant: false })).statusCode, 200);
  assert.throws(() => auth({ adapter, tenant: true, createSession: false }), /persistidas/);
  assert.throws(() => auth({ adapter, tenant: {} }), /booleano/);
  const seq = new Seq({ adapter: new SQLiteAdapter({ database: ":memory:" }), logging: false, tenant: { attribute: "empresaId" } });
  t.after(() => seq.close());
  const sql = new SeqAdapter({ seq, tenant: true });
  for (const model of Object.values(sql.models)) assert.equal(model.options.tenant, false);
  await seq.init(); await seq.sync();
  await sql.models.tenants.create({ id: 1, name: "One" });
  assert.equal((await sql.findTenantById(1)).id, 1);
  await sql.models.users.create({ id: "one", password: "old", tenantId: 1 });
  await sql.models.usersTenants.create({ userId: "one", tenantId: 1 });
  await assert.rejects(() => sql.models.usersTenants.create({ userId: "one", tenantId: 1 }));
  await assert.rejects(() => sql.models.usersTenants.create({ userId: "one", tenantId: 999 }));
});

test("basic authentication validates its reused session and request contexts stay isolated", async t => {
  const { adapter, close } = await fixture("seq"); t.after(close);
  const storage = new AsyncLocalStorage();
  const config = { getContext: () => storage.getStore() };
  const one = await login(adapter), two = await login(adapter, "two");
  await Promise.all([[one, 1], [two, 2]].map(([session, tenantId]) => storage.run({ txId: `tx-${tenantId}` }, async () => {
    await new Promise(resolve => setImmediate(resolve));
    const res = await request(adapter, "GET", "/business", undefined, session.token, config, { "x-tenant-id": "999" });
    assert.equal(res.req.session.tenantId, tenantId);
    assert.deepEqual(storage.getStore(), { txId: `tx-${tenantId}`, tenantId });
  })));
  const basic = { authorization: `Basic ${Buffer.from("one:old").toString("base64")}` };
  const first = await storage.run({}, () => request(adapter, "GET", "/business", undefined, null, config, basic));
  assert.equal(first.req.session.tenantId, 1);
  await adapter.updateSession(first.req.session.id, { tenantId: 3 });
  const denied = await request(adapter, "GET", "/business", undefined, null, config, basic);
  assert.equal(denied.body.code, "TENANT_FORBIDDEN");
  const missing = await request(adapter, "GET", "/business", undefined, two.token, config);
  assert.equal(missing.statusCode, 403);
  assert.equal(missing.body.code, "TENANT_CONTEXT_MISSING");
  assert.equal(missing.next, undefined);
  assert.equal(storage.getStore(), undefined);
});

test("browser options and tenant methods persist updated public state without losing the token", async t => {
  const { adapter, close } = await fixture("memory"); t.after(close);
  const storage = new Map();
  browserAuth.configure({ baseUrl: "/iam", storage: { getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) } });
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    const res = await request(adapter, init.method || "GET", url.slice(4), init.body && JSON.parse(init.body),
      init.headers?.Authorization?.slice(7));
    return { ok: res.statusCode < 400, status: res.statusCode, json: async () => res.body };
  });
  const session = await browserAuth.login({ username: "one", password: "old" });
  assert.equal((await browserAuth.getTenants()).length, 3);
  await browserAuth.updateUserOptions({ language: "es" });
  await browserAuth.updateSessionOptions({ theme: "light" });
  await browserAuth.setUserTenant(2);
  assert.equal(browserAuth.getSession().tenantId, 1);
  await assert.rejects(() => browserAuth.setSessionTenant(3), { code: "TENANT_FORBIDDEN", status: 403 });
  assert.equal(browserAuth.getSession().tenantId, 1);
  const changed = await browserAuth.setSessionTenant(2);
  assert.equal(changed.tenantId, 2);
  assert.equal(changed.token, session.token);
  assert.equal(changed.user.tenantId, 2);
  assert.deepEqual(changed.options, { theme: "light" });
  browserAuth.configure({});
  assert.equal(browserAuth.getSession().tenantId, 2);
  await browserAuth.logout();
});

test("HTTP authentication supplies Seq's context and isolates business data with a different tenant attribute", async t => {
  const storage = new AsyncLocalStorage();
  const getContext = () => storage.getStore();
  class Invoice extends Model {}
  Invoice.init({ id: { type: DataTypes.INTEGER, primaryKey: true }, codEmpresa: { type: DataTypes.INTEGER },
    name: { type: DataTypes.STRING(50) } }, { modelName: "Invoice", tableName: "invoices", timestamps: false, tenant: true });
  const { adapter, close } = await fixture("seq", { models: [Invoice], getContext, tenant: { attribute: "codEmpresa" } });
  t.after(close);
  await storage.run({ tenantId: 1 }, () => Invoice.create({ id: 1, name: "Company one" }));
  await storage.run({ tenantId: 2 }, () => Invoice.create({ id: 2, name: "Company two" }));
  await assert.rejects(() => Invoice.findAll(), { code: "SEQ_TENANT_CONTEXT_MISSING" });
  const app = express();
  app.use(express.json());
  app.use((_req, _res, next) => storage.run({}, next));
  app.use("/iam", auth({ adapter, tenant: true, getContext, jwt: { secret }, logging: false }));
  app.get("/iam/business", async (_req, res, next) => {
    try { res.json({ ok: true, data: await Invoice.findAll({ plain: true }) }); } catch (error) { next(error); }
  });
  const server = await new Promise(resolve => { const listener = app.listen(0, "127.0.0.1", () => resolve(listener)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/iam`;
  async function call(path, { method = "GET", token, body } = {}) {
    const response = await fetch(base + path, { method,
      headers: { "Content-Type": "application/json", "x-tenant-id": "999", ...(token && { Authorization: `Bearer ${token}` }) },
      ...(body && { body: JSON.stringify(body) }) });
    assert.equal(response.status, 200);
    return (await response.json()).data;
  }
  const first = await call("/login", { method: "POST", body: { username: "one", password: "old" } });
  const second = await call("/login", { method: "POST", body: { username: "two", password: "old" } });
  const [a, b] = await Promise.all([call("/business", { token: first.token }), call("/business", { token: second.token })]);
  assert.deepEqual(a, [{ id: 1, codEmpresa: 1, name: "Company one" }]);
  assert.deepEqual(b, [{ id: 2, codEmpresa: 2, name: "Company two" }]);
  await call("/session/tenant", { method: "PATCH", token: first.token, body: { tenantId: 2 } });
  assert.deepEqual(await call("/business", { token: first.token }), b);
  assert.equal((await adapter.findUserById("one")).tenantId, 1);
});

test("login publishes the validated tenant before session audit hooks and rejects an absent request context", async t => {
  const storage = new AsyncLocalStorage();
  const getContext = () => storage.getStore();
  class Audit extends Model {}
  Audit.init({ id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true }, tenantId: { type: DataTypes.INTEGER },
    action: { type: DataTypes.STRING(50) } }, { modelName: "Audit", tableName: "audit", timestamps: false, tenant: true });
  const { adapter, close } = await fixture("seq", { models: [Audit], getContext, tenant: { attribute: "tenantId" } },
    { auditable: change => Audit.create({ action: change.action }) });
  t.after(close);
  const missing = await request(adapter, "POST", "/login", { username: "one", password: "old" }, null, { getContext });
  assert.equal(missing.statusCode, 403);
  assert.equal(missing.body.code, "TENANT_CONTEXT_MISSING");
  assert.equal(await adapter.models.sessions.count(), 0);
  for (const [username, tenantId] of [["one", 1], ["two", 2]]) {
    await storage.run({ txId: `tx-${tenantId}` }, async () => {
      const session = await login(adapter, username, { getContext });
      assert.equal(session.tenantId, tenantId);
      assert.deepEqual(storage.getStore(), { txId: `tx-${tenantId}`, tenantId });
      const audits = await Audit.findAll({ plain: true });
      assert.equal(audits.length, 2);
      assert.ok(audits.every(item => item.tenantId === tenantId));
    });
  }
});
