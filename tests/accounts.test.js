import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { Seq, SQLiteAdapter } from "seq";
import { MemoryAdapter, LocalStorageAdapter, SeqAdapter } from "../src/adapters/index.js";
import { auth, createPasswordReset } from "../src/express/index.js";
import { auth as browserAuth } from "../src/browser/auth.js";

const secret = "test-secret";
async function request(adapter, method, path, body, token, options = {}) {
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
    setHeader() {}
  };
  await auth({ adapter, jwt: { secret }, logging: false, ...options })(
    { method, path, url: path, baseUrl: "/iam", body, headers: token ? { authorization: `Bearer ${token}` } : {} },
    res, error => { if (error) throw error; res.next = true; }
  );
  return res;
}

async function login(adapter, id, password = "old") {
  const res = await request(adapter, "POST", "/login", { username: id, password });
  assert.equal(res.statusCode, 200);
  return res.body.data.token;
}

async function fixture(kind) {
  let adapter, seq;
  if (kind === "seq") {
    seq = new Seq({ adapter: new SQLiteAdapter({ database: ":memory:" }), logging: false });
    adapter = new SeqAdapter({ seq });
    await seq.init();
    await seq.sync();
  } else {
    adapter = new MemoryAdapter();
  }
  await adapter.createUser({ id: "one", name: "One", email: "shared@example.com", password: "old", active: true, options: { empresa: 7 } });
  await adapter.createUser({ id: "two", name: "Two", email: "shared@example.com", password: "old", active: true, options: {} });
  return { adapter, close: async () => { if (seq) await seq.close(); } };
}

for (const kind of ["memory", "seq"]) {
  test(`${kind}: registration, own profile and password change`, async () => {
    const { adapter, close } = await fixture(kind);
    try {
      const body = { name: "New", email: "shared@example.com", password: "old" };
      assert.equal((await request(adapter, "POST", "/register", body)).statusCode, 401);
      for (const field of ["id", "userId", "roles", "permissions", "active", "options"]) {
        assert.equal((await request(adapter, "POST", "/register", { ...body, [field]: "forbidden" }, null, { registration: true })).statusCode, 400);
      }
      const registered = await request(adapter, "POST", "/register", body, null, { registration: true });
      assert.equal(registered.statusCode, 201);
      assert.equal(registered.body.data.password, undefined);
      const id = registered.body.data.id;
      assert.notEqual(id, "one");
      assert.deepEqual(await adapter.findRolesByUserId(id), []);
      const token = await login(adapter, id);
      assert.equal((await request(adapter, "PATCH", "/me", { name: "Changed" })).statusCode, 401);
      for (const field of ["id", "userId", "roles", "permissions", "active", "options", "password"]) {
        assert.equal((await request(adapter, "PATCH", "/me", { [field]: "forbidden" }, token)).statusCode, 400);
      }
      assert.equal((await request(adapter, "PATCH", "/me", { name: "Changed", email: "shared@example.com" }, token)).statusCode, 200);
      assert.equal((await adapter.findUserById(id)).name, "Changed");
      assert.equal((await adapter.findUserById("one")).name, "One");
      assert.equal((await request(adapter, "POST", "/me/password", { currentPassword: "wrong", password: "new" }, token)).statusCode, 401);
      const link = await createPasswordReset({ adapter, userId: id, resetUrl: "https://example.com/reset" });
      assert.equal((await request(adapter, "POST", "/me/password", { currentPassword: "old", password: "new" }, token)).statusCode, 200);
      assert.equal((await request(adapter, "GET", "/session", undefined, token)).statusCode, 401);
      assert.equal((await request(adapter, "POST", "/reset-password", { token: new URL(link.url).searchParams.get("token"), password: "bad" })).statusCode, 401);
      assert.equal((await request(adapter, "POST", "/login", { username: id, password: "old" })).statusCode, 401);
      await login(adapter, id, "new");
    } finally { await close(); }
  });

  test(`${kind}: reset link expires, is single use and targets exact userId`, async () => {
    const { adapter, close } = await fixture(kind);
    try {
      const session = await login(adapter, "one");
      const otherSession = await login(adapter, "two");
      const link = await createPasswordReset({ adapter, userId: "one", resetUrl: "https://example.com/reset?lang=es", expiresIn: 600 });
      const url = new URL(link.url);
      const token = url.searchParams.get("token");
      assert.equal(url.searchParams.get("lang"), "es");
      const hash = createHash("sha256").update(token).digest("hex");
      const stored = kind === "seq" ? (await adapter.models.passwordResets.findByPk(hash)).get() : adapter.passwordResets[0];
      assert.equal(stored.id, hash);
      assert.equal(JSON.stringify(stored).includes(token), false);
      assert.equal(await adapter.resetPassword(hash, "bad", link.expiresAt), false);
      assert.equal((await request(adapter, "POST", "/reset-password", { token: "a".repeat(43), password: "new" })).statusCode, 401);
      assert.equal((await request(adapter, "POST", "/reset-password", { token, password: "" })).statusCode, 400);
      assert.equal((await request(adapter, "POST", "/reset-password", { token, password: "new" })).statusCode, 200);
      assert.equal((await request(adapter, "POST", "/reset-password", { token, password: "bad" })).statusCode, 401);
      assert.equal((await request(adapter, "GET", "/session", undefined, session)).statusCode, 401);
      assert.equal((await request(adapter, "GET", "/session", undefined, otherSession)).statusCode, 200);
      await login(adapter, "one", "new");
      assert.equal((await adapter.findUserById("two")).password, "old");
      assert.deepEqual((await adapter.findUserById("one")).options, { empresa: 7 });
    } finally { await close(); }
  });

  test(`${kind}: reset does not reactivate accounts and concurrent reuse has one winner`, async () => {
    const { adapter, close } = await fixture(kind);
    try {
      await adapter.updateUser("one", { active: false });
      const link = await createPasswordReset({ adapter, userId: "one", resetUrl: "https://example.com/reset" });
      const token = new URL(link.url).searchParams.get("token");
      const results = await Promise.allSettled([1, 2].map(() => request(adapter, "POST", "/reset-password", { token, password: "new" })));
      assert.equal(results.filter(result => result.status === "fulfilled" && result.value.statusCode === 200).length, 1);
      assert.equal((await adapter.findUserById("one")).active, false);
      assert.equal((await request(adapter, "POST", "/reset-password", { token, password: "bad" })).statusCode, 401);
    } finally { await close(); }
  });
}

test("SQL reset rolls back token consumption and password if session invalidation fails", async () => {
  const { adapter, close } = await fixture("seq");
  try {
    const link = await createPasswordReset({ adapter, userId: "one", resetUrl: "https://example.com/reset" });
    const token = new URL(link.url).searchParams.get("token");
    const update = adapter.models.sessions.update;
    adapter.models.sessions.update = async () => { throw new Error("storage failure"); };
    await assert.rejects(request(adapter, "POST", "/reset-password", { token, password: "new" }), /storage failure/);
    adapter.models.sessions.update = update;
    assert.equal((await adapter.findUserById("one")).password, "old");
    assert.equal((await request(adapter, "POST", "/reset-password", { token, password: "new" })).statusCode, 200);
  } finally { await close(); }
});

test("local storage persists account changes and consumed reset credentials", async () => {
  const map = new Map();
  const storage = { getItem: key => map.get(key), setItem: (key, value) => map.set(key, value) };
  const adapter = new LocalStorageAdapter({ storage });
  await adapter.createUser({ id: "one", password: "old" });
  await adapter.updateUser("one", { name: "Changed" });
  const link = await createPasswordReset({ adapter, userId: "one", resetUrl: "https://example.com/reset" });
  const reloaded = new LocalStorageAdapter({ storage });
  assert.equal((await reloaded.findUserById("one")).name, "Changed");
  assert.equal((await request(reloaded, "POST", "/reset-password", { token: new URL(link.url).searchParams.get("token"), password: "new" })).statusCode, 200);
  const final = new LocalStorageAdapter({ storage });
  assert.equal((await final.findUserById("one")).password, "new");
  assert.deepEqual(final.passwordResets, []);
});

test("link generation rejects invalid URL, lifetime and missing users", async () => {
  const { adapter } = await fixture("memory");
  for (const resetUrl of ["/relative", "javascript:alert(1)", "https://user:pass@example.com"]) {
    await assert.rejects(createPasswordReset({ adapter, userId: "one", resetUrl }), { code: "VALIDATION_ERROR" });
  }
  await assert.rejects(createPasswordReset({ adapter, userId: "one", resetUrl: "https://example.com", expiresIn: 0 }), { code: "VALIDATION_ERROR" });
  await assert.rejects(createPasswordReset({ adapter, userId: "missing", resetUrl: "https://example.com" }), { code: "NOT_FOUND" });
});

test("browser account flow matches middleware responses and retains bearer credentials", async () => {
  const { adapter } = await fixture("memory");
  const originalFetch = globalThis.fetch;
  const storage = new Map();
  browserAuth.configure({ baseUrl: "https://example.com", storage: {
    getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)
  } });
  globalThis.fetch = async (url, init) => {
    if (new URL(url).pathname === "/logout") {
      assert.equal(init.method, "POST");
      assert.equal(init.body, undefined);
      assert.ok(init.headers.Authorization.startsWith("Bearer "));
    }
    const result = await request(adapter, init.method ?? "GET", new URL(url).pathname,
      init.body ? JSON.parse(init.body) : undefined, init.headers.Authorization?.slice(7), { registration: true });
    return { ok: result.statusCode < 400, status: result.statusCode, json: async () => result.body };
  };
  try {
    const user = await browserAuth.register({ name: "Browser", email: "shared@example.com", password: "old" });
    const session = await browserAuth.login({ username: user.id, password: "old", options: { empresa: 9 } });
    assert.equal(session.user.id, user.id);
    assert.equal(session.options.empresa, 9);
    await browserAuth.login({ token: session.token });
    assert.equal(browserAuth.getSession().token, session.token);
    await browserAuth.updateProfile({ name: "New name" });
    assert.equal(browserAuth.getSession().user.name, "New name");
    await assert.rejects(browserAuth.changePassword("wrong", "new"));
    assert.equal(browserAuth.getSession().token, session.token);
    await browserAuth.changePassword("old", "new");
    assert.equal(browserAuth.getSession(), null);
    assert.equal(storage.size, 0);
    const link = await createPasswordReset({ adapter, userId: user.id, resetUrl: "https://example.com/reset" });
    await browserAuth.resetPassword(new URL(link.url).searchParams.get("token"), "recovered");
    await browserAuth.login({ username: user.id, password: "recovered" });
    const lastToken = browserAuth.getSession().token;
    await browserAuth.logout();
    assert.equal(browserAuth.getSession(), null);
    assert.equal(storage.size, 0);
    assert.equal((await request(adapter, "GET", "/session", undefined, lastToken)).statusCode, 401);
  } finally {
    globalThis.fetch = originalFetch;
    browserAuth.configure({ storage: null });
  }
});
