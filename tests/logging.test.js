import assert from "node:assert/strict";
import test from "node:test";
import { AsyncLocalStorage } from "node:async_hooks";
import { log, normalizeLogging } from "../src/express/logging.js";

test("logging preserves console defaults and disabled levels", (t) => {
  const output = t.mock.method(console, "log", () => {});
  const errors = t.mock.method(console, "error", () => {});
  const getContext = () => { throw new Error("Disabled logging must not read context"); };
  for (const option of [false, null]) {
    log(normalizeLogging(option, getContext), "info", "Disabled");
  }
  log(normalizeLogging({ trace: false }, getContext), "trace", "Disabled");
  assert.equal(output.mock.callCount(), 0);
  for (const option of [undefined, true, { trace: false }]) {
    const logging = normalizeLogging(option);
    log(logging, "info", "Info");
    log(logging, "error", "Error");
  }
  assert.equal(output.mock.callCount(), 3);
  assert.equal(errors.mock.callCount(), 3);
});

test("logging includes the current transaction without mixing concurrent contexts", async () => {
  const storage = new AsyncLocalStorage();
  const events = [];
  const logging = normalizeLogging({
    trace: (...args) => events.push(args)
  }, () => storage.getStore());
  await Promise.all(["tx-1", "tx-2"].map((txId) => storage.run({ txId }, async () => {
    await new Promise((resolve) => setImmediate(resolve));
    log(logging, "trace", "auth", "Acceso autenticado", { userId: txId, token: "secret" });
  })));
  assert.equal(events.length, 2);
  for (const event of events) {
    assert.deepEqual(event.slice(0, 4), ["[IAM]", "auth", event[4].userId, "Acceso autenticado"]);
    assert.equal(event[4].token, "[REDACTED]");
  }
  log(logging, "trace", "auth", "Sin contexto", { userId: "admin" });
  assert.deepEqual(events[2], ["[IAM]", "auth", "", "Sin contexto", { userId: "admin" }]);
});

test("logging omits null or missing transaction IDs", () => {
  for (const context of [undefined, null, {}, { txId: null }]) {
    const logging = normalizeLogging({
      info: (...args) => assert.deepEqual(args, ["[IAM]", "auth", "", "Sesión iniciada", { userId: "admin" }])
    }, () => context);
    log(logging, "info", "auth", "Sesión iniciada", { userId: "admin" });
  }
});
