import assert from "node:assert/strict";
import test from "node:test";
import { AsyncLocalStorage } from "node:async_hooks";
import { log, normalizeLogging } from "../src/express/logging.js";

test("logging includes the current transaction without mixing concurrent contexts", async () => {
  const storage = new AsyncLocalStorage();
  const events = [];
  const logging = normalizeLogging({
    getContext: () => storage.getStore(),
    trace: (...args) => events.push(args[2])
  });
  await Promise.all(["tx-1", "tx-2"].map((txId) => storage.run({ txId }, async () => {
    await new Promise((resolve) => setImmediate(resolve));
    log(logging, "trace", "Acceso autenticado", { userId: txId, token: "secret" });
  })));
  assert.equal(events.length, 2);
  for (const event of events) {
    assert.equal(event.txId, event.userId);
    assert.equal(event.token, "[REDACTED]");
  }
  log(logging, "trace", "Sin contexto", { userId: "admin" });
  assert.deepEqual(events[2], { userId: "admin" });
});

test("logging omits null or missing transaction IDs", () => {
  for (const context of [undefined, null, {}, { txId: null }]) {
    const logging = normalizeLogging({
      getContext: () => context,
      info: (...args) => assert.deepEqual(args[2], { userId: "admin" })
    });
    log(logging, "info", "Sesión iniciada", { userId: "admin" });
  }
});
