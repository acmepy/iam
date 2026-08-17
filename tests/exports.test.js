import assert from "node:assert/strict";
import test from "node:test";

test("package exports expose root, adapters and express subpaths", async () => {
  const root = await import("iam");
  const adapters = await import("iam/adapters");
  const express = await import("iam/express");

  assert.equal(typeof root.RBAC, "function");
  assert.equal(typeof adapters.SeqAdapter, "function");
  assert.equal(typeof express.auth, "function");
});
