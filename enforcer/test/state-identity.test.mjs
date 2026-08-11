import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { IdempotencyConflictError, LocalStateError } from "../src/errors.mjs";
import { loadOrCreateInstallationIdentity } from "../src/identity.mjs";
import { FileOutcomeStore } from "../src/state-store.mjs";

test("installation identity persists with private permissions and a stable public fingerprint", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-identity-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "installation.json");
  const first = await loadOrCreateInstallationIdentity(filename);
  const second = await loadOrCreateInstallationIdentity(filename);
  assert.equal(first.installationId, second.installationId);
  assert.equal(Object.hasOwn(first.publicJwk, "d"), false);
  if (process.platform !== "win32") assert.equal((await stat(filename)).mode & 0o077, 0);
});

test("identity and replay state refuse group/other-writable directories", async (t) => {
  if (process.platform === "win32") return;
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-permissions-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await chmod(directory, 0o777);
  await assert.rejects(loadOrCreateInstallationIdentity(path.join(directory, "key.json")), LocalStateError);
  const store = new FileOutcomeStore({ directory });
  await assert.rejects(store.get("permission-test-1"), LocalStateError);
});

test("durable store detects replay and conflicting call after a fresh store instance", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-replay-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const callHash = "1".repeat(64);
  const first = new FileOutcomeStore({ directory, clock: () => 1_000 });
  assert.equal((await first.begin({
    idempotencyKey: "persisted-key-01",
    callHash,
    callKind: "mcp_tool",
  })).created, true);
  const restarted = new FileOutcomeStore({ directory, clock: () => 2_000 });
  const replay = await restarted.begin({
    idempotencyKey: "persisted-key-01",
    callHash,
    callKind: "mcp_tool",
  });
  assert.equal(replay.created, false);
  assert.equal(replay.record.state, "AUTHORIZING");
  await assert.rejects(restarted.begin({
    idempotencyKey: "persisted-key-01",
    callHash: "2".repeat(64),
    callKind: "mcp_tool",
  }), IdempotencyConflictError);
});
