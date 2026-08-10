import assert from "node:assert/strict";
import test from "node:test";
import { GoldKeyDatabase } from "../src/database.mjs";

function call(db, overrides = {}) {
  return db.consume({
    tokenId: "1",
    termNumber: "1",
    ownershipEpoch: "0",
    principalId: "owner:0xowner:0",
    allowance: 2,
    idempotencyKey: "request-0001",
    requestHash: "hash-a",
    tool: "json.canonicalize",
    baseResponse: { result: { ok: true } },
    ...overrides,
  });
}

test("quota debit is idempotent and fails closed at the allowance", () => {
  const db = new GoldKeyDatabase();
  try {
    const first = call(db);
    assert.equal(first.quota.remaining, 1);
    const replay = call(db);
    assert.equal(replay.idempotent_replay, true);
    assert.equal(db.quota("1", "1", 2).used, 1);
    assert.throws(() => call(db, { requestHash: "different" }), (error) => error.code === "idempotency_conflict");
    assert.equal(call(db, { idempotencyKey: "request-0002", requestHash: "hash-b" }).quota.remaining, 0);
    assert.throws(() => call(db, { idempotencyKey: "request-0003", requestHash: "hash-c" }), (error) => error.code === "goldkey_quota_exhausted");
  } finally {
    db.close();
  }
});

test("delegated credential cap rolls back atomically when exhausted", () => {
  const db = new GoldKeyDatabase();
  try {
    const issued = db.issueAccessKey({ label: "worker", issuerWallet: "0xowner", tokenId: "1", termNumber: "1", ownershipEpoch: "0", allowedTools: ["json.canonicalize"], maxCalls: 1, expiresAt: Date.now() + 60_000 });
    const record = db.authenticateAccessKey(issued.rawKey);
    assert.equal(record.id, issued.id);
    const delegated = { accessKeyId: issued.id, principalId: `delegate:${issued.id}:0` };
    call(db, delegated);
    assert.throws(() => call(db, { ...delegated, idempotencyKey: "request-0002", requestHash: "hash-b" }), (error) => error.code === "delegated_key_quota_exhausted");
    assert.equal(db.quota("1", "1", 2).used, 1);
  } finally {
    db.close();
  }
});

test("only one contender can consume the final quota unit", async () => {
  const db = new GoldKeyDatabase();
  try {
    const attempts = await Promise.allSettled([
      Promise.resolve().then(() => call(db, { allowance: 1, idempotencyKey: "contender-0001", requestHash: "left" })),
      Promise.resolve().then(() => call(db, { allowance: 1, idempotencyKey: "contender-0002", requestHash: "right" })),
    ]);
    assert.equal(attempts.filter(({ status }) => status === "fulfilled").length, 1);
    assert.equal(attempts.filter(({ status, reason }) => status === "rejected" && reason.code === "goldkey_quota_exhausted").length, 1);
    assert.equal(db.quota("1", "1", 1).used, 1);
  } finally {
    db.close();
  }
});

test("idempotency is scoped to the credential principal", () => {
  const db = new GoldKeyDatabase();
  try {
    const first = call(db, { idempotencyKey: "shared-0001", principalId: "delegate:left:0" });
    const second = call(db, { idempotencyKey: "shared-0001", principalId: "delegate:right:0" });
    assert.equal(first.quota.used, 1);
    assert.equal(second.quota.used, 2);
    assert.equal(second.idempotent_replay, undefined);
  } finally {
    db.close();
  }
});

test("preflight blocks conflicts and exhausted delegated keys before execution", () => {
  const db = new GoldKeyDatabase();
  try {
    const issued = db.issueAccessKey({ label: "worker", issuerWallet: "0xowner", tokenId: "1", termNumber: "1", ownershipEpoch: "0", allowedTools: ["json.canonicalize"], maxCalls: 1, expiresAt: Date.now() + 60_000 });
    const principalId = `delegate:${issued.id}:0`;
    call(db, { accessKeyId: issued.id, principalId, idempotencyKey: "preflight-001", requestHash: "hash-a" });
    assert.throws(() => db.preflight({ tokenId: "1", termNumber: "1", ownershipEpoch: "0", principalId, allowance: 2, idempotencyKey: "preflight-001", requestHash: "hash-b", accessKeyId: issued.id }), (error) => error.code === "idempotency_conflict");
    assert.throws(() => db.preflight({ tokenId: "1", termNumber: "1", ownershipEpoch: "0", principalId, allowance: 2, idempotencyKey: "preflight-002", requestHash: "hash-c", accessKeyId: issued.id }), (error) => error.code === "delegated_key_quota_exhausted");
  } finally {
    db.close();
  }
});
