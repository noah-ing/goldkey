import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { POSTGRES_SCHEMA, PostgresGoldKeyDatabase } from "../src/database-postgres.mjs";

test("Postgres migrations preserve every durable ledger table and lock migration", async () => {
  const statements = [];
  let released = false;
  const client = {
    async query(statement) {
      statements.push(statement);
      return { rows: [], rowCount: 0 };
    },
    release() {
      released = true;
    },
  };
  const pool = {
    on() {},
    async connect() { return client; },
    async query() { return { rows: [{ ok: 1 }], rowCount: 1 }; },
  };

  const database = await PostgresGoldKeyDatabase.connect({ pool });
  assert.equal(await database.healthCheck(), true);
  assert.equal(released, true);
  assert.deepEqual(statements.slice(0, 2), ["BEGIN", "SELECT pg_advisory_xact_lock($1)"]);
  assert.equal(statements.at(-1), "COMMIT");
  for (const table of ["auth_challenges", "sessions", "access_keys", "usage_terms", "usage_dedupe", "usage_daily"]) {
    assert.match(POSTGRES_SCHEMA, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
  }
  assert.match(POSTGRES_SCHEMA, /PRIMARY KEY \(token_id, term_number, principal_id, idempotency_key\)/);
});

const liveUrl = process.env.TEST_DATABASE_URL;
test("Postgres quota and idempotency remain atomic under contention", { skip: !liveUrl }, async () => {
  const database = await PostgresGoldKeyDatabase.connect({ connectionString: liveUrl, poolMax: 3 });
  const tokenId = `test-${Date.now()}-${randomUUID()}`;
  const base = {
    tokenId,
    termNumber: "1",
    ownershipEpoch: "0",
    principalId: "owner:test:0",
    allowance: 1,
    tool: "json.canonicalize",
    baseResponse: { request_id: randomUUID(), result: { ok: true } },
  };
  try {
    const contenders = await Promise.allSettled([
      database.consume({ ...base, idempotencyKey: "contender-0001", requestHash: "left" }),
      database.consume({ ...base, idempotencyKey: "contender-0002", requestHash: "right" }),
    ]);
    assert.equal(contenders.filter(({ status }) => status === "fulfilled").length, 1);
    assert.equal(
      contenders.filter(({ status, reason }) => status === "rejected" && reason.code === "goldkey_quota_exhausted").length,
      1,
    );
    assert.equal((await database.quota(tokenId, "1", 1)).used, 1);

    const winner = contenders.find(({ status }) => status === "fulfilled").value;
    const winningKey = contenders[0].status === "fulfilled" ? "contender-0001" : "contender-0002";
    const winningHash = winningKey.endsWith("1") ? "left" : "right";
    const replay = await database.consume({
      ...base,
      idempotencyKey: winningKey,
      requestHash: winningHash,
      baseResponse: { ...base.baseResponse, request_id: winner.request_id },
    });
    assert.equal(replay.idempotent_replay, true);
    assert.equal((await database.quota(tokenId, "1", 1)).used, 1);
  } finally {
    for (const table of ["usage_daily", "usage_dedupe", "usage_terms", "access_keys", "sessions", "auth_challenges"]) {
      await database.pool.query(`DELETE FROM ${table} WHERE token_id = $1`, [tokenId]);
    }
    await database.close();
  }
});
