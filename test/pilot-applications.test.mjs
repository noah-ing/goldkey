import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { GoldKeyDatabase } from "../src/database.mjs";
import { createPilotApplicationsService } from "../src/pilot-applications.mjs";

const ADMIN_TOKEN = "pilot-admin-token-that-is-deliberately-long-and-random-for-tests";
const ADMIN_HASH = createHash("sha256").update(ADMIN_TOKEN).digest("hex");
const AUTHORIZATION = `Bearer ${ADMIN_TOKEN}`;
const NOW = Date.UTC(2026, 7, 12, 12, 0, 0);

function body(overrides = {}) {
  return {
    name: "Ada Buyer",
    email: "ADA@Example.COM",
    company: "Example Labs",
    agent_stack: "Claude Code plus an MCP gateway",
    connector: "Salesforce",
    action: "Create and update customer records after policy approval.",
    timeline: "This quarter",
    budget_confirmed: true,
    website: "",
    ...overrides,
  };
}

function setup(options = {}) {
  const database = new GoldKeyDatabase();
  const service = createPilotApplicationsService({
    database,
    adminTokenSha256: ADMIN_HASH,
    abuseSecret: "test-only-pilot-abuse-secret-that-is-long-enough",
    ...options,
  });
  return { database, service };
}

test("private pilot intake validates, normalizes, deduplicates, and never echoes PII", async () => {
  const { database, service } = setup();
  try {
    const submission = await service.submit({
      body: body(),
      idempotencyKey: "20e4300d-355a-4d96-9f86-7d8a75e72774",
      clientAddress: "203.0.113.4",
      now: NOW,
    });
    assert.deepEqual(Object.keys(submission).sort(), ["application_id", "idempotent_replay", "ok", "status"]);
    assert.equal(submission.status, "received");
    assert.equal(submission.idempotent_replay, false);
    assert.equal(JSON.stringify(submission).includes("ada@example.com"), false);

    const replay = await service.submit({
      body: body(),
      idempotencyKey: "20e4300d-355a-4d96-9f86-7d8a75e72774",
      clientAddress: "203.0.113.4",
      now: NOW + 1,
    });
    assert.equal(replay.application_id, submission.application_id);
    assert.equal(replay.idempotent_replay, true);

    await assert.rejects(
      service.submit({
        body: body({ action: "A different state-changing action that should conflict." }),
        idempotencyKey: "20e4300d-355a-4d96-9f86-7d8a75e72774",
        clientAddress: "203.0.113.4",
        now: NOW + 2,
      }),
      (error) => error.code === "pilot_idempotency_conflict",
    );

    const listed = await service.list({ authorization: AUTHORIZATION, now: NOW + 3 });
    assert.equal(listed.applications.length, 1);
    assert.equal(listed.applications[0].email, "ada@example.com");
    assert.equal(listed.applications[0].application_id, submission.application_id);
    assert.equal(listed.applications[0].budget_confirmed, true);
  } finally {
    database.close();
  }
});

test("pilot intake closes input, requires pricing confirmation, and silently sinks honeypots", async () => {
  const { database, service } = setup();
  try {
    for (const invalid of [
      body({ budget_confirmed: false }),
      { ...body(), arbitrary_secret: "do not accept" },
      body({ email: "not-an-email" }),
      body({ action: "too short" }),
    ]) {
      await assert.rejects(
        service.submit({
          body: invalid,
          idempotencyKey: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
          clientAddress: "203.0.113.5",
          now: NOW,
        }),
        (error) => error.status === 400,
      );
    }

    const trap = await service.submit({
      body: body({ website: "https://spam.example" }),
      idempotencyKey: "sink-honeypot-key-0000000001",
      clientAddress: "not-even-an-ip",
      now: NOW,
    });
    assert.equal(trap.ok, true);
    const summary = await service.summary({ authorization: AUTHORIZATION, now: NOW });
    assert.equal(summary.total_active, 0);
  } finally {
    database.close();
  }
});

test("persisted pilot abuse limits are atomic and idempotent replay precedes limits", async () => {
  const { database, service } = setup({ sourceHourlyLimit: 2, sourceDailyLimit: 3, contactDailyLimit: 2 });
  try {
    const first = await service.submit({
      body: body(),
      idempotencyKey: "rate-key-0000000000000001",
      clientAddress: "2001:db8::1",
      now: NOW,
    });
    await service.submit({
      body: body({ email: "grace@example.com", name: "Grace Buyer" }),
      idempotencyKey: "rate-key-0000000000000002",
      clientAddress: "2001:db8::1",
      now: NOW + 1,
    });
    await assert.rejects(
      service.submit({
        body: body({ email: "lin@example.com", name: "Lin Buyer" }),
        idempotencyKey: "rate-key-0000000000000003",
        clientAddress: "2001:db8::1",
        now: NOW + 2,
      }),
      (error) => error.status === 429,
    );
    const replay = await service.submit({
      body: body(),
      idempotencyKey: "rate-key-0000000000000001",
      clientAddress: "2001:db8::1",
      now: NOW + 3,
    });
    assert.equal(replay.application_id, first.application_id);
    assert.equal(replay.idempotent_replay, true);
  } finally {
    database.close();
  }
});

test("admin list/review require the separate bearer and summary discloses no PII", async () => {
  const { database, service } = setup();
  try {
    const submitted = await service.submit({
      body: body(),
      idempotencyKey: "review-key-00000000000001",
      clientAddress: "192.0.2.10",
      now: NOW,
    });
    await assert.rejects(service.list({ authorization: "Bearer wrong-wrong-wrong-wrong-wrong", now: NOW }), (error) => error.status === 401);
    await assert.rejects(service.summary({ now: NOW }), (error) => error.status === 401);

    const summary = await service.summary({ authorization: AUTHORIZATION, now: NOW });
    assert.deepEqual(summary, {
      total_active: 1,
      counts_by_status: { received: 1, reviewing: 0, accepted: 0, declined: 0, closed: 0 },
      newest: { application_id: submitted.application_id, submitted_at: new Date(NOW).toISOString() },
    });
    assert.equal(JSON.stringify(summary).includes("Ada"), false);
    assert.equal(JSON.stringify(summary).includes("@"), false);

    const reviewed = await service.review({
      authorization: AUTHORIZATION,
      applicationId: submitted.application_id,
      body: { status: "accepted", admin_note: "Qualified for a paid discovery call." },
      now: NOW + 10,
    });
    assert.equal(reviewed.application.status, "accepted");
    assert.equal(reviewed.application.admin_note, "Qualified for a paid discovery call.");
    assert.equal((await service.summary({ authorization: AUTHORIZATION, now: NOW + 11 })).counts_by_status.accepted, 1);
  } finally {
    database.close();
  }
});

test("pilot PII is purged at the retention deadline", async () => {
  const { database, service } = setup({ retentionDays: 1 });
  try {
    await service.submit({
      body: body(),
      idempotencyKey: "retention-key-00000000001",
      clientAddress: "198.51.100.40",
      now: NOW,
    });
    assert.equal((await service.summary({ authorization: AUTHORIZATION, now: NOW + 86_399_999 })).total_active, 1);
    assert.equal((await service.summary({ authorization: AUTHORIZATION, now: NOW + 86_400_000 })).total_active, 0);
    const raw = database.db.prepare("SELECT COUNT(*) AS count FROM pilot_applications").get();
    assert.equal(raw.count, 0);
  } finally {
    database.close();
  }
});
