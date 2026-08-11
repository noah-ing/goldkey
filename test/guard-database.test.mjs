import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { GoldKeyDatabase } from "../src/database.mjs";
import { POSTGRES_SCHEMA, PostgresGoldKeyDatabase } from "../src/database-postgres.mjs";

const POLICY_HASH = createHash("sha256").update("policy-v1").digest("hex");

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function install(db, overrides = {}) {
  const policy = db.createGuardPolicyVersion({
    policyId: "default",
    version: "1",
    policyHash: POLICY_HASH,
    policyJson: JSON.stringify({ version: 1, spend: { period: "day" } }),
    operatorWallet: "0xoperator",
    operatorSignature: "operator-policy-signature",
    createdAt: 100,
    expiresAt: 10_000,
    ...overrides.policy,
  });
  const installation = db.createGuardInstallation({
    installationId: "installation-1",
    operatorWallet: "0xoperator",
    policyHash: POLICY_HASH,
    publicKeyJwkJson: JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "public-key-material" }),
    bindingJson: JSON.stringify({ agent_id: "agent-1", network: "eip155:8453" }),
    operatorSignature: "operator-installation-signature",
    createdAt: 200,
    expiresAt: 9_000,
    ...overrides.installation,
  });
  return { policy, installation };
}

function reserve(db, id, overrides = {}) {
  return db.reserveGuardExecution({
    executionId: `execution-${id}`,
    installationId: "installation-1",
    idempotencyKey: `idempotency-${id}`,
    callHash: hash(`call-${id}`),
    policyHash: POLICY_HASH,
    decision: "ALLOW",
    status: "authorized",
    authorizationReceiptJson: JSON.stringify({
      format: "goldkey-guard-authorization-v1",
      call_sha256: hash(`call-${id}`),
      signature: `authorization-signature-${id}`,
    }),
    createdAt: 300,
    expiresAt: 500,
    ...overrides,
  });
}

function settle(db, id, overrides = {}) {
  const installationId = overrides.installationId ?? "installation-1";
  const idempotencyKey = overrides.idempotencyKey ?? `idempotency-${id}`;
  const callHash = overrides.callHash ?? hash(`call-${id}`);
  const settlementClaimId = overrides.settlementClaimId ?? `claim-${id}`;
  const paymentSha256 = overrides.paymentSha256 ?? hash(`payment-${id}`);
  const paymentIdentitySha256 = overrides.paymentIdentitySha256 ?? hash(`payment-identity-${id}`);
  const settledAt = overrides.settledAt ?? 320;
  db.beginGuardExecutionSettlement({
    installationId,
    idempotencyKey,
    callHash,
    settlementClaimId,
    paymentSha256,
    paymentIdentitySha256,
    startedAt: Math.max(300, settledAt - 1),
  });
  return db.markGuardExecutionPaymentSettled({
    installationId,
    idempotencyKey,
    callHash,
    settlementClaimId,
    paymentSha256,
    paymentIdentitySha256,
    settledAt,
    transaction: overrides.transaction ?? `settlement-${id}`,
  });
}

test("guard policies and installations are immutable, hash-addressable, and never accept private JWK material", () => {
  const db = new GoldKeyDatabase();
  try {
    const { policy, installation } = install(db);
    assert.equal(db.getGuardPolicyVersion("default", "1").policy_hash, POLICY_HASH);
    assert.equal(db.getGuardPolicyVersionByHash(POLICY_HASH).operator_signature, policy.operator_signature);
    assert.equal(db.getGuardInstallation("installation-1").public_key_jwk_json, installation.public_key_jwk_json);
    assert.throws(() => install(db), (error) => error.code === "guard_policy_conflict");
    const versionTenHash = hash("policy-v10");
    db.createGuardPolicyVersion({
      policyId: "default",
      version: "10",
      policyHash: versionTenHash,
      policyJson: JSON.stringify({ version: 10 }),
      operatorWallet: "0xoperator",
      operatorSignature: "operator-policy-signature-v10",
      createdAt: 101,
      expiresAt: 10_000,
    });
    assert.equal(db.getLatestGuardPolicyVersion("default").version, "10");
    assert.throws(() => db.createGuardPolicyVersion({
      policyId: "default",
      version: "11",
      policyHash: hash("policy-hostile-takeover"),
      policyJson: JSON.stringify({ version: 11 }),
      operatorWallet: "0xattacker",
      operatorSignature: "attacker-signature",
      createdAt: 103,
      expiresAt: 10_000,
    }), (error) => error.code === "guard_policy_operator_change_requires_rotation");
    assert.throws(() => db.createGuardPolicyVersion({
      policyId: "default",
      version: "2",
      policyHash: hash("policy-v2-late"),
      policyJson: JSON.stringify({ version: 2 }),
      operatorWallet: "0xoperator",
      operatorSignature: "operator-policy-signature-v2",
      createdAt: 102,
      expiresAt: 10_000,
    }), (error) => error.code === "guard_policy_version_not_monotonic");
    assert.throws(() => db.createGuardPolicyVersion({
      policyId: "other",
      version: "01",
      policyHash: hash("invalid-version"),
      policyJson: "{}",
      operatorWallet: "0xoperator",
      operatorSignature: "signature",
      createdAt: 100,
      expiresAt: 1_000,
    }), (error) => error.code === "invalid_guard_record");
    assert.throws(() => db.createGuardInstallation({
      installationId: "private-key-installation",
      operatorWallet: "0xoperator",
      policyHash: POLICY_HASH,
      publicKeyJwkJson: JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "public", d: "private" }),
      bindingJson: "{}",
      operatorSignature: "signature",
      createdAt: 201,
      expiresAt: 8_000,
    }), (error) => error.code === "private_jwk_forbidden");

    for (const table of ["guard_policy_versions", "guard_installations", "guard_spend_periods", "guard_executions"]) {
      const columns = db.db.prepare(`PRAGMA table_info(${table})`).all().map(({ name }) => name);
      assert.equal(columns.some((name) => /(^|_)(secret|raw_call|raw_input|raw_output|raw_result)($|_)/.test(name)), false, table);
    }
  } finally {
    db.close();
  }
});

test("guard execution reservation is idempotent and the authoritative cap check rolls back atomically", async () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    const first = reserve(db, "one", {
      reservationKey: "2026-08-11",
      reservationAmountAtomic: "1",
      spendCapAtomic: "1",
    });
    assert.equal(first.replay, false);
    const replay = reserve(db, "replacement-id", {
      executionId: "different-execution-id",
      idempotencyKey: "idempotency-one",
      callHash: hash("call-one"),
      authorizationReceiptJson: JSON.stringify({ different: "receipt-is-ignored-on-replay" }),
      reservationKey: "2026-08-11",
      reservationAmountAtomic: "1",
      spendCapAtomic: "1",
    });
    assert.equal(replay.replay, true);
    assert.equal(replay.execution.id, "execution-one");
    assert.equal(replay.execution.payment_settled_at, null);
    db.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-one",
      callHash: hash("call-one"),
      settlementClaimId: "claim-one",
      paymentSha256: hash("payment-one"),
      paymentIdentitySha256: hash("payment-identity-one"),
      startedAt: 319,
    });
    const marked = db.markGuardExecutionPaymentSettled({
      installationId: "installation-1",
      idempotencyKey: "idempotency-one",
      callHash: hash("call-one"),
      settlementClaimId: "claim-one",
      paymentSha256: hash("payment-one"),
      paymentIdentitySha256: hash("payment-identity-one"),
      settledAt: 320,
      transaction: "0xsettled-one",
    });
    assert.equal(marked.replay, false);
    assert.equal(marked.execution.payment_settled_at, 320);
    assert.equal(marked.execution.payment_transaction, "0xsettled-one");
    assert.equal(db.markGuardExecutionPaymentSettled({
      installationId: "installation-1",
      idempotencyKey: "idempotency-one",
      callHash: hash("call-one"),
      settlementClaimId: "claim-one",
      paymentSha256: hash("payment-one"),
      paymentIdentitySha256: hash("payment-identity-one"),
      settledAt: 321,
      transaction: "0xsettled-one",
    }).replay, true);
    assert.throws(() => db.markGuardExecutionPaymentSettled({
      installationId: "installation-1",
      idempotencyKey: "idempotency-one",
      callHash: hash("call-one"),
      settlementClaimId: "claim-one",
      paymentSha256: hash("payment-one"),
      paymentIdentitySha256: hash("payment-identity-one"),
      settledAt: 321,
      transaction: "0xdifferent-settlement",
    }), (error) => error.code === "guard_payment_transaction_mismatch");
    assert.throws(() => db.markGuardExecutionPaymentSettled({
      installationId: "installation-1",
      idempotencyKey: "idempotency-one",
      callHash: hash("different-call"),
      settlementClaimId: "claim-one",
      paymentSha256: hash("payment-one"),
      paymentIdentitySha256: hash("payment-identity-one"),
      settledAt: 321,
      transaction: "0xwrong",
    }), (error) => error.code === "idempotency_conflict");
    assert.throws(() => reserve(db, "conflict", {
      idempotencyKey: "idempotency-one",
      callHash: hash("different-call"),
      reservationKey: "2026-08-11",
      reservationAmountAtomic: "1",
      spendCapAtomic: "1",
    }), (error) => error.code === "idempotency_conflict");

    const contenders = await Promise.allSettled([
      Promise.resolve().then(() => reserve(db, "two", {
        createdAt: 301,
        expiresAt: 501,
        reservationKey: "2026-08-11",
        reservationAmountAtomic: "1",
        spendCapAtomic: "1",
      })),
      Promise.resolve().then(() => reserve(db, "three", {
        createdAt: 301,
        expiresAt: 501,
        reservationKey: "2026-08-11",
        reservationAmountAtomic: "1",
        spendCapAtomic: "1",
      })),
    ]);
    assert.equal(contenders.filter(({ status }) => status === "fulfilled").length, 0);
    assert.equal(contenders.filter(({ status, reason }) => status === "rejected" && reason.code === "guard_spend_cap_exceeded").length, 2);
    assert.deepEqual(
      { ...db.getGuardSpendPeriod("installation-1", "2026-08-11") },
      {
        reservation_key: "2026-08-11",
        cap_atomic: "1",
        reserved_atomic: "1",
        spent_atomic: "0",
        created_at: 300,
        updated_at: 300,
      },
    );
    assert.equal(db.getGuardExecution("execution-two"), undefined);
    assert.equal(db.getGuardExecution("execution-three"), undefined);
  } finally {
    db.close();
  }
});

test("commit happens before forwarding and completion never releases conservatively spent value", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    reserve(db, "commit", {
      reservationKey: "period-1",
      reservationAmountAtomic: "40",
      spendCapAtomic: "100",
    });
    assert.throws(() => db.completeGuardExecution({
      executionId: "execution-commit",
      completionReceiptJson: JSON.stringify({ signature: "completion-signature" }),
      outcomeStatus: "succeeded",
      outcomeHash: hash("outcome"),
      completedAt: 350,
    }), (error) => error.code === "guard_execution_not_committed");

    assert.throws(
      () => db.commitGuardExecution({ executionId: "execution-commit", committedAt: 339 }),
      (error) => error.code === "guard_payment_not_settled",
    );
    settle(db, "commit");

    const committed = db.commitGuardExecution({ executionId: "execution-commit", committedAt: 340 });
    assert.equal(committed.execution.lifecycle_status, "forwarding");
    assert.equal(committed.execution.spend_disposition, "committed");
    assert.deepEqual(
      { reserved: db.getGuardSpendPeriod("installation-1", "period-1").reserved_atomic, spent: db.getGuardSpendPeriod("installation-1", "period-1").spent_atomic },
      { reserved: "0", spent: "40" },
    );
    assert.equal(db.commitGuardExecution({ executionId: "execution-commit", committedAt: 341 }).replay, true);

    const completion = {
      executionId: "execution-commit",
      completionReceiptJson: JSON.stringify({ format: "goldkey-guard-completion-v1", signature: "completion-signature" }),
      outcomeStatus: "failed",
      outcomeHash: hash("failed-outcome"),
      completedAt: 600,
    };
    assert.equal(db.completeGuardExecution(completion).execution.lifecycle_status, "completed");
    assert.equal(db.completeGuardExecution(completion).replay, true);
    assert.equal(db.getGuardSpendPeriod("installation-1", "period-1").spent_atomic, "40");
    assert.throws(() => reserve(db, "over-cap", {
      createdAt: 601,
      expiresAt: 700,
      reservationKey: "period-1",
      reservationAmountAtomic: "61",
      spendCapAtomic: "100",
    }), (error) => error.code === "guard_spend_cap_exceeded");
    assert.throws(() => db.completeGuardExecution({ ...completion, outcomeStatus: "invented" }), (error) => error.code === "invalid_guard_record");
    assert.throws(() => db.completeGuardExecution({ ...completion, outcomeHash: "A".repeat(64) }), (error) => error.code === "invalid_guard_record");
  } finally {
    db.close();
  }
});

test("revocation and expiry release only uncommitted reservations exactly once", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    reserve(db, "revoked", {
      reservationKey: "period-revoke",
      reservationAmountAtomic: "10",
      spendCapAtomic: "10",
    });
    const revoked = db.revokeGuardExecution("execution-revoked", 350);
    assert.equal(revoked.execution.lifecycle_status, "revoked");
    assert.equal(revoked.execution.spend_disposition, "released");
    assert.equal(db.revokeGuardExecution("execution-revoked", 351).replay, true);
    assert.deepEqual(
      { reserved: db.getGuardSpendPeriod("installation-1", "period-revoke").reserved_atomic, spent: db.getGuardSpendPeriod("installation-1", "period-revoke").spent_atomic },
      { reserved: "0", spent: "0" },
    );

    reserve(db, "stale", {
      createdAt: 400,
      expiresAt: 450,
      reservationKey: "period-expiry",
      reservationAmountAtomic: "10",
      spendCapAtomic: "10",
    });
    reserve(db, "replacement", {
      createdAt: 451,
      expiresAt: 550,
      reservationKey: "period-expiry",
      reservationAmountAtomic: "10",
      spendCapAtomic: "10",
    });
    assert.equal(db.getGuardExecution("execution-stale").lifecycle_status, "expired");
    assert.equal(db.getGuardExecution("execution-stale").spend_disposition, "released");
    assert.equal(db.getGuardSpendPeriod("installation-1", "period-expiry").reserved_atomic, "10");
    assert.deepEqual(db.sweepExpiredGuardReservations("installation-1", "period-expiry", 451), {
      releasedExecutions: 0,
      releasedAtomic: "0",
    });

    settle(db, "replacement", { settledAt: 480 });
    db.commitGuardExecution({ executionId: "execution-replacement", committedAt: 500 });
    assert.equal(db.sweepExpiredGuardReservations("installation-1", "period-expiry", 1_000).releasedAtomic, "0");
    assert.deepEqual(
      { reserved: db.getGuardSpendPeriod("installation-1", "period-expiry").reserved_atomic, spent: db.getGuardSpendPeriod("installation-1", "period-expiry").spent_atomic },
      { reserved: "0", spent: "10" },
    );
  } finally {
    db.close();
  }
});

test("guard database rejects invented authorization states, malformed hashes, and inactive bindings", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    assert.throws(() => reserve(db, "bad-status", { status: "forwarding" }), (error) => error.code === "invalid_guard_record");
    assert.throws(() => reserve(db, "bad-hash", { callHash: `0x${hash("call")}` }), (error) => error.code === "invalid_guard_record");
    db.revokeGuardInstallation("installation-1", 350);
    assert.throws(() => reserve(db, "inactive", { createdAt: 351, expiresAt: 500 }), (error) => error.code === "guard_installation_inactive");
  } finally {
    db.close();
  }
});

test("parent revocation invalidates an already-issued authorization before commit", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    reserve(db, "pending-parent-revocation", {
      reservationKey: "period-parent-revocation",
      reservationAmountAtomic: "10",
      spendCapAtomic: "100",
    });
    db.revokeGuardInstallation("installation-1", 320);
    assert.throws(
      () => db.commitGuardExecution({ executionId: "execution-pending-parent-revocation", committedAt: 340 }),
      (error) => error.code === "guard_execution_revoked",
    );
    assert.equal(db.getGuardSpendPeriod("installation-1", "period-parent-revocation").spent_atomic, "0");
    assert.equal(db.getGuardSpendPeriod("installation-1", "period-parent-revocation").reserved_atomic, "0");
  } finally {
    db.close();
  }
});

test("multi-reservation authorization atomically enforces asset, fee, and wallet-global nonce budgets", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    const reservations = [
      { reservationKey: "guard:asset:policy:connector:period", reservationAmountAtomic: "40", spendCapAtomic: "100" },
      { reservationKey: "guard:fee:policy:native:eip155:8453:period", reservationAmountAtomic: "10", spendCapAtomic: "25" },
      { reservationKey: "guard:nonce:eip155:8453:0xwallet:nonce:7", reservationAmountAtomic: "1", spendCapAtomic: "1" },
    ];
    reserve(db, "multi", { reservations });
    const childRows = db.db.prepare(`
      SELECT reservation_key, amount_atomic, cap_atomic, disposition
      FROM guard_execution_reservations WHERE execution_id = ? ORDER BY reservation_key
    `).all("execution-multi");
    assert.equal(childRows.length, 3);
    assert.equal(childRows.every(({ disposition }) => disposition === "reserved"), true);
    for (const reservation of reservations) {
      const period = db.getGuardSpendPeriod("installation-1", reservation.reservationKey);
      assert.equal(period.reserved_atomic, reservation.reservationAmountAtomic);
      assert.equal(period.spent_atomic, "0");
    }

    assert.throws(() => reserve(db, "rollback", {
      createdAt: 321,
      expiresAt: 499,
      reservations: [
        { reservationKey: reservations[0].reservationKey, reservationAmountAtomic: "10", spendCapAtomic: "100" },
        { reservationKey: reservations[1].reservationKey, reservationAmountAtomic: "16", spendCapAtomic: "25" },
        { reservationKey: "guard:nonce:eip155:8453:0xwallet:nonce:8", reservationAmountAtomic: "1", spendCapAtomic: "1" },
      ],
    }), (error) => error.code === "guard_spend_cap_exceeded");
    assert.equal(db.getGuardExecution("execution-rollback"), undefined);
    assert.equal(db.getGuardSpendPeriod("installation-1", reservations[0].reservationKey).reserved_atomic, "40");
    assert.equal(db.getGuardSpendPeriod("installation-1", reservations[1].reservationKey).reserved_atomic, "10");
    assert.equal(db.getGuardSpendPeriod("installation-1", "guard:nonce:eip155:8453:0xwallet:nonce:8"), undefined);

    settle(db, "multi");
    db.commitGuardExecution({ executionId: "execution-multi", committedAt: 340 });
    for (const reservation of reservations) {
      const period = db.getGuardSpendPeriod("installation-1", reservation.reservationKey);
      assert.equal(period.reserved_atomic, "0");
      assert.equal(period.spent_atomic, reservation.reservationAmountAtomic);
    }
    assert.equal(
      db.db.prepare("SELECT count(*) AS count FROM guard_execution_reservations WHERE execution_id = ? AND disposition = 'committed'").get("execution-multi").count,
      3,
    );

    db.createGuardInstallation({
      installationId: "installation-2",
      operatorWallet: "0xoperator",
      policyHash: POLICY_HASH,
      publicKeyJwkJson: JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "second-public-key" }),
      bindingJson: JSON.stringify({ agent_id: "agent-2" }),
      operatorSignature: "second-installation-signature",
      createdAt: 341,
      expiresAt: 9_000,
    });
    assert.throws(() => reserve(db, "nonce-reuse", {
      installationId: "installation-2",
      createdAt: 350,
      expiresAt: 450,
      reservations: [reservations[2]],
    }), (error) => error.code === "guard_spend_cap_exceeded");
  } finally {
    db.close();
  }
});

test("every multi-reservation lifecycle release transitions all child rows exactly once", () => {
  const keys = (suffix) => [
    { reservationKey: `asset:${suffix}`, reservationAmountAtomic: "2", spendCapAtomic: "20" },
    { reservationKey: `fee:${suffix}`, reservationAmountAtomic: "3", spendCapAtomic: "30" },
    { reservationKey: `nonce:${suffix}`, reservationAmountAtomic: "1", spendCapAtomic: "1" },
  ];
  for (const mode of ["direct", "expiry", "installation", "policy"]) {
    const db = new GoldKeyDatabase();
    try {
      install(db);
      const reservations = keys(mode);
      reserve(db, mode, { reservations, expiresAt: mode === "expiry" ? 350 : 500 });
      if (mode === "direct") db.revokeGuardExecution(`execution-${mode}`, 340);
      if (mode === "expiry") db.sweepExpiredGuardReservations("installation-1", reservations[0].reservationKey, 351);
      if (mode === "installation") db.revokeGuardInstallation("installation-1", 340);
      if (mode === "policy") db.revokeGuardPolicyVersion(POLICY_HASH, 340);
      const execution = db.getGuardExecution(`execution-${mode}`);
      assert.equal(mode === "expiry" ? execution.lifecycle_status : execution.lifecycle_status, mode === "expiry" ? "expired" : "revoked");
      assert.equal(execution.spend_disposition, "released");
      for (const reservation of reservations) {
        const period = db.getGuardSpendPeriod("installation-1", reservation.reservationKey);
        assert.deepEqual({ reserved: period.reserved_atomic, spent: period.spent_atomic }, { reserved: "0", spent: "0" });
      }
      assert.equal(
        db.db.prepare("SELECT count(*) AS count FROM guard_execution_reservations WHERE execution_id = ? AND disposition = 'released'").get(`execution-${mode}`).count,
        3,
      );
    } finally {
      db.close();
    }
  }
});

test("settlement claims are single-owner and linearize safely against parent revocation", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    const claimedKey = "claim:asset";
    const pendingKey = "pending:asset";
    reserve(db, "claimed", {
      reservations: [{ reservationKey: claimedKey, reservationAmountAtomic: "2", spendCapAtomic: "10" }],
    });
    reserve(db, "pending", {
      reservations: [{ reservationKey: pendingKey, reservationAmountAtomic: "2", spendCapAtomic: "10" }],
    });
    const claim = db.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-claimed",
      callHash: hash("call-claimed"),
      settlementClaimId: "claim-owner-a",
      paymentSha256: hash("payment-claimed"),
      paymentIdentitySha256: hash("payment-identity-claimed"),
      startedAt: 320,
    });
    assert.equal(claim.replay, false);
    assert.equal(claim.execution.settlement_claim_id, "claim-owner-a");
    assert.throws(() => db.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-claimed",
      callHash: hash("call-claimed"),
      settlementClaimId: "claim-owner-b",
      paymentSha256: hash("payment-claimed"),
      paymentIdentitySha256: hash("payment-identity-claimed"),
      startedAt: 321,
    }), (error) => error.code === "guard_settlement_in_progress");
    assert.throws(() => db.cancelGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-claimed",
      callHash: hash("call-claimed"),
      settlementClaimId: "claim-owner-b",
      canceledAt: 321,
    }), (error) => error.code === "guard_settlement_claim_mismatch");
    assert.throws(() => db.revokeGuardExecution("execution-claimed", 321), (error) => error.code === "guard_settlement_in_progress");

    const revokedParent = db.revokeGuardInstallation("installation-1", 322);
    assert.equal(revokedParent.revoked_at, 322);
    assert.equal(db.getGuardExecution("execution-claimed").lifecycle_status, "authorized");
    assert.equal(db.getGuardExecution("execution-pending").lifecycle_status, "revoked");
    assert.equal(db.getGuardSpendPeriod("installation-1", claimedKey).reserved_atomic, "2");
    assert.equal(db.getGuardSpendPeriod("installation-1", pendingKey).reserved_atomic, "0");

    db.markGuardExecutionPaymentSettled({
      installationId: "installation-1",
      idempotencyKey: "idempotency-claimed",
      callHash: hash("call-claimed"),
      settlementClaimId: "claim-owner-a",
      paymentSha256: hash("payment-claimed"),
      paymentIdentitySha256: hash("payment-identity-claimed"),
      settledAt: 323,
      transaction: "0xsettled",
    });
    const committed = db.commitGuardExecution({ executionId: "execution-claimed", committedAt: 324 });
    assert.equal(committed.execution.lifecycle_status, "forwarding");
    assert.deepEqual(
      { reserved: db.getGuardSpendPeriod("installation-1", claimedKey).reserved_atomic, spent: db.getGuardSpendPeriod("installation-1", claimedKey).spent_atomic },
      { reserved: "0", spent: "2" },
    );
  } finally {
    db.close();
  }

  const canceledDb = new GoldKeyDatabase();
  try {
    install(canceledDb);
    reserve(canceledDb, "cancel", {
      reservations: [{ reservationKey: "cancel:asset", reservationAmountAtomic: "3", spendCapAtomic: "10" }],
    });
    canceledDb.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-cancel",
      callHash: hash("call-cancel"),
      settlementClaimId: "claim-cancel",
      paymentSha256: hash("payment-cancel"),
      paymentIdentitySha256: hash("payment-identity-cancel"),
      startedAt: 320,
    });
    canceledDb.revokeGuardPolicyVersion(POLICY_HASH, 321);
    const canceled = canceledDb.cancelGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-cancel",
      callHash: hash("call-cancel"),
      settlementClaimId: "claim-cancel",
      canceledAt: 322,
    });
    assert.equal(canceled.execution.lifecycle_status, "revoked");
    assert.equal(canceledDb.getGuardSpendPeriod("installation-1", "cancel:asset").reserved_atomic, "0");
  } finally {
    canceledDb.close();
  }
});

test("payment reconciliation binds one EIP-3009 identity and atomically commits one transaction", () => {
  const db = new GoldKeyDatabase();
  try {
    install(db);
    reserve(db, "reconcile-a");
    reserve(db, "reconcile-b", { createdAt: 301, expiresAt: 501 });
    const paymentSha256 = hash("reconcile-payment-a");
    const paymentIdentitySha256 = hash("reconcile-identity-a");
    db.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-reconcile-a",
      callHash: hash("call-reconcile-a"),
      settlementClaimId: "claim-reconcile-a",
      paymentSha256,
      paymentIdentitySha256,
      startedAt: 320,
    });
    assert.throws(() => db.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-reconcile-b",
      callHash: hash("call-reconcile-b"),
      settlementClaimId: "claim-reconcile-b",
      paymentSha256: hash("different-wrapper-same-authorization"),
      paymentIdentitySha256,
      startedAt: 321,
    }), (error) => error.code === "guard_payment_identity_reused");
    assert.equal(db.getGuardExecution("execution-reconcile-b").settlement_started_at, null);

    const transaction = `0x${"ab".repeat(32)}`;
    assert.throws(() => db.commitGuardExecution({
      executionId: "execution-reconcile-a",
      committedAt: 322,
      paymentReconciliation: {
        paymentSha256: hash("wrong-payment"),
        paymentIdentitySha256,
        transaction,
        settledAt: 322,
      },
    }), (error) => error.code === "guard_payment_proof_mismatch");
    assert.equal(db.getGuardExecution("execution-reconcile-a").payment_settled_at, null);

    const committed = db.commitGuardExecution({
      executionId: "execution-reconcile-a",
      committedAt: 323,
      paymentReconciliation: {
        paymentSha256,
        paymentIdentitySha256,
        transaction,
        settledAt: 323,
      },
    });
    assert.equal(committed.execution.lifecycle_status, "forwarding");
    assert.equal(committed.execution.payment_transaction, transaction);

    db.beginGuardExecutionSettlement({
      installationId: "installation-1",
      idempotencyKey: "idempotency-reconcile-b",
      callHash: hash("call-reconcile-b"),
      settlementClaimId: "claim-reconcile-b-2",
      paymentSha256: hash("reconcile-payment-b"),
      paymentIdentitySha256: hash("reconcile-identity-b"),
      startedAt: 324,
    });
    assert.throws(() => db.commitGuardExecution({
      executionId: "execution-reconcile-b",
      committedAt: 325,
      paymentReconciliation: {
        paymentSha256: hash("reconcile-payment-b"),
        paymentIdentitySha256: hash("reconcile-identity-b"),
        transaction,
        settledAt: 325,
      },
    }), (error) => error.code === "guard_payment_transaction_reused");
    const second = db.getGuardExecution("execution-reconcile-b");
    assert.equal(second.payment_settled_at, null);
    assert.equal(second.committed_at, null);
  } finally {
    db.close();
  }
});

test("Postgres guard schema and API preserve SQLite ledger parity without a live database", () => {
  const db = new GoldKeyDatabase();
  try {
    const expected = {
      guard_policy_versions: ["policy_id", "version", "policy_hash", "policy_json", "operator_wallet", "operator_signature", "created_at", "expires_at", "revoked_at"],
      guard_installations: ["id", "operator_wallet", "policy_hash", "public_key_jwk_json", "binding_json", "operator_signature", "created_at", "expires_at", "revoked_at"],
      guard_spend_periods: ["reservation_key", "cap_atomic", "reserved_atomic", "spent_atomic", "created_at", "updated_at"],
      guard_executions: [
        "id", "installation_id", "idempotency_key", "call_hash", "policy_hash", "decision", "status",
        "authorization_receipt_json", "created_at", "expires_at", "reservation_key", "reservation_amount_atomic",
        "completion_receipt_json", "outcome_status", "outcome_hash", "spend_disposition", "committed_at",
        "completed_at", "expired_at", "revoked_at", "settlement_started_at", "settlement_claim_id", "settlement_payment_hash", "settlement_payment_identity_hash", "payment_settled_at", "payment_transaction",
      ],
      guard_execution_reservations: ["execution_id", "installation_id", "reservation_key", "amount_atomic", "cap_atomic", "disposition"],
    };
    for (const [table, columns] of Object.entries(expected)) {
      const sqliteColumns = db.db.prepare(`PRAGMA table_info(${table})`).all().map(({ name }) => name);
      assert.deepEqual(sqliteColumns, columns, table);
      const block = POSTGRES_SCHEMA.match(new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(([\\s\\S]*?)\\n  \\);`))?.[1];
      assert.ok(block, `${table} missing from Postgres migration`);
      for (const column of columns) assert.match(block, new RegExp(`^    ${column}\\b`, "m"), `${table}.${column}`);
    }
    assert.match(POSTGRES_SCHEMA, /NUMERIC\(78, 0\)/);
    assert.match(POSTGRES_SCHEMA, /UNIQUE \(installation_id, idempotency_key\)/);
    assert.match(POSTGRES_SCHEMA, /reserved_atomic \+ spent_atomic <= cap_atomic/);
    assert.match(POSTGRES_SCHEMA, /status IN \('authorized', 'denied', 'review'\)/);
    assert.match(POSTGRES_SCHEMA, /outcome_status IN \('succeeded', 'failed', 'outcome_unknown'\)/);
    assert.match(POSTGRES_SCHEMA, /version ~ '\^\[1-9\]\[0-9\]\*\$'/);

    const methods = [
      "createGuardPolicyVersion", "getGuardPolicyVersion", "getGuardPolicyVersionByHash", "getLatestGuardPolicyVersion", "revokeGuardPolicyVersion",
      "createGuardInstallation", "getGuardInstallation", "revokeGuardInstallation", "reserveGuardExecution",
      "getGuardExecution", "getGuardExecutionByIdempotency", "beginGuardExecutionSettlement", "cancelGuardExecutionSettlement", "markGuardExecutionPaymentSettled", "getGuardSpendPeriod", "sweepExpiredGuardReservations",
      "commitGuardExecution", "completeGuardExecution", "revokeGuardExecution",
    ];
    for (const method of methods) {
      assert.equal(typeof GoldKeyDatabase.prototype[method], "function", `SQLite ${method}`);
      assert.equal(typeof PostgresGoldKeyDatabase.prototype[method], "function", `Postgres ${method}`);
    }
    assert.match(PostgresGoldKeyDatabase.prototype.reserveGuardExecution.toString(), /pg_advisory_xact_lock/);
    assert.match(PostgresGoldKeyDatabase.prototype.reserveGuardExecution.toString(), /ON CONFLICT \(reservation_key\) DO UPDATE/);
    assert.match(PostgresGoldKeyDatabase.prototype.commitGuardExecution.toString(), /#transitionGuardExecutionReservations/);
    assert.match(PostgresGoldKeyDatabase.prototype.commitGuardExecution.toString(), /guard_payment_not_settled/);
    assert.match(PostgresGoldKeyDatabase.prototype.revokeGuardExecution.toString(), /#transitionGuardExecutionReservations/);
    assert.match(PostgresGoldKeyDatabase.prototype.revokeGuardPolicyVersion.toString(), /#revokePendingGuardExecutions/);
    assert.match(PostgresGoldKeyDatabase.prototype.revokeGuardInstallation.toString(), /#revokePendingGuardExecutions/);
  } finally {
    db.close();
  }
});
