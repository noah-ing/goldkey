import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { SqlitePaymentBudgetStore } from "../src/payment-budget.mjs";

const INSTALLATION = "gki_budget-test-installation";
const PAYER = "0x1111111111111111111111111111111111111111";
const PAYEE = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const TX = `0x${"12".repeat(32)}`;
const NOW = Date.parse("2026-08-11T12:00:00.000Z");

async function fixture(t, overrides = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-budget-store-"));
  let now = NOW;
  const options = {
    filename: path.join(directory, "budget.sqlite"),
    periodSeconds: 3600,
    maxPeriodAtomic: "200000",
    maxOutstandingAtomic: "100000",
    maxOutstandingCount: 2,
    clock: () => now,
    ...overrides,
  };
  const stores = [];
  const open = () => {
    const store = new SqlitePaymentBudgetStore(options);
    stores.push(store);
    return store;
  };
  const store = open();
  t.after(async () => {
    for (const value of stores) value.close();
    await rm(directory, { recursive: true, force: true });
  });
  return {
    store,
    open,
    setNow(value) { now = value; },
  };
}

function reservation(overrides = {}) {
  return {
    installationId: INSTALLATION,
    idempotencyKey: "budget-call-0001",
    callSha256: HASH_A,
    amountAtomic: "50000",
    payer: PAYER,
    payee: PAYEE,
    network: "eip155:8453",
    asset: USDC,
    paymentNonce: `0x${"01".repeat(32)}`,
    validBeforeMs: NOW + 30_000,
    ...overrides,
  };
}

function binding(record) {
  return {
    reservationId: record.reservationId,
    installationId: record.installationId,
    idempotencyKey: record.idempotencyKey,
    callSha256: record.callSha256,
  };
}

test("separate database handles atomically enforce one operator-pinned period cap", async (t) => {
  const fx = await fixture(t, {
    maxPeriodAtomic: "50000",
    maxOutstandingAtomic: "50000",
    maxOutstandingCount: 2,
  });
  const other = fx.open();
  const results = await Promise.allSettled([
    fx.store.reserve(reservation({ idempotencyKey: "atomic-a" })),
    other.reserve(reservation({ idempotencyKey: "atomic-b", callSha256: HASH_B, paymentNonce: `0x${"02".repeat(32)}` })),
  ]);
  assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
  const rejection = results.find(({ status }) => status === "rejected").reason;
  assert.equal(rejection.code, "payment_policy_denied");
  assert.match(rejection.message, /period cap/);

  assert.throws(
    () => new SqlitePaymentBudgetStore({
      filename: fx.store.filename,
      periodSeconds: 3600,
      maxPeriodAtomic: "100000",
      maxOutstandingAtomic: "50000",
      maxOutstandingCount: 2,
      clock: () => NOW,
    }),
    (error) => error.code === "local_state_error" && /pinned/.test(error.message),
  );
});

test("fresh idempotency keys cannot bypass cumulative or outstanding amount/count limits", async (t) => {
  const fx = await fixture(t);
  const first = await fx.store.reserve(reservation({ idempotencyKey: "fresh-a" }));
  const second = await fx.store.reserve(reservation({ idempotencyKey: "fresh-b", callSha256: HASH_B, paymentNonce: `0x${"02".repeat(32)}` }));
  assert.equal(first.status, "RESERVED");
  assert.equal(second.status, "RESERVED");

  await assert.rejects(
    () => fx.store.reserve(reservation({ idempotencyKey: "fresh-c", paymentNonce: `0x${"03".repeat(32)}` })),
    (error) => error.code === "payment_policy_denied" && /count/.test(error.message),
  );
  await fx.store.releaseUntransmitted(binding(second));
  await assert.rejects(
    () => fx.store.reserve(reservation({ idempotencyKey: "fresh-d", amountAtomic: "50001", paymentNonce: `0x${"04".repeat(32)}` })),
    (error) => error.code === "payment_policy_denied" && /amount/.test(error.message),
  );
  const snapshot = await fx.store.snapshot();
  assert.equal(snapshot.periodExposureAtomic, "50000");
  assert.equal(snapshot.outstandingAmountAtomic, "50000");
  assert.equal(snapshot.outstandingCount, 1);
});

test("a transmitted payment stays reserved through timeout and becomes charged unknown at validBefore", async (t) => {
  const fx = await fixture(t);
  const reserved = await fx.store.reserve(reservation());
  const transmitted = await fx.store.markTransmitted(binding(reserved));
  assert.equal(transmitted.status, "TRANSMITTED");
  await assert.rejects(
    () => fx.store.releaseUntransmitted(binding(reserved)),
    (error) => error.code === "local_state_error" && /definitely untransmitted/.test(error.message),
  );

  fx.setNow(NOW + 30_001);
  const snapshot = await fx.store.snapshot();
  assert.equal(snapshot.reservations[0].status, "EXPIRED_UNKNOWN");
  assert.equal(snapshot.outstandingAmountAtomic, "0");
  assert.equal(snapshot.outstandingCount, 0);
  assert.equal(snapshot.periodExposureAtomic, "50000", "expired ambiguity remains conservatively charged to the period");
});

test("settlement commits only a transmitted reservation with valid proof identity", async (t) => {
  const fx = await fixture(t);
  const reserved = await fx.store.reserve(reservation());
  await assert.rejects(
    () => fx.store.commitSettlement({ ...binding(reserved), transaction: TX }),
    (error) => error.code === "local_state_error" && /RESERVED -> SETTLED/.test(error.message),
  );
  await fx.store.markTransmitted(binding(reserved));
  await assert.rejects(
    () => fx.store.commitSettlement({ ...binding(reserved), transaction: "0x1234" }),
    (error) => error.code === "invalid_input",
  );
  const settled = await fx.store.commitSettlement({ ...binding(reserved), transaction: TX });
  assert.equal(settled.status, "SETTLED");
  assert.equal(settled.transaction, TX);
  const replay = await fx.store.commitSettlement({ ...binding(reserved), transaction: TX });
  assert.equal(replay.status, "SETTLED");
});

test("only definite non-transmission or explicit operator resolution releases exposure", async (t) => {
  const fx = await fixture(t);
  const untransmitted = await fx.store.reserve(reservation({ idempotencyKey: "not-sent" }));
  const released = await fx.store.releaseUntransmitted(binding(untransmitted));
  assert.equal(released.status, "RELEASED_UNTRANSMITTED");

  const ambiguous = await fx.store.reserve(reservation({ idempotencyKey: "ambiguous", callSha256: HASH_B, paymentNonce: `0x${"02".repeat(32)}` }));
  await fx.store.markTransmitted(binding(ambiguous));
  const resolved = await fx.store.resolve({ reservationId: ambiguous.reservationId, resolution: "NOT_SETTLED" });
  assert.equal(resolved.status, "RESOLVED_UNPAID");

  const snapshot = await fx.store.snapshot();
  assert.equal(snapshot.periodExposureAtomic, "0");
  assert.equal(snapshot.outstandingCount, 0);
  const next = await fx.store.reserve(reservation({ idempotencyKey: "after-resolution", paymentNonce: `0x${"03".repeat(32)}` }));
  assert.equal(next.status, "RESERVED");
});

test("reservation identity binds call, payer/payee, payment identity, and fixed period", async (t) => {
  const fx = await fixture(t);
  const record = await fx.store.reserve(reservation());
  assert.equal(record.installationId, INSTALLATION);
  assert.equal(record.idempotencyKey, "budget-call-0001");
  assert.equal(record.callSha256, HASH_A);
  assert.equal(record.amountAtomic, "50000");
  assert.equal(record.payer, PAYER);
  assert.equal(record.payee, PAYEE);
  assert.equal(record.network, "eip155:8453");
  assert.equal(record.asset, USDC);
  assert.equal(record.paymentNonce, `0x${"01".repeat(32)}`);
  assert.equal(record.periodStartMs, NOW);
  assert.equal(record.periodEndMs, NOW + 3_600_000);
  await assert.rejects(
    () => fx.store.markTransmitted({ ...binding(record), callSha256: HASH_B }),
    (error) => error.code === "local_state_error" && /binding/.test(error.message),
  );
});
