import assert from "node:assert/strict";
import test from "node:test";
import {
  AuthorizationServiceError,
  InvalidInputError,
  ResponseLimitError,
} from "../src/errors.mjs";
import { canonicalize } from "../src/canonical.mjs";
import { createGuardLifecycleHttpClient } from "../src/lifecycle-http.mjs";

const NOW = "2026-08-11T12:00:00.000Z";
const LATER = "2026-08-11T12:00:01.000Z";
const EXECUTION_ID = "receipt:00000001";
const INSTALLATION_ID = "install.production.1";
const CALL_HASH = "11".repeat(32);
const POLICY_HASH = "22".repeat(32);
const RECEIPT_HASH = "33".repeat(32);
const OUTCOME_HASH = "44".repeat(32);
const SIGNATURE = "A".repeat(86);

const receipt = Object.freeze({
  receipt_id: EXECUTION_ID,
  installation_id: INSTALLATION_ID,
  call_sha256: CALL_HASH,
  policy_sha256: POLICY_HASH,
  kind: "mcp_tool",
  decision: "ALLOW",
});

const paymentProof = Object.freeze({
  transaction: `0x${"ab".repeat(32)}`,
  payment_payload: Object.freeze({
    x402Version: 2,
    resource: { url: "https://guard.example/v1/guard/paygo/authorize/network" },
    accepted: {
      scheme: "exact",
      network: "eip155:8453",
      amount: "50000",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
      maxTimeoutSeconds: 30,
      extra: { name: "USD Coin", version: "2" },
    },
    payload: {
      authorization: {
        from: "0x0000000000000000000000000000000000000001",
        to: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
        value: "50000",
        validAfter: "0",
        validBefore: "1770000000",
        nonce: `0x${"cd".repeat(32)}`,
      },
      signature: `0x${"12".repeat(65)}`,
    },
  }),
});

const commit = Object.freeze({
  schema: "goldkey.guard-commit.v1",
  installation_id: INSTALLATION_ID,
  execution_id: EXECUTION_ID,
  receipt_id: EXECUTION_ID,
  receipt_sha256: RECEIPT_HASH,
  call_sha256: CALL_HASH,
  issued_at: NOW,
  signature: SIGNATURE,
});

const completion = Object.freeze({
  schema: "goldkey.guard-completion.v1",
  installation_id: INSTALLATION_ID,
  execution_id: EXECUTION_ID,
  receipt_id: EXECUTION_ID,
  receipt_sha256: RECEIPT_HASH,
  call_sha256: CALL_HASH,
  issued_at: LATER,
  outcome_status: "succeeded",
  outcome_sha256: OUTCOME_HASH,
  signature: SIGNATURE,
});

const commitAck = Object.freeze({
  replay: false,
  execution_id: EXECUTION_ID,
  installation_id: INSTALLATION_ID,
  policy_sha256: POLICY_HASH,
  call_sha256: CALL_HASH,
  decision: "ALLOW",
  status: "forwarding",
  committed_at: LATER,
});

const completionAck = Object.freeze({
  ...commitAck,
  status: "completed",
  outcome_status: "succeeded",
  outcome_sha256: OUTCOME_HASH,
  completed_at: "2026-08-11T12:00:02.000Z",
});

function client(fetchImpl) {
  return createGuardLifecycleHttpClient({
    serviceOrigin: "https://guard.example",
    fetchImpl,
  });
}

function response(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("lifecycle client derives hosted routes from the signed execution and validates exact acknowledgments", async () => {
  const calls = [];
  const lifecycle = client(async (url, options) => {
    calls.push({ url, options });
    return response(calls.length === 1 ? commitAck : completionAck);
  });

  assert.deepEqual(await lifecycle.commitAuthorization(commit, { receipt }), commitAck);
  assert.deepEqual(await lifecycle.completeAuthorization(completion, { receipt }), completionAck);
  assert.equal(calls[0].url, "https://guard.example/v1/guard/executions/receipt%3A00000001/commit");
  assert.equal(calls[1].url, "https://guard.example/v1/guard/executions/receipt%3A00000001/complete");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(Buffer.from(calls[0].options.body).toString(), canonicalize(commit));
  assert.equal(Buffer.from(calls[1].options.body).toString(), canonicalize(completion));
});

test("paid commit uses the normal endpoint first and reconciles only an exact payment-not-settled response", async () => {
  const calls = [];
  const lifecycle = client(async (url, options) => {
    calls.push({ url, options });
    if (calls.length === 1) return response({ error: { code: "guard_payment_not_settled" } }, 409);
    return response(commitAck);
  });
  assert.deepEqual(await lifecycle.commitAuthorization(commit, { receipt, paymentProof }), commitAck);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://guard.example/v1/guard/executions/receipt%3A00000001/commit");
  assert.equal(Buffer.from(calls[0].options.body).toString(), canonicalize(commit));
  assert.equal(calls[1].url, "https://guard.example/v1/guard/executions/receipt%3A00000001/reconcile-commit");
  assert.equal(Buffer.from(calls[1].options.body).toString(), canonicalize({
    schema: "goldkey.guard-reconciled-commit.v1",
    commit,
    payment_proof: paymentProof,
  }));
});

test("paid commit does not submit payment proof when the normal commit succeeds", async () => {
  const calls = [];
  const lifecycle = client(async (url, options) => {
    calls.push({ url, options });
    return response(commitAck);
  });
  await lifecycle.commitAuthorization(commit, { receipt, paymentProof });
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/commit$/);
  assert.equal(Buffer.from(calls[0].options.body).toString(), canonicalize(commit));
});

test("malformed paid reconciliation proof is rejected before lifecycle network I/O", async () => {
  let calls = 0;
  const lifecycle = client(async () => {
    calls += 1;
    return response(commitAck);
  });
  for (const invalid of [
    { ...paymentProof, transaction: "0x1234" },
    { ...paymentProof, payment_payload: { ...paymentProof.payment_payload, x402Version: 1 } },
    { ...paymentProof, payment_payload: { ...paymentProof.payment_payload, resource: { url: "https://attacker.example/" } } },
    { ...paymentProof, payment_payload: { ...paymentProof.payment_payload, accepted: { ...paymentProof.payment_payload.accepted, amount: "50001" } } },
  ]) {
    await assert.rejects(
      lifecycle.commitAuthorization(commit, { receipt, paymentProof: invalid }),
      (error) => error instanceof InvalidInputError || error instanceof ResponseLimitError,
    );
  }
  assert.equal(calls, 0);
});

test("lifecycle client rejects insecure or non-origin service locations", () => {
  for (const serviceOrigin of [
    "http://guard.example",
    "https://user:pass@guard.example",
    "https://guard.example/",
    "https://guard.example/path",
    "https://guard.example?query=1",
    "https://guard.example#fragment",
  ]) {
    assert.throws(
      () => createGuardLifecycleHttpClient({ serviceOrigin, fetchImpl: fetch }),
      InvalidInputError,
    );
  }
});

test("lifecycle client rejects empty, non-JSON, non-object, non-2xx, and oversized acknowledgments", async () => {
  const cases = [
    async () => new Response(null, { status: 204 }),
    async () => new Response("not-json", { status: 200 }),
    async () => response([commitAck]),
    async () => new Response("no", { status: 409 }),
  ];
  for (const fetchImpl of cases) {
    await assert.rejects(
      client(fetchImpl).commitAuthorization(commit, { receipt }),
      AuthorizationServiceError,
    );
  }
  await assert.rejects(
    client(async () => new Response(Buffer.alloc(64 * 1024 + 1))).commitAuthorization(commit, { receipt }),
    ResponseLimitError,
  );
});

test("commit acknowledgment fails closed on every authorization binding mismatch", async () => {
  const mutations = [
    { execution_id: "wrong-execution" },
    { installation_id: "wrong-installation" },
    { call_sha256: "55".repeat(32) },
    { policy_sha256: "66".repeat(32) },
    { decision: "BLOCK" },
    { status: "denied" },
    { replay: "false" },
    { replay: true },
    { committed_at: null },
  ];
  for (const mutation of mutations) {
    await assert.rejects(
      client(async () => response({ ...commitAck, ...mutation })).commitAuthorization(commit, { receipt }),
      (error) => error instanceof AuthorizationServiceError && /exact ALLOW authorization/.test(error.message),
    );
  }
});

test("completion acknowledgment must match the exact signed outcome", async () => {
  for (const mutation of [
    { outcome_status: "failed" },
    { outcome_sha256: "77".repeat(32) },
    { completed_at: null },
  ]) {
    await assert.rejects(
      client(async () => response({ ...completionAck, ...mutation })).completeAuthorization(completion, { receipt }),
      (error) => error instanceof AuthorizationServiceError && /signed outcome/.test(error.message),
    );
  }
});

test("malformed or receipt-mismatched lifecycle envelopes are rejected before network I/O", async () => {
  let calls = 0;
  const lifecycle = client(async () => {
    calls += 1;
    return response(commitAck);
  });
  for (const [envelope, context] of [
    [{ ...commit, execution_id: "wrong" }, { receipt }],
    [{ ...commit, call_sha256: "88".repeat(32) }, { receipt }],
    [{ ...commit, signature: "invalid" }, { receipt }],
    [commit, { receipt: { ...receipt, decision: "BLOCK" } }],
    [commit, {}],
  ]) {
    await assert.rejects(
      lifecycle.commitAuthorization(envelope, context),
      InvalidInputError,
    );
  }
  assert.equal(calls, 0);
});
