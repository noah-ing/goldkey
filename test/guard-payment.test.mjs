import assert from "node:assert/strict";
import test from "node:test";
import {
  BASE_MAINNET_USDC,
  guardPaymentBinding,
  validateGuardReconciledCommit,
} from "../src/guard-payment.mjs";

const ORIGIN = "https://goldkey.example";
const PATH = "/v1/guard/paygo/authorize/network";
const TREASURY = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const PAYER = "0x0000000000000000000000000000000000000021";
const config = {
  chainId: 8453,
  publicOrigin: ORIGIN,
  usdcAddress: BASE_MAINNET_USDC,
  treasuryAddress: TREASURY,
  guardNetworkPriceUsd: "0.05",
  guardEvmPriceUsd: "0.10",
};

function paymentPayload() {
  const accepted = {
    scheme: "exact",
    network: "eip155:8453",
    asset: BASE_MAINNET_USDC,
    amount: "50000",
    payTo: TREASURY,
    maxTimeoutSeconds: 30,
    extra: { name: "USD Coin", version: "2" },
  };
  return {
    x402Version: 2,
    resource: { url: `${ORIGIN}${PATH}` },
    accepted,
    payload: {
      authorization: {
        from: PAYER,
        to: TREASURY,
        value: "50000",
        validAfter: "0",
        validBefore: "2000000000",
        nonce: `0x${"31".repeat(32)}`,
      },
      signature: `0x${"11".repeat(65)}`,
    },
  };
}

test("Guard payment binding freezes the exact resource and a wrapper-independent EIP-3009 identity", () => {
  const payload = paymentPayload();
  const first = guardPaymentBinding(payload, { config, path: PATH, requirements: payload.accepted });
  const enriched = structuredClone(payload);
  enriched.resource.description = "same signed authorization, altered unsigned wrapper";
  const second = guardPaymentBinding(enriched, { config, path: PATH, requirements: enriched.accepted });
  assert.notEqual(first.payment_sha256, second.payment_sha256);
  assert.equal(first.payment_identity_sha256, second.payment_identity_sha256);
  assert.equal(first.authorization.value, "50000");
  assert.equal(first.authorization.nonce, `0x${"31".repeat(32)}`);
});

test("Guard payment binding rejects route, price, treasury, asset, and facilitator requirement substitution", () => {
  const cases = [
    ["resource", (payload) => { payload.resource.url = `${ORIGIN}/v1/action-gate`; }, "guard_payment_resource_mismatch"],
    ["price", (payload) => { payload.accepted.amount = "1"; }, "guard_payment_amount_mismatch"],
    ["treasury", (payload) => { payload.payload.authorization.to = PAYER; }, "guard_payment_recipient_mismatch"],
    ["asset", (payload) => { payload.accepted.asset = PAYER; }, "guard_payment_asset_mismatch"],
    ["signature", (payload) => { payload.payload.signature = "0x12"; }, "invalid_guard_payment_proof"],
  ];
  for (const [name, mutate, code] of cases) {
    const payload = paymentPayload();
    mutate(payload);
    assert.throws(
      () => guardPaymentBinding(payload, { config, path: PATH }),
      (error) => error.code === code,
      name,
    );
  }
  const payload = paymentPayload();
  assert.throws(
    () => guardPaymentBinding(payload, { config, path: PATH, requirements: { ...payload.accepted, amount: "1" } }),
    (error) => error.code === "guard_payment_requirements_mismatch",
  );
});

test("reconciled commit envelope is closed and carries only existing commit plus bounded public payment proof", () => {
  const value = {
    schema: "goldkey.guard-reconciled-commit.v1",
    commit: { schema: "goldkey.guard-commit.v1" },
    payment_proof: { transaction: `0x${"ab".repeat(32)}`, payment_payload: paymentPayload() },
  };
  assert.equal(validateGuardReconciledCommit(value).payment_proof.transaction, `0x${"ab".repeat(32)}`);
  assert.throws(
    () => validateGuardReconciledCommit({ ...value, private_key: "forbidden" }),
    (error) => error.code === "invalid_guard_payment_proof",
  );
});
