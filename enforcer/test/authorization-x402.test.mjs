import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { privateKeyToAccount } from "viem/accounts";
import {
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import { createGuardReceiptSigner } from "../../src/guard-receipt.mjs";
import { validateGuardRequest } from "../../src/guard.mjs";
import {
  BASE_MAINNET_USDC,
  BASE_MAINNET_X402_NETWORK,
  GUARD_EVM_PAYMENT_ATOMIC,
  GUARD_NETWORK_PAYMENT_ATOMIC,
  RemoteAuthorizer,
} from "../src/authorization.mjs";
import { createInstallationIdentity } from "../src/identity.mjs";
import { SqlitePaymentBudgetStore } from "../src/payment-budget.mjs";
import { hashGuardCall } from "../src/protocol.mjs";

const NOW = Date.parse("2026-08-11T12:00:00.000Z");
const AUTHORIZE_URL = "https://guard.goldkey.example/v1/guard/paygo/authorize/network";
const POLICY_HASH = "a".repeat(64);
const SCHEMA_HASH = "b".repeat(64);
const TREASURY = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const OTHER = "0x0000000000000000000000000000000000000011";
const PAYMENT_STORES = [];

after(() => {
  for (const { store, directory } of PAYMENT_STORES) {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

function paymentBudgetStore(overrides = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), "goldkey-payment-budget-"));
  const store = new SqlitePaymentBudgetStore({
    filename: path.join(directory, "budget.sqlite"),
    periodSeconds: 3600,
    maxPeriodAtomic: "1000000",
    maxOutstandingAtomic: "500000",
    maxOutstandingCount: 10,
    ...overrides,
  });
  PAYMENT_STORES.push({ store, directory });
  return store;
}

function receiptSigner() {
  const { privateKey } = generateKeyPairSync("ed25519");
  return createGuardReceiptSigner({
    privateKeyPkcs8Base64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    keyId: "receipt-key-v1",
    clock: () => NOW,
    idGenerator: () => "receipt-00000001",
  });
}

function mcpCall() {
  return {
    kind: "mcp_tool",
    connector_id: "trusted-mcp",
    tool: "send_message",
    input_schema_sha256: SCHEMA_HASH,
    arguments: { message: "hello" },
  };
}

function evmCall() {
  return {
    kind: "evm_transaction",
    connector_id: "trusted-wallet",
    transaction: {
      chain_id: 8453,
      from: TREASURY,
      to: OTHER,
      value_atomic: "0",
      data: "0x",
      nonce: "1",
      gas_limit: "21000",
      max_fee_per_gas_atomic: "1000000",
      max_priority_fee_per_gas_atomic: "100000",
      type: "eip1559",
      access_list: [],
    },
  };
}

function challenge({ amount = GUARD_NETWORK_PAYMENT_ATOMIC, resource = AUTHORIZE_URL, ...optionOverrides } = {}, challengeOverrides = {}) {
  return {
    x402Version: 2,
    resource: { url: resource },
    accepts: [{
      scheme: "exact",
      network: BASE_MAINNET_X402_NETWORK,
      amount,
      asset: BASE_MAINNET_USDC,
      payTo: TREASURY,
      maxTimeoutSeconds: 30,
      extra: { name: "USD Coin", version: "2" },
      ...optionOverrides,
    }],
    ...challengeOverrides,
  };
}

function paymentRequiredResponse(value) {
  return new Response("{}", {
    status: 402,
    headers: {
      "content-type": "application/json",
      "payment-required": Buffer.from(JSON.stringify(value), "utf8").toString("base64"),
    },
  });
}

function authorizationResponse({ request, signer, paymentResponse }) {
  const evidence = {
    schema: "goldkey.guard-evidence.v1",
    decision: "ALLOW",
    reason_codes: [],
    effect: request.call.kind === "evm_transaction" ? "payment" : "write",
    destination: request.call.kind === "evm_transaction"
      ? `eip155:8453:${request.call.transaction.to}`
      : `mcp://trusted-server/${request.call.tool}`,
  };
  const envelope = signer.signAuthorization({
    installation_id: request.installation_id,
    idempotency_key: request.idempotency_key,
    connector_id: request.call.connector_id,
    kind: request.call.kind,
    policy_id: "operator-policy",
    policy_version: 1,
    policy_sha256: POLICY_HASH,
    call_sha256: hashGuardCall(request.call),
    decision: "ALLOW",
    reason_codes: [],
    evidence,
    ttl_ms: 30_000,
  });
  return new Response(JSON.stringify(envelope), {
    status: 200,
    headers: {
      "content-type": "application/json",
      ...(paymentResponse === undefined ? {} : { "payment-response": encodePaymentResponseHeader(paymentResponse) }),
    },
  });
}

function createTransport({
  fetchImpl,
  maxAmountAtomic = GUARD_EVM_PAYMENT_ATOMIC,
  timeoutMs = 30_000,
  budgetStore = paymentBudgetStore(),
  signTypedDataImpl,
} = {}) {
  const installationIdentity = createInstallationIdentity();
  const signer = receiptSigner();
  const payer = privateKeyToAccount(`0x${"42".repeat(32)}`);
  let signatures = 0;
  const authorizer = new RemoteAuthorizer({
    authorizeUrl: AUTHORIZE_URL,
    fetchImpl,
    installationIdentity,
    receiptKeyset: signer.keyset,
    policyHash: POLICY_HASH,
    payment: {
      signer: {
        address: payer.address,
        async signTypedData(typedData) {
          signatures += 1;
          return signTypedDataImpl === undefined
            ? payer.signTypedData(typedData)
            : signTypedDataImpl(typedData, payer, signatures);
        },
      },
      treasuryAddress: TREASURY,
      maxAmountAtomic,
      timeoutMs,
      budgetStore,
    },
    clock: () => NOW,
  });
  return { authorizer, installationIdentity, signer, payer, budgetStore, signatures: () => signatures };
}

test("valid exact Base-USDC challenge signs locally and retries exactly once", async (t) => {
  for (const { name, call, amount } of [
    { name: "network", call: mcpCall(), amount: GUARD_NETWORK_PAYMENT_ATOMIC },
    { name: "evm", call: evmCall(), amount: GUARD_EVM_PAYMENT_ATOMIC },
  ]) {
    await t.test(name, async () => {
      let calls = 0;
      let transport;
      let sentPaymentPayload;
      const transaction = `0x${"12".repeat(32)}`;
      const fetchImpl = async (_url, init) => {
        calls += 1;
        const request = validateGuardRequest(JSON.parse(Buffer.from(init.body).toString("utf8")));
        const paymentHeader = Object.entries(init.headers).find(([key]) => key.toLowerCase() === "payment-signature")?.[1];
        if (calls === 1) {
          assert.equal(paymentHeader, undefined);
          return paymentRequiredResponse(challenge({ amount }));
        }
        assert.equal(calls, 2, "authorization transport must make at most one paid retry");
        assert.equal(typeof paymentHeader, "string");
        assert.ok(paymentHeader.length > 0);
        sentPaymentPayload = decodePaymentSignatureHeader(paymentHeader);
        return authorizationResponse({
          request,
          signer: transport.signer,
          paymentResponse: {
            success: true,
            payer: transport.payer.address,
            transaction,
            network: BASE_MAINNET_X402_NETWORK,
            amount,
          },
        });
      };
      transport = createTransport({ fetchImpl });
      const result = await transport.authorizer.authorize({
        call,
        idempotencyKey: `guard-${name}-payment-0001`,
        deadlineAt: NOW + 30_000,
      });
      assert.equal(result.receipt.decision, "ALLOW");
      assert.deepEqual(result.paymentProof, {
        transaction,
        payment_payload: sentPaymentPayload,
      });
      assert.equal(Object.isFrozen(result.paymentProof), true);
      assert.equal(Object.isFrozen(result.paymentProof.payment_payload), true);
      assert.equal(calls, 2);
      assert.equal(transport.signatures(), 1);
    });
  }
});

test("paid authorization rejects missing or mismatched settlement proof after one bounded retry", async (t) => {
  const cases = [
    ["missing header", undefined],
    ["failed", { success: false, transaction: `0x${"13".repeat(32)}`, network: BASE_MAINNET_X402_NETWORK }],
    ["wrong network", { success: true, transaction: `0x${"14".repeat(32)}`, network: "eip155:84532" }],
    ["wrong payer", { success: true, payer: OTHER, transaction: `0x${"15".repeat(32)}`, network: BASE_MAINNET_X402_NETWORK }],
    ["wrong amount", { success: true, transaction: `0x${"16".repeat(32)}`, network: BASE_MAINNET_X402_NETWORK, amount: "50001" }],
    ["invalid transaction", { success: true, transaction: "0x1234", network: BASE_MAINNET_X402_NETWORK }],
  ];
  for (const [name, paymentResponse] of cases) {
    await t.test(name, async () => {
      let calls = 0;
      let transport;
      const fetchImpl = async (_url, init) => {
        calls += 1;
        const request = validateGuardRequest(JSON.parse(Buffer.from(init.body).toString("utf8")));
        if (calls === 1) return paymentRequiredResponse(challenge());
        return authorizationResponse({ request, signer: transport.signer, paymentResponse });
      };
      transport = createTransport({ fetchImpl });
      await assert.rejects(
        () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: `bad-proof-${name.replaceAll(" ", "-")}-0001`, deadlineAt: NOW + 30_000 }),
        (error) => ["authorization_service_error", "payment_policy_denied"].includes(error.code),
      );
      assert.equal(calls, 2);
      assert.equal(transport.signatures(), 1);
    });
  }
});

test("invalid or substituted challenge never signs and never retries", async (t) => {
  const cases = [
    ["resource", challenge({ resource: "https://attacker.example/authorize" })],
    ["version", challenge({}, { x402Version: 1 })],
    ["multiple offers", { ...challenge(), accepts: [...challenge().accepts, ...challenge().accepts] }],
    ["scheme", challenge({ scheme: "upto" })],
    ["network", challenge({ network: "eip155:84532" })],
    ["asset", challenge({ asset: OTHER })],
    ["payee", challenge({ payTo: OTHER })],
    ["amount", challenge({ amount: "50001" })],
    ["timeout", challenge({ maxTimeoutSeconds: 31 })],
    ["transfer method", challenge({ extra: { name: "USD Coin", version: "2", assetTransferMethod: "permit2" } })],
    ["domain", challenge({ extra: { name: "Fake USD", version: "2" } })],
  ];
  for (const [name, invalidChallenge] of cases) {
    await t.test(name, async () => {
      let calls = 0;
      const transport = createTransport({
        fetchImpl: async () => {
          calls += 1;
          if (calls > 1) throw new Error("invalid challenge must never retry");
          return paymentRequiredResponse(invalidChallenge);
        },
      });
      await assert.rejects(
        () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: `invalid-${name.replaceAll(" ", "-")}-0001`, deadlineAt: NOW + 30_000 }),
        (error) => error.code === "payment_policy_denied",
      );
      assert.equal(calls, 1);
      assert.equal(transport.signatures(), 0);
    });
  }
});

test("local per-call maximum blocks an otherwise valid challenge before signing", async () => {
  let calls = 0;
  const transport = createTransport({
    maxAmountAtomic: "49999",
    fetchImpl: async () => {
      calls += 1;
      return paymentRequiredResponse(challenge());
    },
  });
  await assert.rejects(
    () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "local-cap-0001", deadlineAt: NOW + 30_000 }),
    (error) => error.code === "payment_policy_denied" && /local per-call/.test(error.message),
  );
  assert.equal(calls, 1);
  assert.equal(transport.signatures(), 0);
});

test("a second 402 stops after one signature and one paid retry", async () => {
  let calls = 0;
  const transport = createTransport({
    fetchImpl: async () => {
      calls += 1;
      if (calls > 2) throw new Error("authorization transport attempted a forbidden second retry");
      return paymentRequiredResponse(challenge());
    },
  });
  await assert.rejects(
    () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "still-402-0001", deadlineAt: NOW + 30_000 }),
    (error) => error.code === "authorization_service_error" && /single permitted/.test(error.message),
  );
  assert.equal(calls, 2);
  assert.equal(transport.signatures(), 1);
});

test("authorization timeout aborts an injected fetch that ignores AbortSignal", async () => {
  const started = performance.now();
  const transport = createTransport({
    timeoutMs: 5,
    fetchImpl: async () => new Promise(() => {}),
  });
  await assert.rejects(
    () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "timeout-transport-0001", deadlineAt: NOW + 30_000 }),
    (error) => error.code === "deadline_exceeded",
  );
  assert.ok(performance.now() - started < 250, "timeout must not rely on injected fetch honoring AbortSignal");
  assert.equal(transport.signatures(), 0);
});

test("cumulative period cap cannot be bypassed with a fresh idempotency key", async () => {
  let calls = 0;
  let transport;
  const budgetStore = paymentBudgetStore({
    maxPeriodAtomic: GUARD_NETWORK_PAYMENT_ATOMIC,
    maxOutstandingAtomic: GUARD_NETWORK_PAYMENT_ATOMIC,
    maxOutstandingCount: 1,
  });
  const fetchImpl = async (_url, init) => {
    calls += 1;
    const request = validateGuardRequest(JSON.parse(Buffer.from(init.body).toString("utf8")));
    const paymentHeader = Object.entries(init.headers).find(([key]) => key.toLowerCase() === "payment-signature")?.[1];
    if (!paymentHeader) return paymentRequiredResponse(challenge());
    return authorizationResponse({
      request,
      signer: transport.signer,
      paymentResponse: {
        success: true,
        payer: transport.payer.address,
        transaction: `0x${"31".repeat(32)}`,
        network: BASE_MAINNET_X402_NETWORK,
        amount: GUARD_NETWORK_PAYMENT_ATOMIC,
      },
    });
  };
  transport = createTransport({ fetchImpl, budgetStore });
  await transport.authorizer.authorize({
    call: mcpCall(),
    idempotencyKey: "period-budget-first",
    deadlineAt: NOW + 30_000,
  });
  await assert.rejects(
    () => transport.authorizer.authorize({
      call: mcpCall(),
      idempotencyKey: "period-budget-fresh-key",
      deadlineAt: NOW + 30_000,
    }),
    (error) => error.code === "payment_policy_denied" && /period cap/.test(error.message),
  );
  assert.equal(transport.signatures(), 1, "the over-cap request must be rejected before signTypedData");
  assert.equal(calls, 3);
  const snapshot = await budgetStore.snapshot();
  assert.equal(snapshot.periodExposureAtomic, GUARD_NETWORK_PAYMENT_ATOMIC);
  assert.equal(snapshot.reservations[0].status, "SETTLED");
});

test("missing settlement proof remains ambiguous and blocks a fresh-key payment before signing", async () => {
  let transport;
  const budgetStore = paymentBudgetStore({
    maxPeriodAtomic: "1000000",
    maxOutstandingAtomic: GUARD_NETWORK_PAYMENT_ATOMIC,
    maxOutstandingCount: 1,
  });
  const fetchImpl = async (_url, init) => {
    const request = validateGuardRequest(JSON.parse(Buffer.from(init.body).toString("utf8")));
    const paymentHeader = Object.entries(init.headers).find(([key]) => key.toLowerCase() === "payment-signature")?.[1];
    if (!paymentHeader) return paymentRequiredResponse(challenge());
    return authorizationResponse({ request, signer: transport.signer, paymentResponse: undefined });
  };
  transport = createTransport({ fetchImpl, budgetStore });
  await assert.rejects(
    () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "ambiguous-first", deadlineAt: NOW + 30_000 }),
    (error) => error.code === "authorization_service_error" && /PAYMENT-RESPONSE/.test(error.message),
  );
  await assert.rejects(
    () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "ambiguous-fresh-key", deadlineAt: NOW + 30_000 }),
    (error) => error.code === "payment_policy_denied" && /count/.test(error.message),
  );
  assert.equal(transport.signatures(), 1);
  const snapshot = await budgetStore.snapshot();
  assert.equal(snapshot.outstandingCount, 1);
  assert.equal(snapshot.reservations[0].status, "TRANSMITTED");
});

test("signer failure releases only the definitely untransmitted reservation", async () => {
  let transport;
  const budgetStore = paymentBudgetStore({
    maxPeriodAtomic: GUARD_NETWORK_PAYMENT_ATOMIC,
    maxOutstandingAtomic: GUARD_NETWORK_PAYMENT_ATOMIC,
    maxOutstandingCount: 1,
  });
  const fetchImpl = async (_url, init) => {
    const request = validateGuardRequest(JSON.parse(Buffer.from(init.body).toString("utf8")));
    const paymentHeader = Object.entries(init.headers).find(([key]) => key.toLowerCase() === "payment-signature")?.[1];
    if (!paymentHeader) return paymentRequiredResponse(challenge());
    return authorizationResponse({
      request,
      signer: transport.signer,
      paymentResponse: {
        success: true,
        transaction: `0x${"32".repeat(32)}`,
        network: BASE_MAINNET_X402_NETWORK,
        amount: GUARD_NETWORK_PAYMENT_ATOMIC,
      },
    });
  };
  transport = createTransport({
    fetchImpl,
    budgetStore,
    signTypedDataImpl: (typedData, payer, attempt) => {
      if (attempt === 1) throw new Error("local signer unavailable");
      return payer.signTypedData(typedData);
    },
  });
  await assert.rejects(
    () => transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "sign-failed", deadlineAt: NOW + 30_000 }),
    (error) => error.code === "authorization_service_error",
  );
  const afterFailure = await budgetStore.snapshot();
  assert.equal(afterFailure.periodExposureAtomic, "0");
  assert.equal(afterFailure.reservations[0].status, "RELEASED_UNTRANSMITTED");

  const result = await transport.authorizer.authorize({ call: mcpCall(), idempotencyKey: "sign-retry-new-key", deadlineAt: NOW + 30_000 });
  assert.equal(result.receipt.decision, "ALLOW");
  assert.equal(transport.signatures(), 2);
});

test("paid RemoteAuthorizer refuses construction without a durable budget store", () => {
  const installationIdentity = createInstallationIdentity();
  const signer = receiptSigner();
  const payer = privateKeyToAccount(`0x${"43".repeat(32)}`);
  assert.throws(
    () => new RemoteAuthorizer({
      authorizeUrl: AUTHORIZE_URL,
      fetchImpl: async () => new Response("{}"),
      installationIdentity,
      receiptKeyset: signer.keyset,
      policyHash: POLICY_HASH,
      payment: {
        signer: payer,
        treasuryAddress: TREASURY,
        maxAmountAtomic: GUARD_NETWORK_PAYMENT_ATOMIC,
      },
      clock: () => NOW,
    }),
    (error) => error.code === "invalid_input" && /budgetStore/.test(error.message),
  );
});
