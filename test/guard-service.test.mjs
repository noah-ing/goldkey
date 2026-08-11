import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { encodeFunctionData, parseAbi, verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { GoldKeyDatabase } from "../src/database.mjs";
import { BASE_GAS_PRICE_ORACLE, EVM_SIMULATION_SCHEMA, hashEvmTransaction } from "../src/evm-guard.mjs";
import {
  GUARD_INSTALLATION_SCHEMA,
  GUARD_POLICY_SCHEMA,
  GUARD_REVOCATION_SCHEMA,
  guardInstallationId,
  guardInstallationKeyProofMessage,
  guardInstallationSigningMessage,
  guardPolicySigningMessage,
  guardRevocationSigningMessage,
  hashGuardPolicy,
} from "../src/guard-policy.mjs";
import { createGuardReceiptSigner, verifyGuardAuthorizationReceipt } from "../src/guard-receipt.mjs";
import { createGuardService } from "../src/guard-service.mjs";
import {
  GUARD_COMMIT_SCHEMA,
  GUARD_COMPLETION_SCHEMA,
  GUARD_REQUEST_SCHEMA,
  guardCommitSigningMessage,
  guardCompletionSigningMessage,
  guardRequestSigningMessage,
} from "../src/guard.mjs";

const NOW = Date.parse("2026-08-11T12:00:00.000Z");
const ORIGIN = "https://goldkey.example";
const operator = privateKeyToAccount(`0x${"71".repeat(32)}`);
const TOKEN = "0x0000000000000000000000000000000000000013";
const RECIPIENT = "0x0000000000000000000000000000000000000014";
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAYMENT_PAYER = "0x0000000000000000000000000000000000000021";
const SCHEMA_HASH = "ab".repeat(32);
const ERC20_ABI = parseAbi(["function transfer(address to, uint256 amount) returns (bool)"]);

function createFixture({ allowedOperatorWallets = [] } = {}) {
  let now = NOW;
  let receiptSequence = 0;
  const db = new GoldKeyDatabase();
  const installationKeys = generateKeyPairSync("ed25519");
  const installationPublic = installationKeys.publicKey.export({ format: "jwk" });
  const installationPublicJwk = { kty: installationPublic.kty, crv: installationPublic.crv, x: installationPublic.x };
  const installationId = guardInstallationId(installationPublicJwk);
  const receiptPrivate = generateKeyPairSync("ed25519").privateKey;
  const signer = createGuardReceiptSigner({
    privateKeyPkcs8Base64: receiptPrivate.export({ format: "der", type: "pkcs8" }).toString("base64"),
    keyId: "guard-receipt-test",
    clock: () => now,
    idGenerator: () => `receipt.${++receiptSequence}`,
  });
  let simulationCalls = 0;
  const paymentVerificationCalls = [];
  const chain = {
    verifyWalletMessage: ({ wallet, message, signature }) => verifyMessage({ address: wallet, message, signature }),
    verifyGuardPaymentTransaction: async (proof) => {
      paymentVerificationCalls.push(proof);
      return { transaction: proof.transaction, payer: proof.authorization.from };
    },
  };
  const service = createGuardService({
    config: {
      guardEnabled: true,
      publicOrigin: ORIGIN,
      guardAuthorizationTtlMs: 60_000,
      guardAllowedOperatorWallets: [operator.address.toLowerCase(), ...allowedOperatorWallets.map((wallet) => wallet.toLowerCase())],
      chainId: 8453,
      usdcAddress: BASE_USDC,
      treasuryAddress: operator.address,
      guardNetworkPriceUsd: "0.05",
      guardEvmPriceUsd: "0.10",
    },
    db,
    chain,
    receiptSigner: signer,
    clock: () => now,
    simulateEvmTransaction: async (transaction) => {
      simulationCalls += 1;
      return {
        schema: EVM_SIMULATION_SCHEMA,
        status: "success",
        chain_id: transaction.chain_id,
        transaction_sha256: hashEvmTransaction(transaction),
        block_number: "1234",
        block_hash: `0x${"12".repeat(32)}`,
        target_code_sha256: "34".repeat(32),
        return_data_sha256: "56".repeat(32),
        gas_estimate: "55000",
        pending_nonce: transaction.nonce,
        l1_fee_estimate_atomic: "1000",
        operator_fee_estimate_atomic: "0",
        gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
      };
    },
  });

  function policyBody(version = 1) {
    return {
      schema: GUARD_POLICY_SCHEMA,
      policy_id: "policy.production",
      version,
      operator_wallet: operator.address,
      audience: ORIGIN,
      issued_at: new Date(NOW - 60_000).toISOString(),
      expires_at: new Date(NOW + 86_400_000).toISOString(),
      connectors: [
        {
          id: "mcp.billing",
          kind: "mcp_tool",
          server_id: "billing-server",
          tools: [{ name: "invoice.create", effect: "write", input_schema_sha256: SCHEMA_HASH }],
        },
        {
          id: "evm.usdc",
          kind: "evm_transaction",
          chain_id: 8453,
          from: operator.address,
          allowed_native_recipients: [],
          allowed_erc20_tokens: [TOKEN],
          allowed_erc20_recipients: [RECIPIENT],
          allowed_approval_spenders: [],
          max_native_value_atomic: "0",
          max_erc20_transfer_atomic: "1000",
          max_erc20_approval_atomic: "0",
          max_gas_limit: "100000",
          max_fee_per_gas_atomic: "100",
          max_priority_fee_per_gas_atomic: "10",
          max_total_fee_atomic: "5000000",
          fee_period_seconds: 86400,
          max_fee_period_atomic: "10000000",
          spend_period_seconds: 86400,
          max_period_atomic: "1500",
          require_simulation: true,
        },
      ],
    };
  }

  async function signedPolicy(version = 1) {
    const body = policyBody(version);
    return { ...body, signature: await operator.signMessage({ message: guardPolicySigningMessage(body) }) };
  }

  async function signedInstallation(policy) {
    const body = {
      schema: GUARD_INSTALLATION_SCHEMA,
      installation_id: installationId,
      operator_wallet: operator.address,
      policy_sha256: hashGuardPolicy(policy),
      public_key_jwk: installationPublicJwk,
      issued_at: new Date(NOW - 30_000).toISOString(),
      expires_at: new Date(NOW + 86_000_000).toISOString(),
    };
    return {
      ...body,
      signature: await operator.signMessage({ message: guardInstallationSigningMessage(body) }),
      key_proof: sign(null, Buffer.from(guardInstallationKeyProofMessage(body), "utf8"), installationKeys.privateKey).toString("base64url"),
    };
  }

  async function signedRevocation(targetKind, targetId, overrides = {}) {
    const body = {
      schema: GUARD_REVOCATION_SCHEMA,
      target_kind: targetKind,
      target_id: targetId,
      operator_wallet: operator.address,
      audience: ORIGIN,
      issued_at: new Date(now).toISOString(),
      ...overrides,
    };
    return { ...body, signature: await operator.signMessage({ message: guardRevocationSigningMessage(body) }) };
  }

  function signedRequest(call, idempotencyKey = "guard.request.0001") {
    const body = {
      schema: GUARD_REQUEST_SCHEMA,
      installation_id: installationId,
      idempotency_key: idempotencyKey,
      issued_at: new Date(now).toISOString(),
      call,
    };
    return {
      ...body,
      signature: sign(null, Buffer.from(guardRequestSigningMessage(body)), installationKeys.privateKey).toString("base64url"),
    };
  }

  function signedLifecycle(envelope, kind, overrides = {}) {
    const completion = kind === "completion";
    const body = {
      schema: completion ? GUARD_COMPLETION_SCHEMA : GUARD_COMMIT_SCHEMA,
      installation_id: envelope.receipt.installation_id,
      execution_id: envelope.receipt.receipt_id,
      receipt_id: envelope.receipt.receipt_id,
      receipt_sha256: envelope.receipt_sha256,
      call_sha256: envelope.receipt.call_sha256,
      issued_at: new Date(now).toISOString(),
      ...(completion ? { outcome_status: "succeeded", outcome_sha256: "77".repeat(32) } : {}),
      ...overrides,
    };
    const message = completion ? guardCompletionSigningMessage(body) : guardCommitSigningMessage(body);
    return { ...body, signature: sign(null, Buffer.from(message), installationKeys.privateKey).toString("base64url") };
  }

  function paymentContext(path = "/v1/guard/paygo/authorize/network", nonce = `0x${"31".repeat(32)}`) {
    const accepted = {
      scheme: "exact",
      network: "eip155:8453",
      asset: BASE_USDC,
      amount: path.endsWith("/evm") ? "100000" : "50000",
      payTo: operator.address,
      maxTimeoutSeconds: 30,
      extra: { name: "USD Coin", version: "2" },
    };
    return {
      path,
      requirements: accepted,
      paymentPayload: {
        x402Version: 2,
        resource: { url: `${ORIGIN}${path}` },
        accepted,
        payload: {
          authorization: {
            from: PAYMENT_PAYER,
            to: operator.address,
            value: accepted.amount,
            validAfter: "0",
            validBefore: "1786452000",
            nonce,
          },
          signature: `0x${"11".repeat(65)}`,
        },
      },
    };
  }

  return {
    db,
    service,
    signer,
    installationId,
    policyBody,
    signedPolicy,
    signedInstallation,
    signedRevocation,
    signedRequest,
    signedLifecycle,
    paymentContext,
    setNow: (value) => { now = value; },
    simulationCalls: () => simulationCalls,
    paymentVerificationCalls: () => [...paymentVerificationCalls],
  };
}

test("Guard service registers signed immutable config and completes an exact MCP lifecycle", async () => {
  const fixture = createFixture();
  const policy = await fixture.signedPolicy();
  assert.equal((await fixture.service.registerPolicy(policy)).replay, false);
  assert.equal((await fixture.service.registerPolicy(policy)).replay, true);
  assert.equal(
    fixture.db.getGuardPolicyVersionByHash(hashGuardPolicy(policy)).policy_id,
    `${operator.address.toLowerCase()}:policy.production`,
  );
  const installation = await fixture.signedInstallation(policy);
  assert.equal((await fixture.service.registerInstallation(installation)).replay, false);

  const request = fixture.signedRequest({
    kind: "mcp_tool",
    connector_id: "mcp.billing",
    tool: "invoice.create",
    input_schema_sha256: SCHEMA_HASH,
    arguments: { invoice_id: "INV-42" },
  });
  const envelope = await fixture.service.authorize(request, ["mcp_tool", "https"]);
  const verified = verifyGuardAuthorizationReceipt(envelope, { keyset: fixture.service.keyset, now: NOW + 1 });
  assert.equal(verified.receipt.decision, "ALLOW");
  assert.equal(verified.evidence.destination, "mcp://billing-server/invoice.create");
  assert.deepEqual(await fixture.service.authorize(request, ["mcp_tool", "https"]), envelope);
  const unpaidReplay = await fixture.service.preflight(request, ["mcp_tool", "https"]);
  assert.equal(unpaidReplay.replay, true);
  assert.equal(unpaidReplay.payment_settled, false);
  assert.equal(unpaidReplay.replay_authorization, undefined);
  await assert.rejects(
    () => fixture.service.recordPaymentSettlement(request, { success: false, transaction: `0x${"f".repeat(64)}` }, ["mcp_tool", "https"], "claim-1"),
    (error) => error.code === "guard_settlement_not_successful",
  );
  const paymentContext = fixture.paymentContext();
  await fixture.service.beginPaymentSettlement(request, ["mcp_tool", "https"], "claim-1", paymentContext);
  const settlement = await fixture.service.recordPaymentSettlement(
    request,
    { success: true, transaction: `0x${"a".repeat(64)}`, network: "eip155:8453", payer: PAYMENT_PAYER },
    ["mcp_tool", "https"],
    "claim-1",
    paymentContext,
  );
  assert.equal(settlement.payment_transaction, undefined);
  const replay = await fixture.service.preflight(request, ["mcp_tool", "https"]);
  assert.equal(replay.replay, true);
  assert.equal(replay.payment_settled, true);
  assert.deepEqual(replay.replay_authorization, envelope);

  const committed = await fixture.service.commit(fixture.signedLifecycle(envelope, "commit"));
  assert.equal(committed.status, "forwarding");
  const completed = await fixture.service.complete(fixture.signedLifecycle(envelope, "completion"));
  assert.equal(completed.status, "completed");
  assert.equal(completed.outcome_status, "succeeded");
});

test("crash recovery verifies the settlement-bound payment proof and atomically reconciles commit", async () => {
  const fixture = createFixture();
  const policy = await fixture.signedPolicy();
  await fixture.service.registerPolicy(policy);
  await fixture.service.registerInstallation(await fixture.signedInstallation(policy));
  const request = fixture.signedRequest({
    kind: "mcp_tool",
    connector_id: "mcp.billing",
    tool: "invoice.create",
    input_schema_sha256: SCHEMA_HASH,
    arguments: { invoice_id: "INV-RECOVERY" },
  }, "guard.request.recovery");
  const envelope = await fixture.service.authorize(request, ["mcp_tool", "https"]);
  const paymentContext = fixture.paymentContext("/v1/guard/paygo/authorize/network", `0x${"42".repeat(32)}`);
  await fixture.service.beginPaymentSettlement(request, ["mcp_tool", "https"], "claim-recovery", paymentContext);
  const indeterminate = await fixture.service.cancelPaymentSettlement(
    request,
    ["mcp_tool", "https"],
    "claim-recovery",
    { error: new Error("facilitator response was lost after broadcast") },
  );
  assert.equal(indeterminate.indeterminate, true);
  assert.equal(fixture.db.getGuardExecution(envelope.receipt.receipt_id).settlement_claim_id, "claim-recovery");
  const commit = fixture.signedLifecycle(envelope, "commit");
  const transaction = `0x${"de".repeat(32)}`;
  const reconciliation = {
    schema: "goldkey.guard-reconciled-commit.v1",
    commit,
    payment_proof: { transaction, payment_payload: paymentContext.paymentPayload },
  };

  const tamperedPayload = structuredClone(paymentContext.paymentPayload);
  tamperedPayload.payload.authorization.nonce = `0x${"43".repeat(32)}`;
  await assert.rejects(
    () => fixture.service.reconcileCommit({ ...reconciliation, payment_proof: { transaction, payment_payload: tamperedPayload } }),
    (error) => error.code === "guard_payment_proof_mismatch",
  );
  const before = fixture.db.getGuardExecution(envelope.receipt.receipt_id);
  assert.equal(before.payment_settled_at, null);
  assert.equal(before.committed_at, null);
  assert.equal(fixture.paymentVerificationCalls().length, 0);

  const recovered = await fixture.service.reconcileCommit(reconciliation);
  assert.equal(recovered.payment_reconciled, true);
  assert.equal(recovered.status, "forwarding");
  assert.equal(fixture.paymentVerificationCalls().length, 1);
  const stored = fixture.db.getGuardExecution(envelope.receipt.receipt_id);
  assert.equal(stored.payment_transaction, transaction);
  assert.equal(stored.payment_settled_at, NOW);
  assert.equal(stored.committed_at, NOW);
  const replay = await fixture.service.reconcileCommit(reconciliation);
  assert.equal(replay.replay, true);
  assert.equal(replay.payment_reconciled, false);
  assert.equal(fixture.paymentVerificationCalls().length, 1);
});

test("new installations cannot pin superseded policy versions", async () => {
  const fixture = createFixture();
  const version1 = await fixture.signedPolicy(1);
  await fixture.service.registerPolicy(version1);
  await fixture.service.registerPolicy(await fixture.signedPolicy(2));
  await assert.rejects(
    async () => fixture.service.registerInstallation(await fixture.signedInstallation(version1)),
    (error) => error.code === "guard_policy_superseded",
  );
});

test("identical human policy IDs are independently namespaced by operator wallet", async () => {
  const otherOperator = privateKeyToAccount(`0x${"72".repeat(32)}`);
  const fixture = createFixture({ allowedOperatorWallets: [otherOperator.address] });
  const ownerPolicy = await fixture.signedPolicy();
  await fixture.service.registerPolicy(ownerPolicy);
  const otherBody = { ...fixture.policyBody(), operator_wallet: otherOperator.address };
  const otherPolicy = {
    ...otherBody,
    signature: await otherOperator.signMessage({ message: guardPolicySigningMessage(otherBody) }),
  };
  const registered = await fixture.service.registerPolicy(otherPolicy);
  assert.equal(registered.policy_id, "policy.production");
  const rows = fixture.db.db.prepare("SELECT policy_id, operator_wallet FROM guard_policy_versions ORDER BY policy_id").all();
  assert.equal(rows.length, 2);
  assert.equal(new Set(rows.map(({ policy_id }) => policy_id)).size, 2);
  assert.equal(rows.every(({ policy_id, operator_wallet }) => policy_id.startsWith(`${operator_wallet.toLowerCase()}:`)), true);
});

test("EVM simulation runs only after static policy checks and authoritative cap races become signed BLOCK decisions", async () => {
  const fixture = createFixture();
  const policy = await fixture.signedPolicy();
  await fixture.service.registerPolicy(policy);
  await fixture.service.registerInstallation(await fixture.signedInstallation(policy));
  const allowedTransaction = {
    chain_id: 8453,
    from: operator.address,
    to: TOKEN,
    value_atomic: "0",
    data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [RECIPIENT, 1000n] }),
    nonce: "7",
    gas_limit: "60000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
  };
  const first = await fixture.service.authorize(
    fixture.signedRequest({ kind: "evm_transaction", connector_id: "evm.usdc", transaction: allowedTransaction }, "guard.evm.0001"),
    ["evm_transaction"],
  );
  assert.equal(first.receipt.decision, "ALLOW");
  assert.equal(first.evidence.details.fee_reservation.amount_atomic, "1201000");
  assert.equal(first.evidence.details.fee_reservation.fee_domain, "native:eip155:8453");
  assert.equal(first.evidence.details.nonce_reservation.nonce, "7");
  assert.equal(first.evidence.details.nonce_reservation.max_period_atomic, "1");
  assert.equal(fixture.simulationCalls(), 1);
  const storedReservations = fixture.db.db.prepare(`
    SELECT reservation_key, amount_atomic, cap_atomic, disposition
    FROM guard_execution_reservations WHERE execution_id = ? ORDER BY reservation_key
  `).all(first.receipt.receipt_id);
  assert.equal(storedReservations.length, 3);
  assert.equal(storedReservations.every(({ disposition }) => disposition === "reserved"), true);
  assert.equal(storedReservations.some(({ reservation_key }) => reservation_key.startsWith("guard:asset:")), true);
  assert.equal(storedReservations.some(({ reservation_key, amount_atomic }) => reservation_key.startsWith("guard:fee:") && amount_atomic === "1201000"), true);
  assert.equal(storedReservations.some(({ reservation_key, amount_atomic, cap_atomic }) => (
    reservation_key === `guard:nonce:${first.evidence.details.nonce_reservation.lock_key}`
      && amount_atomic === "1"
      && cap_atomic === "1"
  )), true);

  const second = await fixture.service.authorize(
    fixture.signedRequest({ kind: "evm_transaction", connector_id: "evm.usdc", transaction: allowedTransaction }, "guard.evm.0002"),
    ["evm_transaction"],
  );
  assert.equal(second.receipt.decision, "BLOCK");
  assert.deepEqual(second.receipt.reason_codes, ["authoritative_spend_cap_exceeded"]);
  assert.equal(fixture.simulationCalls(), 2);

  const forbidden = {
    ...allowedTransaction,
    to: "0x0000000000000000000000000000000000000099",
  };
  const blocked = await fixture.service.authorize(
    fixture.signedRequest({ kind: "evm_transaction", connector_id: "evm.usdc", transaction: forbidden }, "guard.evm.0003"),
    ["evm_transaction"],
  );
  assert.equal(blocked.receipt.decision, "BLOCK");
  assert.equal(fixture.simulationCalls(), 2);
});

test("expired idempotency receipts fail closed instead of replaying an unusable ALLOW", async () => {
  const fixture = createFixture();
  const policy = await fixture.signedPolicy();
  await fixture.service.registerPolicy(policy);
  await fixture.service.registerInstallation(await fixture.signedInstallation(policy));
  const request = fixture.signedRequest({
    kind: "mcp_tool",
    connector_id: "mcp.billing",
    tool: "invoice.create",
    input_schema_sha256: SCHEMA_HASH,
    arguments: {},
  });
  await fixture.service.authorize(request, ["mcp_tool"]);
  fixture.setNow(NOW + 60_001);
  await assert.rejects(
    () => fixture.service.authorize(request, ["mcp_tool"]),
    (error) => error.code === "guard_idempotency_expired",
  );
});

test("operator can immediately revoke an installation or policy with a fresh signed envelope", async () => {
  const fixture = createFixture();
  const policy = await fixture.signedPolicy();
  const registered = await fixture.service.registerPolicy(policy);
  await fixture.service.registerInstallation(await fixture.signedInstallation(policy));

  const revokedInstallation = await fixture.service.revoke(await fixture.signedRevocation("installation", fixture.installationId));
  assert.equal(revokedInstallation.target_kind, "installation");
  await assert.rejects(
    () => fixture.service.authorize(fixture.signedRequest({
      kind: "mcp_tool",
      connector_id: "mcp.billing",
      tool: "invoice.create",
      input_schema_sha256: SCHEMA_HASH,
      arguments: {},
    }), ["mcp_tool"]),
    (error) => error.code === "guard_installation_inactive",
  );

  const revokedPolicy = await fixture.service.revoke(await fixture.signedRevocation("policy", registered.policy_sha256));
  assert.equal(revokedPolicy.target_kind, "policy");
  assert.equal(revokedPolicy.target_id, registered.policy_sha256);

  fixture.setNow(NOW + 5 * 60_000 + 1);
  const staleRevocation = await fixture.signedRevocation("policy", registered.policy_sha256, { issued_at: new Date(NOW).toISOString() });
  await assert.rejects(
    () => fixture.service.revoke(staleRevocation),
    (error) => error.code === "guard_revocation_expired",
  );
});
