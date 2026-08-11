import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import test from "node:test";
import { encodeFunctionData, parseAbi, verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { BASE_GAS_PRICE_ORACLE, EVM_SIMULATION_SCHEMA, hashEvmTransaction } from "../src/evm-guard.mjs";
import { GUARD_POLICY_SCHEMA, guardPolicySigningMessage } from "../src/guard-policy.mjs";
import {
  GUARD_COMMIT_SCHEMA,
  GUARD_COMPLETION_SCHEMA,
  GUARD_EVIDENCE_SCHEMA,
  GUARD_REQUEST_SCHEMA,
  evaluateGuardRequest,
  guardCommitSigningMessage,
  guardCompletionSigningMessage,
  guardDecisionEvidence,
  guardRequestSigningMessage,
  hashGuardCall,
  validateGuardCommit,
  validateGuardCompletion,
  validateGuardRequest,
  verifyGuardCommit,
  verifyGuardCompletion,
} from "../src/guard.mjs";

const NOW = Date.parse("2026-08-11T12:00:00.000Z");
const AUDIENCE = "https://guard.goldkey.example";
const operator = privateKeyToAccount(`0x${"22".repeat(32)}`);
const { privateKey: installationPrivateKey, publicKey: installationPublicKey } = generateKeyPairSync("ed25519");
const SCHEMA_HASH = "ab".repeat(32);
const FROM = operator.address;
const RECIPIENT = "0x0000000000000000000000000000000000000011";
const SPENDER = "0x0000000000000000000000000000000000000012";
const TOKEN = "0x0000000000000000000000000000000000000013";
const ERC20_ABI = parseAbi(["function transfer(address to, uint256 amount) returns (bool)"]);

function unsignedPolicy() {
  return {
    schema: GUARD_POLICY_SCHEMA,
    policy_id: "policy.production.1",
    version: 1,
    operator_wallet: operator.address,
    audience: AUDIENCE,
    issued_at: "2026-08-11T00:00:00.000Z",
    expires_at: "2027-08-11T00:00:00.000Z",
    connectors: [
      {
        id: "mcp.billing",
        kind: "mcp_tool",
        server_id: "billing-server",
        tools: [{
          name: "invoice.create",
          effect: "write",
          input_schema_sha256: SCHEMA_HASH,
          arguments_schema: {
            type: "object",
            properties: {
              invoice_id: { type: "string", maxLength: 32 },
              approved: { const: true },
              recipient: { const: "acct.vendor.17" },
              amount_atomic: { const: "1000" },
            },
            required: ["invoice_id", "approved", "recipient", "amount_atomic"],
            additionalProperties: false,
          },
        }],
      },
      {
        id: "https.vendor",
        kind: "https",
        origin: "https://api.vendor.example",
        operations: [{
          id: "quote",
          method: "POST",
          path: "/v1/quote",
          effect: "network",
          query_schema: {
            type: "object",
            properties: { region: { const: "us" } },
            required: ["region"],
            additionalProperties: false,
          },
          body_schema: {
            type: "object",
            properties: {
              sku: { const: "A-17" },
              recipient: { const: "acct.vendor.17" },
              amount_atomic: { const: "1000" },
            },
            required: ["sku", "recipient", "amount_atomic"],
            additionalProperties: false,
          },
        }],
      },
      {
        id: "evm.treasury",
        kind: "evm_transaction",
        chain_id: 8453,
        from: FROM,
        allowed_native_recipients: [],
        allowed_erc20_tokens: [TOKEN],
        allowed_erc20_recipients: [RECIPIENT],
        allowed_approval_spenders: [SPENDER],
        max_native_value_atomic: "0",
        max_erc20_transfer_atomic: "2000",
        max_erc20_approval_atomic: "3000",
        max_gas_limit: "100000",
        max_fee_per_gas_atomic: "100",
        max_priority_fee_per_gas_atomic: "10",
        max_total_fee_atomic: "5000000",
        fee_period_seconds: 86400,
        max_fee_period_atomic: "10000000",
        spend_period_seconds: 86400,
        max_period_atomic: "10000",
        require_simulation: true,
      },
    ],
  };
}

async function signedPolicy() {
  const policy = unsignedPolicy();
  return { ...policy, signature: await operator.signMessage({ message: guardPolicySigningMessage(policy) }) };
}

function signedRequest(call, overrides = {}) {
  const request = {
    schema: GUARD_REQUEST_SCHEMA,
    installation_id: "install.production.1",
    idempotency_key: "guard.call.0001",
    issued_at: new Date(NOW).toISOString(),
    call,
    ...overrides,
  };
  return {
    ...request,
    signature: sign(null, Buffer.from(guardRequestSigningMessage(request)), installationPrivateKey).toString("base64url"),
  };
}

const verifyWalletMessage = ({ wallet, message, signature }) => verifyMessage({ address: wallet, message, signature });
const verifyInstallationSignature = ({ message, signature }) => verify(null, Buffer.from(message), installationPublicKey, Buffer.from(signature, "base64url"));

async function evaluate(request, overrides = {}) {
  return evaluateGuardRequest({
    request,
    policy: await signedPolicy(),
    audience: AUDIENCE,
    verifyWalletMessage,
    verifyInstallationSignature,
    now: NOW,
    ...overrides,
  });
}

test("MCP decision derives effect and destination only from signed policy", async () => {
  const call = {
    kind: "mcp_tool",
    connector_id: "mcp.billing",
    tool: "invoice.create",
    input_schema_sha256: SCHEMA_HASH,
    arguments: { invoice_id: "INV-17", approved: true, recipient: "acct.vendor.17", amount_atomic: "1000" },
  };
  const result = await evaluate(signedRequest(call));
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.effect, "write");
  assert.equal(result.destination, "mcp://billing-server/invoice.create");
  assert.equal(result.call_sha256, hashGuardCall(call));
  assert.deepEqual(guardDecisionEvidence(result), {
    schema: GUARD_EVIDENCE_SCHEMA,
    decision: "ALLOW",
    reason_codes: [],
    effect: "write",
    destination: "mcp://billing-server/invoice.create",
  });

  assert.throws(
    () => validateGuardRequest(signedRequest({ ...call, effect: "read" })),
    (error) => error.code === "invalid_guard_request",
  );
});

test("MCP schema drift and unknown connector fail closed", async () => {
  const changed = signedRequest({
    kind: "mcp_tool",
    connector_id: "mcp.billing",
    tool: "invoice.create",
    input_schema_sha256: "00".repeat(32),
    arguments: {},
  });
  assert.deepEqual((await evaluate(changed)).reason_codes, ["mcp_tool_schema_changed"]);

  const unknown = signedRequest({
    kind: "mcp_tool",
    connector_id: "mcp.attacker",
    tool: "invoice.create",
    input_schema_sha256: SCHEMA_HASH,
    arguments: {},
  });
  assert.deepEqual((await evaluate(unknown)).reason_codes, ["connector_not_allowed"]);
});

test("MCP arguments policy blocks recipient and amount tampering after schema-drift verification", async () => {
  const baseCall = {
    kind: "mcp_tool",
    connector_id: "mcp.billing",
    tool: "invoice.create",
    input_schema_sha256: SCHEMA_HASH,
    arguments: { invoice_id: "INV-17", approved: true, recipient: "acct.vendor.17", amount_atomic: "1000" },
  };
  for (const argumentsValue of [
    { ...baseCall.arguments, recipient: "acct.attacker" },
    { ...baseCall.arguments, amount_atomic: "1001" },
  ]) {
    const result = await evaluate(signedRequest({ ...baseCall, arguments: argumentsValue }));
    assert.equal(result.decision, "BLOCK");
    assert.deepEqual(result.reason_codes, ["mcp_arguments_policy_mismatch"]);
  }
});

test("HTTPS call selects an operator-fixed operation and cannot supply URL or credentials", async () => {
  const call = {
    kind: "https",
    connector_id: "https.vendor",
    operation_id: "quote",
    query: { region: "us" },
    body: { sku: "A-17", recipient: "acct.vendor.17", amount_atomic: "1000" },
  };
  const result = await evaluate(signedRequest(call));
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.effect, "network");
  assert.equal(result.destination, "https://api.vendor.example/v1/quote");
  assert.deepEqual(result.details, { method: "POST", operation_id: "quote" });

  assert.throws(
    () => signedRequest({ ...call, url: "https://attacker.example", authorization: "Bearer secret" }),
    (error) => error.code === "invalid_guard_request",
  );
});

test("HTTPS query and body policy block tampering with stable sorted reason codes", async () => {
  const tampered = signedRequest({
    kind: "https",
    connector_id: "https.vendor",
    operation_id: "quote",
    query: { region: "eu" },
    body: { sku: "A-17", recipient: "acct.attacker", amount_atomic: "1001" },
  });
  const result = await evaluate(tampered);
  assert.equal(result.decision, "BLOCK");
  assert.deepEqual(result.reason_codes, ["https_body_policy_mismatch", "https_query_policy_mismatch"]);
  assert.deepEqual(result.details, { method: "POST", operation_id: "quote" });

  const missingBody = signedRequest({
    kind: "https",
    connector_id: "https.vendor",
    operation_id: "quote",
    query: { region: "us" },
  });
  assert.deepEqual((await evaluate(missingBody)).reason_codes, ["https_body_policy_mismatch"]);
});

test("EVM guard decision includes policy-derived spend reservation evidence", async () => {
  const transaction = {
    chain_id: 8453,
    from: FROM,
    to: TOKEN,
    value_atomic: "0",
    data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [RECIPIENT, 1200n] }),
    nonce: "7",
    gas_limit: "60000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
  };
  const simulation = {
    schema: EVM_SIMULATION_SCHEMA,
    status: "success",
    chain_id: 8453,
    transaction_sha256: hashEvmTransaction(transaction),
    block_number: "1234",
    block_hash: `0x${"ab".repeat(32)}`,
    target_code_sha256: "ef".repeat(32),
    return_data_sha256: "cd".repeat(32),
    gas_estimate: "55000",
    pending_nonce: "7",
    l1_fee_estimate_atomic: "1000",
    operator_fee_estimate_atomic: "0",
    gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
  };
  const request = signedRequest({ kind: "evm_transaction", connector_id: "evm.treasury", transaction });
  const result = await evaluate(request, { simulation });
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.effect, "payment");
  assert.equal(result.details.reservation.asset, TOKEN);
  assert.equal(result.details.reservation.connector_id, "evm.treasury");
  assert.equal(result.details.reservation.period_key_scope, "connector");
  assert.equal(result.details.reservation.counterparty, RECIPIENT);
  assert.equal(result.details.reservation.amount_atomic, "1200");
  assert.equal(result.details.reservation.max_period_atomic, "10000");
  assert.equal(result.details.fee_reservation.fee_domain, "native:eip155:8453");
  assert.equal(result.details.fee_reservation.amount_atomic, "1201000");
  assert.equal(result.details.nonce_reservation.nonce, "7");
  assert.equal(result.details.nonce_reservation.max_period_atomic, "1");
  assert.equal(guardDecisionEvidence(result).details.simulation.block_number, "1234");
});

test("stale requests block, invalid installation signatures reject, and policy audience is enforced", async () => {
  const call = { kind: "mcp_tool", connector_id: "mcp.billing", tool: "invoice.create", input_schema_sha256: SCHEMA_HASH, arguments: {} };
  const policy = await signedPolicy();
  const stale = signedRequest(call, { issued_at: new Date(NOW - 120_000).toISOString() });
  stale.signature = sign(null, Buffer.from(guardRequestSigningMessage(stale)), installationPrivateKey).toString("base64url");
  assert.deepEqual((await evaluate(stale)).reason_codes, ["request_expired"]);

  await assert.rejects(
    () => evaluateGuardRequest({
      request: signedRequest(call),
      policy,
      audience: AUDIENCE,
      verifyWalletMessage,
      verifyInstallationSignature: () => false,
      now: NOW,
    }),
    (error) => error.code === "invalid_guard_request_signature",
  );

  await assert.rejects(
    () => evaluateGuardRequest({
      request: signedRequest(call),
      policy,
      audience: "https://other.example",
      verifyWalletMessage,
      verifyInstallationSignature,
      now: NOW,
    }),
    (error) => error.code === "guard_policy_audience_mismatch",
  );
});

test("installation-signed commit and completion envelopes bind the exact authorization and outcome", async () => {
  const commitBody = {
    schema: GUARD_COMMIT_SCHEMA,
    installation_id: "install.production.1",
    execution_id: "execution.0001",
    receipt_id: "receipt.0001",
    receipt_sha256: "11".repeat(32),
    call_sha256: "22".repeat(32),
    issued_at: new Date(NOW).toISOString(),
  };
  const commit = {
    ...commitBody,
    signature: sign(null, Buffer.from(guardCommitSigningMessage(commitBody)), installationPrivateKey).toString("base64url"),
  };
  assert.deepEqual(validateGuardCommit(commit), commit);
  assert.deepEqual(await verifyGuardCommit(commit, { verifyInstallationSignature, now: NOW }), commit);

  const completionBody = {
    schema: GUARD_COMPLETION_SCHEMA,
    installation_id: commit.installation_id,
    execution_id: commit.execution_id,
    receipt_id: commit.receipt_id,
    receipt_sha256: commit.receipt_sha256,
    call_sha256: commit.call_sha256,
    issued_at: new Date(NOW + 1_000).toISOString(),
    outcome_status: "outcome_unknown",
    outcome_sha256: "33".repeat(32),
  };
  const completion = {
    ...completionBody,
    signature: sign(null, Buffer.from(guardCompletionSigningMessage(completionBody)), installationPrivateKey).toString("base64url"),
  };
  assert.deepEqual(validateGuardCompletion(completion), completion);
  assert.deepEqual(await verifyGuardCompletion(completion, { verifyInstallationSignature, now: NOW + 1_000 }), completion);

  await assert.rejects(
    () => verifyGuardCommit({ ...commit, call_sha256: "44".repeat(32) }, { verifyInstallationSignature, now: NOW }),
    (error) => error.code === "invalid_guard_lifecycle_signature",
  );
  assert.throws(
    () => guardCompletionSigningMessage({ ...completionBody, outcome_status: "retryable" }),
    (error) => error.code === "invalid_guard_lifecycle",
  );
});
