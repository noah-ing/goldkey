import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  guardCommitSigningMessage,
  guardCompletionSigningMessage,
  guardRequestSigningMessage,
  hashGuardCall as hostedHashGuardCall,
  validateGuardCommit,
  validateGuardCompletion,
  validateGuardRequest,
} from "../../src/guard.mjs";
import { createGuardReceiptSigner } from "../../src/guard-receipt.mjs";
import { RemoteAuthorizer } from "../src/authorization.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import { GoldKeyEnforcer } from "../src/enforcer.mjs";
import {
  AmbiguousOutcomeError,
  AuthorizationDeniedError,
  ReceiptVerificationError,
} from "../src/errors.mjs";
import { createInstallationIdentity } from "../src/identity.mjs";
import { normalizeReceiptKeyset } from "../src/protocol.mjs";
import { FileOutcomeStore } from "../src/state-store.mjs";

const NOW = Date.parse("2026-08-11T12:00:00.000Z");
const POLICY_HASH = "a".repeat(64);
const SCHEMA_HASH = "b".repeat(64);
const FROM = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
const TO = "0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0";
const BASE_GAS_PRICE_ORACLE = "0x420000000000000000000000000000000000000F";

function replayedCommitAcknowledgment(commit) {
  return Object.freeze({
    ok: true,
    replay: true,
    execution_id: commit.execution_id,
    installation_id: commit.installation_id,
    call_sha256: commit.call_sha256,
    policy_sha256: POLICY_HASH,
    decision: "ALLOW",
    status: "forwarding",
    committed_at: new Date(NOW).toISOString(),
  });
}

function receiptSigner(clock = () => NOW) {
  const { privateKey } = generateKeyPairSync("ed25519");
  return createGuardReceiptSigner({
    privateKeyPkcs8Base64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    keyId: "receipt-key-v1",
    clock,
    idGenerator: () => "receipt-00000001",
  });
}

function evidenceFor(call, decision = "ALLOW") {
  if (call.kind === "mcp_tool") {
    return {
      schema: "goldkey.guard-evidence.v1",
      decision,
      reason_codes: decision === "ALLOW" ? [] : ["operator_blocked"],
      effect: "write",
      destination: "mcp://trusted-server/" + call.tool,
    };
  }
  if (call.kind === "evm_transaction") {
    const destination = call.transaction.to
      ? "eip155:" + call.transaction.chain_id + ":" + call.transaction.to
      : "eip155:" + call.transaction.chain_id + ":contract_creation";
    const transactionSha256 = canonicalSha256(call.transaction);
    const l1FeeEstimate = 1000n;
    const feeAmount = BigInt(call.transaction.gas_limit) * BigInt(call.transaction.max_fee_per_gas_atomic) + l1FeeEstimate + 100n;
    return {
      schema: "goldkey.guard-evidence.v1",
      decision,
      reason_codes: decision === "ALLOW" ? [] : ["operator_blocked"],
      effect: "payment",
      destination,
      details: {
        transaction_sha256: transactionSha256,
        simulation: {
          schema: "goldkey.evm-simulation-evidence.v2",
          status: "success",
          chain_id: call.transaction.chain_id,
          transaction_sha256: transactionSha256,
          block_number: "123456",
          block_hash: "0x" + "ab".repeat(32),
          target_code_sha256: "ef".repeat(32),
          return_data_sha256: "cd".repeat(32),
          gas_estimate: "21000",
          pending_nonce: call.transaction.nonce,
          l1_fee_estimate_atomic: l1FeeEstimate.toString(),
          operator_fee_estimate_atomic: "100",
          gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
        },
        fee_reservation: {
          period_key_scope: "chain_native_fee",
          fee_domain: `native:eip155:${call.transaction.chain_id}`,
          amount_atomic: feeAmount.toString(),
          spend_period_seconds: 86400,
          max_period_atomic: "1000000000000000000",
          exposure: "network_fee",
        },
        nonce_reservation: {
          period_key_scope: "wallet_nonce",
          lock_key: `eip155:${call.transaction.chain_id}:${call.transaction.from}:nonce:${call.transaction.nonce}`,
          connector_id: call.connector_id,
          chain_id: call.transaction.chain_id,
          from: call.transaction.from,
          nonce: call.transaction.nonce,
          amount_atomic: "1",
          max_period_atomic: "1",
          exposure: "nonce_lock",
        },
      },
    };
  }
  if (call.kind === "https") {
    return {
      schema: "goldkey.guard-evidence.v1",
      decision,
      reason_codes: decision === "ALLOW" ? [] : ["operator_blocked"],
      effect: "write",
      destination: "https://api.example.net/v1/write",
      details: { method: "POST", operation_id: "write" },
    };
  }
  throw new Error("Unsupported fixture call");
}

function successfulFeeRecheck(overrides = {}) {
  return async ({ transaction }) => ({
    schema: "goldkey.evm-prebroadcast-fee-state.v1",
    chain_id: transaction.chain_id,
    from: transaction.from,
    transaction_sha256: canonicalSha256(transaction),
    block_number: "123457",
    block_hash: "0x" + "bc".repeat(32),
    pending_nonce: transaction.nonce,
    native_balance_atomic: "1000000000000000",
    l1_fee_estimate_atomic: "1000",
    operator_fee_estimate_atomic: "100",
    ...overrides,
  });
}

function evmExposureControls(overrides = {}) {
  return {
    max_estimated_network_fee_atomic: "1000000000000000",
    max_wallet_native_exposure_atomic: "2000000000000000",
    recheckFeeExposure: successfulFeeRecheck(),
    ...overrides,
  };
}

async function fixture(t, {
  decision = "ALLOW",
  receiptOverrides = {},
  signerClock,
  authorizationSigner,
  receiptKeyset,
  verificationClock = () => NOW,
  mutateEvidence,
  mutateEnvelope,
  authorizationPaymentProof,
  commitAuthorization,
  completeAuthorization,
  connectors,
  enforcerOptions = {},
} = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-enforcer-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const installationIdentity = createInstallationIdentity();
  const signer = authorizationSigner ?? receiptSigner(signerClock);
  let latestRequest;
  const fetchImpl = async (_url, options) => {
    latestRequest = validateGuardRequest(JSON.parse(Buffer.from(options.body).toString("utf8")));
    const publicKey = createPublicKey({ key: installationIdentity.publicJwk, format: "jwk" });
    assert.equal(
      verify(null, Buffer.from(guardRequestSigningMessage(latestRequest)), publicKey, Buffer.from(latestRequest.signature, "base64url")),
      true,
      "local request must use the hosted canonical signature protocol",
    );
    let evidence = evidenceFor(latestRequest.call, decision);
    if (mutateEvidence) evidence = mutateEvidence(evidence, latestRequest.call);
    let envelope = signer.signAuthorization({
      installation_id: receiptOverrides.installation_id ?? latestRequest.installation_id,
      idempotency_key: receiptOverrides.idempotency_key ?? latestRequest.idempotency_key,
      connector_id: receiptOverrides.connector_id ?? latestRequest.call.connector_id,
      kind: receiptOverrides.kind ?? latestRequest.call.kind,
      policy_id: "operator-policy",
      policy_version: 1,
      policy_sha256: receiptOverrides.policy_sha256 ?? POLICY_HASH,
      call_sha256: receiptOverrides.call_sha256 ?? hostedHashGuardCall(latestRequest.call),
      decision,
      reason_codes: evidence.reason_codes,
      evidence,
      ttl_ms: receiptOverrides.ttl_ms ?? 30_000,
    });
    if (mutateEnvelope) envelope = mutateEnvelope(envelope);
    return new Response(JSON.stringify(envelope), { status: 200, headers: { "content-type": "application/json" } });
  };
  const remoteAuthorizer = new RemoteAuthorizer({
    authorizeUrl: "https://guard.goldkey.invalid/v1/authorize",
    fetchImpl,
    installationIdentity,
    receiptKeyset: receiptKeyset ?? signer.keyset,
    policyHash: POLICY_HASH,
    clock: verificationClock,
  });
  const authorizer = authorizationPaymentProof === undefined ? remoteAuthorizer : Object.freeze({
    callHash: (call) => remoteAuthorizer.callHash(call),
    assertReceiptFresh: (receipt, now) => remoteAuthorizer.assertReceiptFresh(receipt, now),
    authorize: async (input) => Object.freeze({
      ...await remoteAuthorizer.authorize(input),
      paymentProof: authorizationPaymentProof,
    }),
  });
  const outcomeStore = new FileOutcomeStore({ directory, clock: () => NOW });
  const commits = [];
  const completions = [];
  const commit = commitAuthorization ?? (async (value) => {
    commits.push(validateGuardCommit(value));
    const key = createPublicKey({ key: installationIdentity.publicJwk, format: "jwk" });
    assert.equal(verify(null, Buffer.from(guardCommitSigningMessage(value)), key, Buffer.from(value.signature, "base64url")), true);
    assert.equal(value.execution_id, value.receipt_id);
    assert.equal((await outcomeStore.get(value.receipt_id === "never" ? "none" : latestRequest.idempotency_key)).state, "FORWARDING");
    return { ok: true, replay: false };
  });
  const complete = completeAuthorization === false ? undefined : (completeAuthorization ?? (async (value) => {
    completions.push(validateGuardCompletion(value));
    const key = createPublicKey({ key: installationIdentity.publicJwk, format: "jwk" });
    assert.equal(verify(null, Buffer.from(guardCompletionSigningMessage(value)), key, Buffer.from(value.signature, "base64url")), true);
    return { ok: true };
  }));
  const defaultConnectors = [{
    id: "trusted-mcp",
    kind: "mcp_tool",
    server_id: "trusted-server",
    tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
    invokeTool: async () => ({ ok: true }),
  }];
  const enforcer = new GoldKeyEnforcer({
    installationIdentity,
    outcomeStore,
    authorizer,
    commitAuthorization: commit,
    ...(complete ? { completeAuthorization: complete } : {}),
    connectors: connectors ?? defaultConnectors,
    clock: () => NOW,
    ...enforcerOptions,
  });
  return { enforcer, outcomeStore, installationIdentity, commits, completions, latestRequest: () => latestRequest };
}

test("MCP forwarding uses hosted protocol, commits durably, and delivers exact canonical argument bytes once", async (t) => {
  let invocations = 0;
  let received;
  const fx = await fixture(t, {
    connectors: [{
      id: "trusted-mcp",
      kind: "mcp_tool",
      server_id: "trusted-server",
      tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
      invokeTool: async (call) => {
        invocations += 1;
        received = call;
        return { delivered: true };
      },
    }],
  });
  const result = await fx.enforcer.guardMcpTool({
    connectorId: "trusted-mcp",
    tool: "send_message",
    arguments: { z: 2, a: "hello" },
    idempotencyKey: "mcp-success-0001",
  });
  assert.deepEqual(result, { delivered: true });
  assert.equal(received.argumentsBytes.toString("utf8"), '{"a":"hello","z":2}');
  assert.deepEqual(received.arguments, { a: "hello", z: 2 });
  assert.equal(Object.isFrozen(received.arguments), true);
  assert.equal(invocations, 1);
  assert.equal(fx.commits.length, 1);
  assert.equal(fx.completions.length, 1);
  assert.equal((await fx.outcomeStore.get("mcp-success-0001")).state, "SUCCEEDED");
  await assert.rejects(
    fx.enforcer.guardMcpTool({
      connectorId: "trusted-mcp",
      tool: "send_message",
      arguments: { a: "hello", z: 2 },
      idempotencyKey: "mcp-success-0001",
    }),
    /already been used/,
  );
  assert.equal(invocations, 1);
});

test("paid authorization proof is private durable recovery state and reaches only the lifecycle commit", async (t) => {
  const paymentProof = Object.freeze({
    transaction: `0x${"12".repeat(32)}`,
    payment_payload: Object.freeze({ x402Version: 2, marker: "public-payment-authorization" }),
  });
  let fx;
  let lifecycleContext;
  let connectorReceipt;
  fx = await fixture(t, {
    authorizationPaymentProof: paymentProof,
    commitAuthorization: async (value, context) => {
      lifecycleContext = context;
      const state = await fx.outcomeStore.get("mcp-paid-proof-0001");
      assert.equal(state.state, "FORWARDING");
      assert.deepEqual(state.payment_proof, paymentProof);
      return { ok: true, replay: false };
    },
    connectors: [{
      id: "trusted-mcp",
      kind: "mcp_tool",
      server_id: "trusted-server",
      tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
      invokeTool: async ({ receipt }) => {
        connectorReceipt = receipt;
        return { delivered: true };
      },
    }],
  });
  assert.deepEqual(await fx.enforcer.guardMcpTool({
    connectorId: "trusted-mcp",
    tool: "send_message",
    arguments: { message: "hello" },
    idempotencyKey: "mcp-paid-proof-0001",
  }), { delivered: true });
  assert.deepEqual(lifecycleContext.paymentProof, paymentProof);
  assert.equal(Object.hasOwn(connectorReceipt, "paymentProof"), false);
  const finalState = await fx.outcomeStore.get("mcp-paid-proof-0001");
  assert.equal(finalState.state, "SUCCEEDED");
  assert.equal(finalState.payment_proof, null);
});

test("signed BLOCK never reaches commit or MCP", async (t) => {
  let invoked = 0;
  const fx = await fixture(t, {
    decision: "BLOCK",
    connectors: [{
      id: "trusted-mcp",
      kind: "mcp_tool",
      server_id: "trusted-server",
      tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
      invokeTool: async () => { invoked += 1; },
    }],
  });
  await assert.rejects(
    fx.enforcer.guardMcpTool({
      connectorId: "trusted-mcp",
      tool: "send_message",
      arguments: { text: "no" },
      idempotencyKey: "mcp-block-00001",
    }),
    AuthorizationDeniedError,
  );
  assert.equal(invoked, 0);
  assert.equal(fx.commits.length, 0);
  assert.equal((await fx.outcomeStore.get("mcp-block-00001")).state, "DENIED");
});

for (const [name, receiptOverrides] of [
  ["installation", { installation_id: "different-installation" }],
  ["idempotency", { idempotency_key: "different-key-0001" }],
  ["connector", { connector_id: "different-connector" }],
  ["kind", { kind: "https" }],
  ["policy", { policy_sha256: "c".repeat(64) }],
  ["call", { call_sha256: "d".repeat(64) }],
]) {
  test("validly signed receipt with wrong " + name + " binding is rejected before forwarding", async (t) => {
    let invoked = 0;
    const fx = await fixture(t, {
      receiptOverrides,
      connectors: [{
        id: "trusted-mcp",
        kind: "mcp_tool",
        server_id: "trusted-server",
        tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
        invokeTool: async () => { invoked += 1; },
      }],
    });
    await assert.rejects(
      fx.enforcer.guardMcpTool({
        connectorId: "trusted-mcp",
        tool: "send_message",
        arguments: { value: name },
        idempotencyKey: "bad-binding-" + name.padEnd(8, "0"),
      }),
      ReceiptVerificationError,
    );
    assert.equal(invoked, 0);
    assert.equal(fx.commits.length, 0);
  });
}

test("forged and expired authorization envelopes fail closed", async (t) => {
  await t.test("forged", async (t) => {
    const fx = await fixture(t, {
      mutateEnvelope: (envelope) => ({ ...envelope, signature: (envelope.signature[0] === "A" ? "B" : "A") + envelope.signature.slice(1) }),
    });
    await assert.rejects(
      fx.enforcer.guardMcpTool({
        connectorId: "trusted-mcp",
        tool: "send_message",
        arguments: {},
        idempotencyKey: "forged-receipt-1",
      }),
      ReceiptVerificationError,
    );
  });
  await t.test("expired", async (t) => {
    const fx = await fixture(t, {
      signerClock: () => NOW - 5_000,
      receiptOverrides: { ttl_ms: 1_000 },
    });
    await assert.rejects(
      fx.enforcer.guardMcpTool({
        connectorId: "trusted-mcp",
        tool: "send_message",
        arguments: {},
        idempotencyKey: "expired-receipt-1",
      }),
      ReceiptVerificationError,
    );
  });
});

test("retired receipt keys verify historical overlap but cannot authorize a fresh privileged call", async (t) => {
  const { privateKey: oldPrivateKey } = generateKeyPairSync("ed25519");
  let oldClock = NOW;
  const oldSigner = createGuardReceiptSigner({
    privateKeyPkcs8Base64: oldPrivateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    keyId: "receipt-key-retired",
    clock: () => oldClock,
    idGenerator: () => `receipt-retired-${oldClock}`,
  });
  const retiredAt = NOW + 10_000;
  const { privateKey: currentPrivateKey } = generateKeyPairSync("ed25519");
  const currentSigner = createGuardReceiptSigner({
    privateKeyPkcs8Base64: currentPrivateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    keyId: "receipt-key-current",
    previousPublicKeys: [{
      ...oldSigner.publicKeyJwk,
      not_before: new Date(NOW - 60_000).toISOString(),
      signing_not_after: new Date(retiredAt).toISOString(),
    }],
  });
  const pinnedKeyset = normalizeReceiptKeyset({ receiptKeyset: currentSigner.keyset });
  assert.equal(pinnedKeyset.keys[1].signing_not_after, new Date(retiredAt).toISOString());
  assert.equal(JSON.stringify(pinnedKeyset).includes("\"d\""), false);
  assert.throws(
    () => normalizeReceiptKeyset({
      receiptKeyset: {
        schema: currentSigner.keyset.schema,
        keys: [currentSigner.publicKeyJwk, oldSigner.publicKeyJwk],
      },
    }),
    /bounded signing interval/,
  );
  assert.throws(
    () => normalizeReceiptKeyset({
      receiptKeyset: {
        schema: currentSigner.keyset.schema,
        keys: [{ ...currentSigner.publicKeyJwk, d: "private-material" }],
      },
    }),
    /unsupported fields|non-public/,
  );

  let historicalInvocations = 0;
  const historical = await fixture(t, {
    authorizationSigner: oldSigner,
    receiptKeyset: pinnedKeyset,
    verificationClock: () => retiredAt + 1,
    connectors: [{
      id: "trusted-mcp",
      kind: "mcp_tool",
      server_id: "trusted-server",
      tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
      invokeTool: async () => { historicalInvocations += 1; return { delivered: true }; },
    }],
  });
  assert.deepEqual(await historical.enforcer.guardMcpTool({
    connectorId: "trusted-mcp",
    tool: "send_message",
    arguments: { historical: true },
    idempotencyKey: "receipt-before-retirement-1",
  }), { delivered: true });
  assert.equal(historicalInvocations, 1);

  oldClock = retiredAt + 1;
  let forgedInvocations = 0;
  const forged = await fixture(t, {
    authorizationSigner: oldSigner,
    receiptKeyset: pinnedKeyset,
    verificationClock: () => retiredAt + 2,
    connectors: [{
      id: "trusted-mcp",
      kind: "mcp_tool",
      server_id: "trusted-server",
      tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
      invokeTool: async () => { forgedInvocations += 1; },
    }],
  });
  await assert.rejects(
    forged.enforcer.guardMcpTool({
      connectorId: "trusted-mcp",
      tool: "send_message",
      arguments: { forged: true },
      idempotencyKey: "receipt-after-retirement-1",
    }),
    (error) => error instanceof ReceiptVerificationError && /retired/.test(error.message),
  );
  assert.equal(forgedInvocations, 0);
  assert.equal(forged.commits.length, 0);
});

test("ambiguous commit and upstream failures are persisted UNKNOWN and never retried", async (t) => {
  await t.test("commit failure", async (t) => {
    let invoked = 0;
    const fx = await fixture(t, {
      commitAuthorization: async () => { throw new Error("connection reset"); },
      connectors: [{
        id: "trusted-mcp",
        kind: "mcp_tool",
        server_id: "trusted-server",
        tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
        invokeTool: async () => { invoked += 1; },
      }],
    });
    const call = {
      connectorId: "trusted-mcp", tool: "send_message", arguments: {}, idempotencyKey: "commit-ambiguous-1",
    };
    await assert.rejects(fx.enforcer.guardMcpTool(call), AmbiguousOutcomeError);
    assert.equal(invoked, 0);
    assert.equal((await fx.outcomeStore.get(call.idempotencyKey)).state, "UNKNOWN");
    await assert.rejects(fx.enforcer.guardMcpTool(call), AmbiguousOutcomeError);
    assert.equal(invoked, 0);
  });
  await t.test("upstream failure", async (t) => {
    let invoked = 0;
    const fx = await fixture(t, {
      connectors: [{
        id: "trusted-mcp",
        kind: "mcp_tool",
        server_id: "trusted-server",
        tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
        invokeTool: async () => { invoked += 1; throw new Error("socket closed after write"); },
      }],
    });
    const call = {
      connectorId: "trusted-mcp", tool: "send_message", arguments: {}, idempotencyKey: "upstream-unknown-1",
    };
    await assert.rejects(fx.enforcer.guardMcpTool(call), AmbiguousOutcomeError);
    assert.equal(invoked, 1);
    assert.equal((await fx.outcomeStore.get(call.idempotencyKey)).state, "UNKNOWN");
    await assert.rejects(fx.enforcer.guardMcpTool(call), AmbiguousOutcomeError);
    assert.equal(invoked, 1);
  });
});

test("a fully bound replayed commit acknowledgment never reaches any privileged connector and is never retried", async (t) => {
  await t.test("MCP", async (t) => {
    let commits = 0;
    let invocations = 0;
    const fx = await fixture(t, {
      commitAuthorization: async (commit) => {
        commits += 1;
        return replayedCommitAcknowledgment(commit);
      },
      connectors: [{
        id: "trusted-mcp",
        kind: "mcp_tool",
        server_id: "trusted-server",
        tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
        invokeTool: async () => { invocations += 1; },
      }],
    });
    const call = {
      connectorId: "trusted-mcp",
      tool: "send_message",
      arguments: { irreversible: true },
      idempotencyKey: "replayed-commit-mcp-1",
    };

    await assert.rejects(fx.enforcer.guardMcpTool(call), AmbiguousOutcomeError);
    assert.equal(commits, 1);
    assert.equal(invocations, 0);
    assert.deepEqual(
      { state: (await fx.outcomeStore.get(call.idempotencyKey)).state, phase: (await fx.outcomeStore.get(call.idempotencyKey)).phase },
      { state: "UNKNOWN", phase: "commit" },
    );
    await assert.rejects(fx.enforcer.guardMcpTool(call), AmbiguousOutcomeError);
    assert.equal(commits, 1);
    assert.equal(invocations, 0);
  });

  await t.test("HTTPS", async (t) => {
    let commits = 0;
    let sockets = 0;
    const fx = await fixture(t, {
      commitAuthorization: async (commit) => {
        commits += 1;
        return replayedCommitAcknowledgment(commit);
      },
      connectors: [{
        id: "trusted-https",
        kind: "https",
        origin: "https://api.example.net",
        trusted_headers: { authorization: "Bearer operator-secret" },
        operations: [{ id: "write", method: "POST", path: "/v1/write", effect: "write" }],
      }],
      enforcerOptions: {
        resolve4: async () => [{ address: "93.184.216.34", ttl: 60 }],
        resolve6: async () => noIpv6(),
        httpsRequest: () => {
          sockets += 1;
          throw new Error("replayed commit opened a forbidden socket");
        },
      },
    });
    const call = {
      connectorId: "trusted-https",
      operationId: "write",
      body: { irreversible: true },
      idempotencyKey: "replayed-commit-https-1",
    };

    await assert.rejects(fx.enforcer.guardHttps(call), AmbiguousOutcomeError);
    assert.equal(commits, 1);
    assert.equal(sockets, 0);
    assert.equal((await fx.outcomeStore.get(call.idempotencyKey)).state, "UNKNOWN");
    await assert.rejects(fx.enforcer.guardHttps(call), AmbiguousOutcomeError);
    assert.equal(commits, 1);
    assert.equal(sockets, 0);
  });

  await t.test("EVM", async (t) => {
    let commits = 0;
    let signatures = 0;
    const fx = await fixture(t, {
      commitAuthorization: async (commit) => {
        commits += 1;
        return replayedCommitAcknowledgment(commit);
      },
      connectors: [{
        id: "base-mainnet",
        kind: "evm_transaction",
        chain_id: 8453,
        from: FROM,
        ...evmExposureControls(),
        signAndBroadcast: async () => { signatures += 1; },
      }],
    });
    const call = {
      connectorId: "base-mainnet",
      transaction: {
        chain_id: 8453,
        from: FROM,
        to: TO,
        value_atomic: "1",
        data: "0x",
        nonce: "7",
        gas_limit: "30000",
        max_fee_per_gas_atomic: "20",
        max_priority_fee_per_gas_atomic: "2",
      },
      idempotencyKey: "replayed-commit-evm-1",
    };

    await assert.rejects(fx.enforcer.guardEvmTransaction(call), AmbiguousOutcomeError);
    assert.equal(commits, 1);
    assert.equal(signatures, 0);
    assert.equal((await fx.outcomeStore.get(call.idempotencyKey)).state, "UNKNOWN");
    await assert.rejects(fx.enforcer.guardEvmTransaction(call), AmbiguousOutcomeError);
    assert.equal(commits, 1);
    assert.equal(signatures, 0);
  });
});

test("EVM signer receives the exact frozen transaction only after signed authorization and commit", async (t) => {
  const events = [];
  let signed;
  const fx = await fixture(t, {
    commitAuthorization: async (commit) => {
      events.push("commit");
      assert.equal(validateGuardCommit(commit).execution_id, "receipt-00000001");
      return { ok: true, replay: false };
    },
    connectors: [{
      id: "base-mainnet",
      kind: "evm_transaction",
      chain_id: 8453,
      from: FROM,
      ...evmExposureControls({
        recheckFeeExposure: async (value) => {
          events.push("recheck");
          return successfulFeeRecheck()(value);
        },
      }),
      signAndBroadcast: async (value) => {
        events.push("sign");
        signed = value;
        return { transactionHash: "0x" + "1".repeat(64) };
      },
    }],
  });
  const transaction = {
    chain_id: 8453,
    from: FROM.toLowerCase(),
    to: TO.toLowerCase(),
    value_atomic: "1",
    data: "0x",
    nonce: "7",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
  };
  await fx.enforcer.guardEvmTransaction({
    connectorId: "base-mainnet",
    transaction,
    idempotencyKey: "evm-payment-0001",
  });
  assert.deepEqual(events, ["commit", "recheck", "sign"]);
  assert.equal(Object.isFrozen(signed.transaction), true);
  assert.equal(signed.transaction.from, FROM);
  assert.equal(signed.transaction.to, TO);
  assert.equal(signed.transaction.type, "eip1559");
  assert.deepEqual(signed.transaction.access_list, []);
  assert.equal(signed.feeExposure.schema, "goldkey.evm-prebroadcast-fee-state.v1");
  assert.equal(signed.feeExposure.estimated_network_fee_atomic, "601100");
  assert.equal(signed.feeExposure.estimated_native_requirement_atomic, "601101");
  assert.equal(Object.isFrozen(signed.feeExposure), true);
  assert.equal(signed.transactionBytes.toString("utf8"), JSON.stringify({
    access_list: [],
    chain_id: 8453,
    data: "0x",
    from: FROM,
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
    nonce: "7",
    to: TO,
    type: "eip1559",
    value_atomic: "1",
  }));
});

test("EVM calls without a fully populated nonce and fee envelope fail before authorization or signing", async (t) => {
  let signed = 0;
  const fx = await fixture(t, {
    connectors: [{
      id: "base-mainnet",
      kind: "evm_transaction",
      chain_id: 8453,
      from: FROM,
      ...evmExposureControls(),
      signAndBroadcast: async () => { signed += 1; },
    }],
  });
  await assert.rejects(
    fx.enforcer.guardEvmTransaction({
      connectorId: "base-mainnet",
      transaction: {
        chain_id: 8453,
        from: FROM,
        to: TO,
        value_atomic: "1",
        data: "0x",
        gas_limit: "30000",
        max_fee_per_gas_atomic: "20",
        max_priority_fee_per_gas_atomic: "2",
      },
      idempotencyKey: "evm-incomplete-0001",
    }),
    /transaction.nonce is required/,
  );
  assert.equal(signed, 0);
});

test("EVM connectors require immutable local fee caps and an operator-bound recheck", async (t) => {
  const base = {
    id: "base-mainnet",
    kind: "evm_transaction",
    chain_id: 8453,
    from: FROM,
    signAndBroadcast: async () => {},
  };
  await assert.rejects(fixture(t, { connectors: [base] }), /max_estimated_network_fee_atomic/);
  await assert.rejects(fixture(t, {
    connectors: [{
      ...base,
      max_estimated_network_fee_atomic: "1000",
      max_wallet_native_exposure_atomic: "2000",
    }],
  }), /recheckFeeExposure/);
  await assert.rejects(fixture(t, {
    connectors: [{
      ...base,
      ...evmExposureControls({
        max_estimated_network_fee_atomic: "2001",
        max_wallet_native_exposure_atomic: "2000",
      }),
    }],
  }), /must not exceed its wallet-native exposure cap/);
});

test("post-commit EVM fee recheck blocks every cap, balance, nonce, and binding failure before signing", async (t) => {
  const cases = [
    ["transaction binding", {}, { transaction_sha256: "0".repeat(64) }],
    ["pending nonce", {}, { pending_nonce: "8" }],
    ["signed estimate reservation", {}, { l1_fee_estimate_atomic: "1001" }],
    ["operator-fee estimate reservation", {}, { operator_fee_estimate_atomic: "101" }],
    ["local estimated-fee cap", { max_estimated_network_fee_atomic: "601099" }, {}],
    ["segregated-wallet exposure cap", {
      max_estimated_network_fee_atomic: "601100",
      max_wallet_native_exposure_atomic: "700000",
    }, { native_balance_atomic: "700001" }],
    ["insufficient native balance", {}, { native_balance_atomic: "601100" }],
  ];

  for (const [index, [name, capOverrides, stateOverrides]] of cases.entries()) {
    await t.test(name, async (t) => {
      let rechecks = 0;
      let broadcasts = 0;
      const fx = await fixture(t, {
        connectors: [{
          id: "base-mainnet",
          kind: "evm_transaction",
          chain_id: 8453,
          from: FROM,
          ...evmExposureControls({
            ...capOverrides,
            recheckFeeExposure: async (value) => {
              rechecks += 1;
              return successfulFeeRecheck(stateOverrides)(value);
            },
          }),
          signAndBroadcast: async () => { broadcasts += 1; },
        }],
      });
      const idempotencyKey = `evm-fee-recheck-${String(index).padStart(2, "0")}`;
      await assert.rejects(
        fx.enforcer.guardEvmTransaction({
          connectorId: "base-mainnet",
          transaction: {
            chain_id: 8453,
            from: FROM,
            to: TO,
            value_atomic: "1",
            data: "0x",
            nonce: "7",
            gas_limit: "30000",
            max_fee_per_gas_atomic: "20",
            max_priority_fee_per_gas_atomic: "2",
          },
          idempotencyKey,
        }),
        (error) => error instanceof AmbiguousOutcomeError && error.cause?.code === "invalid_input",
      );
      assert.equal(fx.commits.length, 1, "the signed server commit precedes the final live recheck");
      assert.equal(rechecks, 1);
      assert.equal(broadcasts, 0);
      assert.equal((await fx.outcomeStore.get(idempotencyKey)).state, "UNKNOWN");
    });
  }
});

test("signed EVM ALLOW evidence must exactly prove simulation, fees, and wallet nonce before commit", async (t) => {
  const cases = [
    ["missing simulation", (details) => { delete details.simulation; }],
    ["unsuccessful simulation", (details) => { details.simulation.status = "revert"; }],
    ["simulation transaction mismatch", (details) => { details.simulation.transaction_sha256 = "0".repeat(64); }],
    ["pending nonce mismatch", (details) => { details.simulation.pending_nonce = "8"; }],
    ["gas estimate above frozen limit", (details) => { details.simulation.gas_estimate = "30001"; }],
    ["missing target code hash", (details) => { delete details.simulation.target_code_sha256; }],
    ["missing operator-fee estimate", (details) => { delete details.simulation.operator_fee_estimate_atomic; }],
    ["fee amount mismatch", (details) => { details.fee_reservation.amount_atomic = "1"; }],
    ["fee domain mismatch", (details) => { details.fee_reservation.fee_domain = "native:eip155:1"; }],
    ["fee cap below exposure", (details) => { details.fee_reservation.max_period_atomic = "1"; }],
    ["missing nonce lock", (details) => { delete details.nonce_reservation; }],
    ["wallet nonce lock mismatch", (details) => { details.nonce_reservation.lock_key += ":attacker"; }],
  ];

  for (const [index, [name, mutate]] of cases.entries()) {
    await t.test(name, async (t) => {
      let broadcasts = 0;
      const idempotencyKey = `bad-evm-proof-${String(index).padStart(2, "0")}`;
      const fx = await fixture(t, {
        mutateEvidence: (evidence) => {
          const changed = JSON.parse(JSON.stringify(evidence));
          mutate(changed.details);
          return changed;
        },
        connectors: [{
          id: "base-mainnet",
          kind: "evm_transaction",
          chain_id: 8453,
          from: FROM,
          ...evmExposureControls(),
          signAndBroadcast: async () => { broadcasts += 1; },
        }],
      });
      await assert.rejects(
        fx.enforcer.guardEvmTransaction({
          connectorId: "base-mainnet",
          transaction: {
            chain_id: 8453,
            from: FROM,
            to: TO,
            value_atomic: "1",
            data: "0x",
            nonce: "7",
            gas_limit: "30000",
            max_fee_per_gas_atomic: "20",
            max_priority_fee_per_gas_atomic: "2",
          },
          idempotencyKey,
        }),
        ReceiptVerificationError,
      );
      assert.equal(fx.commits.length, 0);
      assert.equal(broadcasts, 0);
      assert.equal((await fx.outcomeStore.get(idempotencyKey)).state, "AUTHORIZATION_FAILED");
    });
  }
});

function fakeHttpsRequest(capture) {
  return (options, callback) => {
    capture.options = options;
    capture.written = Buffer.alloc(0);
    const outgoing = new EventEmitter();
    outgoing.write = (chunk) => {
      capture.written = Buffer.concat([capture.written, Buffer.from(chunk)]);
    };
    outgoing.destroy = (error) => {
      if (error) queueMicrotask(() => outgoing.emit("error", error));
    };
    outgoing.end = () => queueMicrotask(() => {
      const response = new EventEmitter();
      response.statusCode = 200;
      response.headers = { "content-type": "application/json", "set-cookie": "secret=1" };
      response.destroy = () => {};
      callback(response);
      response.emit("data", Buffer.from('{"ok":true}'));
      response.emit("end");
    });
    return outgoing;
  };
}

function noIpv6() {
  const error = new Error("no IPv6");
  error.code = "ENODATA";
  throw error;
}

test("HTTPS connector ignores every agent header, pins public DNS, preserves TLS SNI, and commits first", async (t) => {
  const capture = {};
  const fx = await fixture(t, {
    connectors: [{
      id: "trusted-https",
      kind: "https",
      origin: "https://api.example.net",
      trusted_headers: { authorization: "Bearer operator-secret" },
      operations: [{ id: "write", method: "POST", path: "/v1/write", effect: "write" }],
    }],
    enforcerOptions: {
      resolve4: async () => [{ address: "93.184.216.34", ttl: 60 }],
      resolve6: async () => noIpv6(),
      httpsRequest: fakeHttpsRequest(capture),
    },
  });
  const result = await fx.enforcer.guardHttps({
    connectorId: "trusted-https",
    operationId: "write",
    query: { z: "last", a: ["one", "two"] },
    body: { z: 2, a: 1 },
    headers: {
      authorization: "Bearer attacker",
      cookie: "session=attacker",
      connection: "keep-alive",
      host: "127.0.0.1",
      "x-forwarded-host": "metadata.google.internal",
      accept: "application/json",
      "accept-language": "attacker-controlled",
      "user-agent": "attacker-controlled",
    },
    idempotencyKey: "https-success-001",
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.toString(), '{"ok":true}');
  assert.equal(result.headers["set-cookie"], undefined);
  assert.equal(capture.options.hostname, "api.example.net");
  assert.equal(capture.options.servername, "api.example.net");
  assert.equal(capture.options.agent, false);
  assert.equal(capture.options.path, "/v1/write?a=one&a=two&z=last");
  assert.equal(capture.options.headers.authorization, "Bearer operator-secret");
  assert.equal(capture.options.headers.cookie, undefined);
  assert.equal(capture.options.headers.connection, undefined);
  assert.equal(capture.options.headers.host, undefined);
  assert.equal(capture.options.headers["x-forwarded-host"], undefined);
  assert.equal(capture.options.headers.accept, undefined);
  assert.equal(capture.options.headers["accept-language"], undefined);
  assert.equal(capture.options.headers["user-agent"], undefined);
  assert.equal(capture.written.toString(), '{"a":1,"z":2}');
  await new Promise((resolve, reject) => capture.options.lookup("api.example.net", {}, (error, address, family) => {
    if (error) reject(error);
    else {
      assert.equal(address, "93.184.216.34");
      assert.equal(family, 4);
      resolve();
    }
  }));
  assert.equal(fx.commits.length, 1);
  assert.equal((await fx.outcomeStore.get("https-success-001")).state, "SUCCEEDED");
});

test("mixed DNS answer blocks before commit and before opening any socket", async (t) => {
  let sockets = 0;
  const fx = await fixture(t, {
    connectors: [{
      id: "trusted-https",
      kind: "https",
      origin: "https://api.example.net",
      operations: [{ id: "write", method: "POST", path: "/v1/write", effect: "write" }],
    }],
    enforcerOptions: {
      resolve4: async () => [
        { address: "93.184.216.34", ttl: 60 },
        { address: "169.254.169.254", ttl: 1 },
      ],
      resolve6: async () => noIpv6(),
      httpsRequest: () => {
        sockets += 1;
      },
    },
  });
  await assert.rejects(fx.enforcer.guardHttps({
    connectorId: "trusted-https",
    operationId: "write",
    body: { ok: true },
    idempotencyKey: "https-mixed-dns1",
  }), /private, reserved/);
  assert.equal(fx.commits.length, 0);
  assert.equal(sockets, 0);
  assert.equal((await fx.outcomeStore.get("https-mixed-dns1")).state, "PREPARATION_FAILED");
});

test("15-second ceiling is configurable downward and hanging upstream becomes UNKNOWN", async (t) => {
  const fx = await fixture(t, {
    connectors: [{
      id: "trusted-mcp",
      kind: "mcp_tool",
      server_id: "trusted-server",
      tools: [{ name: "send_message", effect: "write", input_schema_sha256: SCHEMA_HASH }],
      invokeTool: async () => new Promise(() => {}),
    }],
    enforcerOptions: { deadlineMs: 10 },
  });
  await assert.rejects(fx.enforcer.guardMcpTool({
    connectorId: "trusted-mcp",
    tool: "send_message",
    arguments: {},
    idempotencyKey: "deadline-hang-001",
  }), AmbiguousOutcomeError);
  assert.equal((await fx.outcomeStore.get("deadline-hang-001")).state, "UNKNOWN");
});
