import assert from "node:assert/strict";
import test from "node:test";
import { encodeFunctionData, parseAbi, toFunctionSelector } from "viem";
import {
  BASE_GAS_PRICE_ORACLE,
  EVM_SIMULATION_SCHEMA,
  evaluateEvmTransaction,
  hashEvmTransaction,
  normalizeEvmTransaction,
  validateEvmSimulationEvidence,
} from "../src/evm-guard.mjs";

const FROM = "0x0000000000000000000000000000000000000010";
const RECIPIENT = "0x0000000000000000000000000000000000000011";
const SPENDER = "0x0000000000000000000000000000000000000012";
const TOKEN = "0x0000000000000000000000000000000000000013";
const OTHER = "0x0000000000000000000000000000000000000014";
const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);

function nativeConnector(overrides = {}) {
  return {
    id: "evm.treasury",
    kind: "evm_transaction",
    chain_id: 8453,
    from: FROM,
    allowed_native_recipients: [RECIPIENT],
    allowed_erc20_tokens: [],
    allowed_erc20_recipients: [],
    allowed_approval_spenders: [],
    max_native_value_atomic: "1000",
    max_erc20_transfer_atomic: "0",
    max_erc20_approval_atomic: "0",
    max_gas_limit: "100000",
    max_fee_per_gas_atomic: "100",
    max_priority_fee_per_gas_atomic: "10",
    max_total_fee_atomic: "5000000",
    fee_period_seconds: 86400,
    max_fee_period_atomic: "10000000",
    spend_period_seconds: 86400,
    max_period_atomic: "10000",
    require_simulation: true,
    asset_id: "native:eip155:8453",
    ...overrides,
  };
}

function tokenConnector(overrides = {}) {
  return {
    id: "evm.usdc",
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
    asset_id: TOKEN,
    ...overrides,
  };
}

function nativeTransaction(overrides = {}) {
  return {
    chain_id: 8453,
    from: FROM,
    to: RECIPIENT,
    value_atomic: "500",
    data: "0x",
    nonce: "7",
    gas_limit: "30000",
    max_fee_per_gas_atomic: "20",
    max_priority_fee_per_gas_atomic: "2",
    ...overrides,
  };
}

function successfulSimulation(transaction) {
  return {
    schema: EVM_SIMULATION_SCHEMA,
    status: "success",
    chain_id: transaction.chain_id,
    transaction_sha256: hashEvmTransaction(transaction),
    block_number: "123456",
    block_hash: `0x${"ab".repeat(32)}`,
    target_code_sha256: "ef".repeat(32),
    return_data_sha256: "cd".repeat(32),
    gas_estimate: "21000",
    pending_nonce: transaction.nonce,
    l1_fee_estimate_atomic: "1000",
    operator_fee_estimate_atomic: "0",
    gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
  };
}

test("native transfer is policy-bound, simulated, and emits authoritative reservation fields", () => {
  const transaction = nativeTransaction();
  const result = evaluateEvmTransaction({ transaction, connector: nativeConnector(), simulation: successfulSimulation(transaction) });
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.decoded.operation, "native_transfer");
  assert.deepEqual(result.reservation, {
    connector_id: "evm.treasury",
    period_key_scope: "connector",
    asset: "native:eip155:8453",
    counterparty: RECIPIENT,
    amount_atomic: "500",
    spend_period_seconds: 86400,
    max_period_atomic: "10000",
    exposure: "transfer",
  });
  assert.deepEqual(result.fee_reservation, {
    period_key_scope: "chain_native_fee",
    fee_domain: "native:eip155:8453",
    amount_atomic: "601000",
    spend_period_seconds: 86400,
    max_period_atomic: "10000000",
    exposure: "network_fee",
  });
  assert.deepEqual(result.nonce_reservation, {
    period_key_scope: "wallet_nonce",
    lock_key: `eip155:8453:${FROM}:nonce:7`,
    connector_id: "evm.treasury",
    chain_id: 8453,
    from: FROM,
    nonce: "7",
    amount_atomic: "1",
    max_period_atomic: "1",
    exposure: "nonce_lock",
  });
});

test("ERC-20 transfer and approval derive asset, counterparty, amount, and exposure", () => {
  const transfer = nativeTransaction({
    to: TOKEN,
    value_atomic: "0",
    data: encodeFunctionData({ abi: ERC20_ABI, functionName: "transfer", args: [RECIPIENT, 1200n] }),
  });
  const transferResult = evaluateEvmTransaction({ transaction: transfer, connector: tokenConnector(), simulation: successfulSimulation(transfer) });
  assert.equal(transferResult.decision, "ALLOW");
  assert.equal(transferResult.reservation.asset, TOKEN);
  assert.equal(transferResult.reservation.counterparty, RECIPIENT);
  assert.equal(transferResult.reservation.amount_atomic, "1200");
  assert.equal(transferResult.reservation.exposure, "transfer");
  assert.equal(transferResult.reservation.period_key_scope, "connector");
  assert.equal(transferResult.reservation.connector_id, "evm.usdc");

  const approve = nativeTransaction({
    to: TOKEN,
    value_atomic: "0",
    data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [SPENDER, 2500n] }),
  });
  const approveResult = evaluateEvmTransaction({ transaction: approve, connector: tokenConnector(), simulation: successfulSimulation(approve) });
  assert.equal(approveResult.decision, "ALLOW");
  assert.equal(approveResult.reservation.counterparty, SPENDER);
  assert.equal(approveResult.reservation.amount_atomic, "2500");
  assert.equal(approveResult.reservation.exposure, "approval");
});

test("unlimited approval, unknown selector, multicall, creation, and wrong recipient block", () => {
  const maxUint = (1n << 256n) - 1n;
  const unlimited = nativeTransaction({
    to: TOKEN,
    value_atomic: "0",
    data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [SPENDER, maxUint] }),
  });
  const unlimitedResult = evaluateEvmTransaction({ transaction: unlimited, connector: tokenConnector(), simulation: successfulSimulation(unlimited) });
  assert.equal(unlimitedResult.decision, "BLOCK");
  assert.ok(unlimitedResult.reason_codes.includes("evm_unlimited_approval_blocked"));
  assert.equal(unlimitedResult.reservation.amount_atomic, maxUint.toString());

  const unknown = nativeTransaction({ to: TOKEN, value_atomic: "0", data: "0x12345678" });
  assert.deepEqual(evaluateEvmTransaction({ transaction: unknown, connector: tokenConnector() }).reason_codes, ["evm_unknown_selector"]);

  const multicall = nativeTransaction({ to: TOKEN, value_atomic: "0", data: toFunctionSelector("multicall(bytes[])") });
  assert.deepEqual(evaluateEvmTransaction({ transaction: multicall, connector: tokenConnector() }).reason_codes, ["evm_multicall_blocked"]);

  const creation = nativeTransaction();
  delete creation.to;
  assert.ok(evaluateEvmTransaction({ transaction: creation, connector: nativeConnector() }).reason_codes.includes("evm_contract_creation_blocked"));

  const wrongRecipient = nativeTransaction({ to: OTHER });
  assert.ok(evaluateEvmTransaction({ transaction: wrongRecipient, connector: nativeConnector() }).reason_codes.includes("evm_native_recipient_not_allowed"));

});

test("ERC-20 transfer and approve reject trailing calldata", () => {
  for (const [functionName, target] of [["transfer", RECIPIENT], ["approve", SPENDER]]) {
    const canonicalData = encodeFunctionData({ abi: ERC20_ABI, functionName, args: [target, 1n] });
    const transaction = nativeTransaction({
      to: TOKEN,
      value_atomic: "0",
      data: `${canonicalData}deadbeef`,
    });
    const result = evaluateEvmTransaction({ transaction, connector: tokenConnector(), simulation: successfulSimulation(transaction) });
    assert.equal(result.decision, "BLOCK", `${functionName} with a calldata suffix must block`);
    assert.ok(result.reason_codes.includes("evm_noncanonical_calldata"), `${functionName} must report noncanonical calldata`);
  }
});

test("required or unavailable simulation reviews; revert and mismatched evidence fail closed", () => {
  const transaction = nativeTransaction();
  assert.deepEqual(evaluateEvmTransaction({ transaction, connector: nativeConnector() }).reason_codes, ["evm_simulation_required"]);

  const unavailable = {
    schema: EVM_SIMULATION_SCHEMA,
    status: "unavailable",
    chain_id: 8453,
    transaction_sha256: hashEvmTransaction(transaction),
    reason: "rpc unavailable",
  };
  assert.deepEqual(evaluateEvmTransaction({ transaction, connector: nativeConnector(), simulation: unavailable }).reason_codes, ["evm_simulation_unavailable"]);

  const reverted = { ...successfulSimulation(transaction), status: "revert" };
  assert.ok(evaluateEvmTransaction({ transaction, connector: nativeConnector(), simulation: reverted }).reason_codes.includes("evm_simulation_reverted"));

  const mismatch = { ...successfulSimulation(transaction), transaction_sha256: "00".repeat(32) };
  assert.throws(
    () => evaluateEvmTransaction({ transaction, connector: nativeConnector(), simulation: mismatch }),
    (error) => error.code === "simulation_transaction_mismatch",
  );
  assert.equal(validateEvmSimulationEvidence(unavailable).status, "unavailable");
  const missingTargetCode = { ...successfulSimulation(transaction) };
  delete missingTargetCode.target_code_sha256;
  assert.throws(
    () => validateEvmSimulationEvidence(missingTargetCode),
    (error) => error.code === "invalid_simulation_evidence",
  );
});

test("transaction normalization rejects fee inversion and unsupported fields", () => {
  assert.throws(
    () => normalizeEvmTransaction(nativeTransaction({ max_fee_per_gas_atomic: "10", max_priority_fee_per_gas_atomic: "11" })),
    /must not exceed/,
  );
  assert.throws(
    () => normalizeEvmTransaction({ ...nativeTransaction(), private_key: "never" }),
    (error) => error.code === "invalid_evm_transaction",
  );
  const incomplete = nativeTransaction();
  delete incomplete.nonce;
  assert.throws(
    () => normalizeEvmTransaction(incomplete),
    /transaction.nonce is required/,
  );
  assert.throws(
    () => normalizeEvmTransaction(nativeTransaction({ gas_limit: (1n << 256n).toString() })),
    /exceeds uint256/,
  );
});

test("nonce, gas, priority fee, execution fee, and total fee drain attempts block", () => {
  const connector = nativeConnector();

  const badNonce = nativeTransaction();
  const badNonceSimulation = successfulSimulation(badNonce);
  badNonceSimulation.pending_nonce = "8";
  const badNonceResult = evaluateEvmTransaction({ transaction: badNonce, connector, simulation: badNonceSimulation });
  assert.ok(badNonceResult.reason_codes.includes("evm_nonce_mismatch"));
  assert.equal(badNonceResult.nonce_reservation, undefined);

  const lowGas = nativeTransaction({ gas_limit: "20000" });
  assert.ok(evaluateEvmTransaction({ transaction: lowGas, connector, simulation: successfulSimulation(lowGas) }).reason_codes.includes("evm_gas_limit_below_estimate"));

  const highGas = nativeTransaction({ gas_limit: "100001" });
  assert.ok(evaluateEvmTransaction({ transaction: highGas, connector, simulation: successfulSimulation(highGas) }).reason_codes.includes("evm_gas_limit_cap_exceeded"));

  const highFee = nativeTransaction({ max_fee_per_gas_atomic: "101" });
  assert.ok(evaluateEvmTransaction({ transaction: highFee, connector, simulation: successfulSimulation(highFee) }).reason_codes.includes("evm_max_fee_per_gas_cap_exceeded"));

  const highPriority = nativeTransaction({ max_priority_fee_per_gas_atomic: "11" });
  assert.ok(evaluateEvmTransaction({ transaction: highPriority, connector, simulation: successfulSimulation(highPriority) }).reason_codes.includes("evm_max_priority_fee_per_gas_cap_exceeded"));

  const highTotal = nativeTransaction({ gas_limit: "100000", max_fee_per_gas_atomic: "100" });
  assert.ok(evaluateEvmTransaction({ transaction: highTotal, connector, simulation: successfulSimulation(highTotal) }).reason_codes.includes("evm_max_total_fee_cap_exceeded"));

  const l1High = nativeTransaction();
  const l1HighSimulation = successfulSimulation(l1High);
  l1HighSimulation.l1_fee_estimate_atomic = "5000000";
  assert.ok(evaluateEvmTransaction({ transaction: l1High, connector, simulation: l1HighSimulation }).reason_codes.includes("evm_max_total_fee_cap_exceeded"));

  const operatorHigh = nativeTransaction();
  const operatorHighSimulation = successfulSimulation(operatorHigh);
  operatorHighSimulation.operator_fee_estimate_atomic = "5000000";
  assert.ok(evaluateEvmTransaction({ transaction: operatorHigh, connector, simulation: operatorHighSimulation }).reason_codes.includes("evm_max_total_fee_cap_exceeded"));
});
