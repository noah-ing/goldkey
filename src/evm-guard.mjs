import { decodeFunctionData, encodeFunctionData, getAddress, isAddress, parseAbi, toFunctionSelector } from "viem";
import { canonicalize, hashCanonical } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";

export const EVM_SIMULATION_SCHEMA = "goldkey.evm-simulation-evidence.v2";
export const BASE_GAS_PRICE_ORACLE = getAddress("0x420000000000000000000000000000000000000F");

const ATOMIC_PATTERN = /^(0|[1-9]\d{0,77})$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const DATA_PATTERN = /^0x(?:[0-9a-fA-F]{2})*$/;
const MAX_CALLDATA_BYTES = 64 * 1024;
const MAX_UINT256 = (1n << 256n) - 1n;
const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);
const TRANSFER_SELECTOR = toFunctionSelector("transfer(address,uint256)");
const APPROVE_SELECTOR = toFunctionSelector("approve(address,uint256)");
const MULTICALL_SELECTORS = new Set([
  toFunctionSelector("multicall(bytes[])"),
  toFunctionSelector("aggregate((address,bytes)[])"),
  toFunctionSelector("tryAggregate(bool,(address,bytes)[])"),
  toFunctionSelector("aggregate3((address,bool,bytes)[])"),
]);

function exactKeys(value, allowed, name, code = "invalid_evm_transaction") {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, code, `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, code, `${name} contains unsupported fields`, { fields: extras.sort() });
}

function atomic(value, name, code = "invalid_evm_transaction") {
  assert(typeof value === "string" && ATOMIC_PATTERN.test(value), 400, code, `${name} must be a canonical atomic-unit integer string of at most 78 digits`);
  assert(BigInt(value) <= MAX_UINT256, 400, code, `${name} exceeds uint256`);
  return value;
}

function address(value, name, code = "invalid_evm_transaction") {
  assert(typeof value === "string" && isAddress(value), 400, code, `${name} must be an EVM address`);
  return getAddress(value);
}

function maybeAtomic(target, source, field) {
  if (source[field] !== undefined) target[field] = atomic(source[field], `transaction.${field}`);
}

export function normalizeEvmTransaction(transaction) {
  exactKeys(transaction, new Set([
    "chain_id",
    "from",
    "to",
    "value_atomic",
    "data",
    "nonce",
    "gas_limit",
    "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic",
    "type",
    "access_list",
  ]), "transaction");
  for (const field of ["nonce", "gas_limit", "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic"]) {
    assert(Object.hasOwn(transaction, field), 400, "invalid_evm_transaction", `transaction.${field} is required`);
  }
  assert(Number.isSafeInteger(transaction.chain_id) && transaction.chain_id > 0, 400, "invalid_evm_transaction", "transaction.chain_id must be a positive safe integer");
  assert(transaction.to === undefined || transaction.to === null || isAddress(transaction.to), 400, "invalid_evm_transaction", "transaction.to must be an EVM address when provided");
  assert(typeof transaction.data === "string" && DATA_PATTERN.test(transaction.data), 400, "invalid_evm_transaction", "transaction.data must be even-length hexadecimal bytes");
  assert(transaction.type === undefined || transaction.type === "eip1559", 400, "invalid_evm_transaction", "transaction.type must be eip1559 when provided");
  assert(transaction.access_list === undefined || (Array.isArray(transaction.access_list) && transaction.access_list.length === 0), 400, "invalid_evm_transaction", "transaction.access_list must be empty when provided");
  assert((transaction.data.length - 2) / 2 <= MAX_CALLDATA_BYTES, 413, "evm_calldata_too_large", `transaction.data exceeds ${MAX_CALLDATA_BYTES} bytes`);
  const normalized = {
    chain_id: transaction.chain_id,
    from: address(transaction.from, "transaction.from"),
    ...(transaction.to === undefined || transaction.to === null ? {} : { to: getAddress(transaction.to) }),
    value_atomic: atomic(transaction.value_atomic, "transaction.value_atomic"),
    data: transaction.data.toLowerCase(),
    type: "eip1559",
    access_list: Object.freeze([]),
  };
  maybeAtomic(normalized, transaction, "nonce");
  maybeAtomic(normalized, transaction, "gas_limit");
  maybeAtomic(normalized, transaction, "max_fee_per_gas_atomic");
  maybeAtomic(normalized, transaction, "max_priority_fee_per_gas_atomic");
  assert(BigInt(normalized.nonce) <= BigInt(Number.MAX_SAFE_INTEGER), 400, "invalid_evm_transaction", "transaction.nonce exceeds the supported safe-integer range");
  assert(BigInt(normalized.gas_limit) > 0n, 400, "invalid_evm_transaction", "transaction.gas_limit must be greater than zero");
  assert(BigInt(normalized.max_fee_per_gas_atomic) > 0n, 400, "invalid_evm_transaction", "transaction.max_fee_per_gas_atomic must be greater than zero");
  if (normalized.max_priority_fee_per_gas_atomic !== undefined && normalized.max_fee_per_gas_atomic !== undefined) {
    assert(BigInt(normalized.max_priority_fee_per_gas_atomic) <= BigInt(normalized.max_fee_per_gas_atomic), 400, "invalid_evm_transaction", "max_priority_fee_per_gas_atomic must not exceed max_fee_per_gas_atomic");
  }
  return Object.freeze(normalized);
}

export function hashEvmTransaction(transaction) {
  return hashCanonical(normalizeEvmTransaction(transaction)).sha256;
}

function normalizedSimulationBase(evidence) {
  exactKeys(evidence, new Set([
    "schema",
    "status",
    "chain_id",
    "transaction_sha256",
    "block_number",
    "block_hash",
    "target_code_sha256",
    "return_data_sha256",
    "gas_estimate",
    "pending_nonce",
    "l1_fee_estimate_atomic",
    "operator_fee_estimate_atomic",
    "gas_price_oracle_address",
    "reason",
  ]), "simulation evidence", "invalid_simulation_evidence");
  assert(evidence.schema === EVM_SIMULATION_SCHEMA, 400, "invalid_simulation_evidence", `simulation.schema must be ${EVM_SIMULATION_SCHEMA}`);
  assert(["success", "revert", "unavailable"].includes(evidence.status), 400, "invalid_simulation_evidence", "simulation.status is invalid");
  assert(Number.isSafeInteger(evidence.chain_id) && evidence.chain_id > 0, 400, "invalid_simulation_evidence", "simulation.chain_id must be a positive safe integer");
  assert(typeof evidence.transaction_sha256 === "string" && SHA256_PATTERN.test(evidence.transaction_sha256), 400, "invalid_simulation_evidence", "simulation.transaction_sha256 is invalid");
  return {
    schema: EVM_SIMULATION_SCHEMA,
    status: evidence.status,
    chain_id: evidence.chain_id,
    transaction_sha256: evidence.transaction_sha256,
  };
}

export function validateEvmSimulationEvidence(evidence) {
  const normalized = normalizedSimulationBase(evidence);
  if (evidence.status === "unavailable") {
    assert(typeof evidence.reason === "string" && evidence.reason.length >= 1 && evidence.reason.length <= 256, 400, "invalid_simulation_evidence", "unavailable simulation evidence requires a bounded reason");
    assert(
      evidence.block_number === undefined
      && evidence.block_hash === undefined
      && evidence.target_code_sha256 === undefined
      && evidence.return_data_sha256 === undefined
      && evidence.gas_estimate === undefined
      && evidence.pending_nonce === undefined
      && evidence.l1_fee_estimate_atomic === undefined
      && evidence.operator_fee_estimate_atomic === undefined
      && evidence.gas_price_oracle_address === undefined,
      400,
      "invalid_simulation_evidence",
      "unavailable simulation evidence must not claim block or result fields",
    );
    return Object.freeze({ ...normalized, reason: evidence.reason });
  }
  assert(typeof evidence.block_number === "string", 400, "invalid_simulation_evidence", "simulation.block_number is required");
  assert(typeof evidence.block_hash === "string" && BYTES32_PATTERN.test(evidence.block_hash), 400, "invalid_simulation_evidence", "simulation.block_hash must be 32-byte hex");
  assert(typeof evidence.target_code_sha256 === "string" && SHA256_PATTERN.test(evidence.target_code_sha256), 400, "invalid_simulation_evidence", "simulation.target_code_sha256 is invalid");
  assert(typeof evidence.return_data_sha256 === "string" && SHA256_PATTERN.test(evidence.return_data_sha256), 400, "invalid_simulation_evidence", "simulation.return_data_sha256 is invalid");
  assert(typeof evidence.gas_price_oracle_address === "string" && isAddress(evidence.gas_price_oracle_address), 400, "invalid_simulation_evidence", "simulation.gas_price_oracle_address must be an EVM address");
  assert(getAddress(evidence.gas_price_oracle_address) === BASE_GAS_PRICE_ORACLE, 400, "invalid_simulation_evidence", `simulation.gas_price_oracle_address must be ${BASE_GAS_PRICE_ORACLE}`);
  const result = {
    ...normalized,
    block_number: atomic(evidence.block_number, "simulation.block_number", "invalid_simulation_evidence"),
    block_hash: evidence.block_hash.toLowerCase(),
    target_code_sha256: evidence.target_code_sha256,
    return_data_sha256: evidence.return_data_sha256,
    pending_nonce: atomic(evidence.pending_nonce, "simulation.pending_nonce", "invalid_simulation_evidence"),
    l1_fee_estimate_atomic: atomic(evidence.l1_fee_estimate_atomic, "simulation.l1_fee_estimate_atomic", "invalid_simulation_evidence"),
    operator_fee_estimate_atomic: atomic(evidence.operator_fee_estimate_atomic, "simulation.operator_fee_estimate_atomic", "invalid_simulation_evidence"),
    gas_price_oracle_address: BASE_GAS_PRICE_ORACLE,
  };
  if (evidence.gas_estimate !== undefined) result.gas_estimate = atomic(evidence.gas_estimate, "simulation.gas_estimate", "invalid_simulation_evidence");
  if (evidence.status === "success") {
    assert(result.gas_estimate !== undefined, 400, "invalid_simulation_evidence", "successful simulation evidence requires gas_estimate");
  }
  assert(evidence.reason === undefined, 400, "invalid_simulation_evidence", "successful or reverted simulation evidence must not contain reason");
  return Object.freeze(result);
}

function includesAddress(values, candidate) {
  return values.some((value) => value.toLowerCase() === candidate.toLowerCase());
}

function decision(decisionValue, reasonCodes, details) {
  return Object.freeze({
    decision: decisionValue,
    reason_codes: [...new Set(reasonCodes)].sort(),
    effect: "payment",
    ...details,
  });
}

function validateConnector(connector) {
  assert(connector && connector.kind === "evm_transaction", 500, "invalid_guard_connector", "A normalized evm_transaction policy connector is required");
  for (const field of ["allowed_native_recipients", "allowed_erc20_tokens", "allowed_erc20_recipients", "allowed_approval_spenders"]) {
    assert(Array.isArray(connector[field]), 500, "invalid_guard_connector", `connector.${field} must be configured`);
  }
  for (const field of [
    "max_native_value_atomic",
    "max_erc20_transfer_atomic",
    "max_erc20_approval_atomic",
    "max_period_atomic",
    "max_gas_limit",
    "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic",
    "max_total_fee_atomic",
    "max_fee_period_atomic",
  ]) atomic(connector[field], `connector.${field}`, "invalid_guard_connector");
  assert(BigInt(connector.max_gas_limit) > 0n, 500, "invalid_guard_connector", "connector.max_gas_limit must be greater than zero");
  assert(BigInt(connector.max_fee_per_gas_atomic) > 0n, 500, "invalid_guard_connector", "connector.max_fee_per_gas_atomic must be greater than zero");
  assert(BigInt(connector.max_priority_fee_per_gas_atomic) <= BigInt(connector.max_fee_per_gas_atomic), 500, "invalid_guard_connector", "connector.max_priority_fee_per_gas_atomic must not exceed max_fee_per_gas_atomic");
  assert(BigInt(connector.max_total_fee_atomic) > 0n, 500, "invalid_guard_connector", "connector.max_total_fee_atomic must be greater than zero");
  assert(BigInt(connector.max_fee_period_atomic) >= BigInt(connector.max_total_fee_atomic), 500, "invalid_guard_connector", "connector.max_fee_period_atomic must be at least max_total_fee_atomic");
  assert(Number.isSafeInteger(connector.spend_period_seconds) && connector.spend_period_seconds >= 60 && connector.spend_period_seconds <= 31_536_000, 500, "invalid_guard_connector", "connector.spend_period_seconds must be configured");
  assert(Number.isSafeInteger(connector.fee_period_seconds) && connector.fee_period_seconds >= 60 && connector.fee_period_seconds <= 31_536_000, 500, "invalid_guard_connector", "connector.fee_period_seconds must be configured");
  assert(connector.require_simulation === true, 500, "invalid_guard_connector", "connector.require_simulation must be true");
  assert(typeof connector.id === "string" && connector.id.length >= 1 && connector.id.length <= 128, 500, "invalid_guard_connector", "connector.id must be configured");
  const nativeOnly = connector.allowed_native_recipients.length > 0;
  const tokenOnly = connector.allowed_native_recipients.length === 0 && connector.allowed_erc20_tokens.length === 1 && (connector.allowed_erc20_recipients.length > 0 || connector.allowed_approval_spenders.length > 0);
  assert(nativeOnly || tokenOnly, 500, "invalid_guard_connector", "connector must contain one asset domain");
  if (nativeOnly) {
    assert(connector.allowed_erc20_tokens.length === 0 && connector.allowed_erc20_recipients.length === 0 && connector.allowed_approval_spenders.length === 0, 500, "invalid_guard_connector", "native connector must not contain ERC-20 policy");
    assert(BigInt(connector.max_erc20_transfer_atomic) === 0n && BigInt(connector.max_erc20_approval_atomic) === 0n, 500, "invalid_guard_connector", "native connector ERC-20 caps must be zero");
  } else {
    assert(BigInt(connector.max_native_value_atomic) === 0n, 500, "invalid_guard_connector", "ERC-20 connector native cap must be zero");
  }
  const expectedAsset = nativeOnly ? `native:eip155:${connector.chain_id}` : getAddress(connector.allowed_erc20_tokens[0]);
  assert(connector.asset_id === expectedAsset, 500, "invalid_guard_connector", "connector.asset_id must identify its single asset domain");
  return connector;
}

function buildReservation(connector, counterparty, amountAtomic, exposure) {
  return {
    connector_id: connector.id,
    period_key_scope: "connector",
    asset: connector.asset_id,
    counterparty,
    amount_atomic: amountAtomic,
    spend_period_seconds: connector.spend_period_seconds,
    max_period_atomic: connector.max_period_atomic,
    exposure,
  };
}

export function evaluateEvmTransaction({ transaction: rawTransaction, connector: rawConnector, simulation } = {}) {
  const transaction = normalizeEvmTransaction(rawTransaction);
  const connector = validateConnector(rawConnector);
  const transactionSha256 = hashCanonical(transaction).sha256;
  const reasons = [];
  const value = BigInt(transaction.value_atomic);
  const gasLimit = BigInt(transaction.gas_limit);
  const maxFeePerGas = BigInt(transaction.max_fee_per_gas_atomic);
  const maxPriorityFeePerGas = BigInt(transaction.max_priority_fee_per_gas_atomic);
  const executionFeeUpperBound = gasLimit * maxFeePerGas;
  const maxTotalFee = BigInt(connector.max_total_fee_atomic);
  let decoded;
  let reservation;
  let feeReservation;
  let nonceReservation;

  if (transaction.chain_id !== connector.chain_id) reasons.push("evm_chain_not_allowed");
  if (transaction.from.toLowerCase() !== connector.from.toLowerCase()) reasons.push("evm_sender_not_allowed");
  if (gasLimit > BigInt(connector.max_gas_limit)) reasons.push("evm_gas_limit_cap_exceeded");
  if (maxFeePerGas > BigInt(connector.max_fee_per_gas_atomic)) reasons.push("evm_max_fee_per_gas_cap_exceeded");
  if (maxPriorityFeePerGas > BigInt(connector.max_priority_fee_per_gas_atomic)) reasons.push("evm_max_priority_fee_per_gas_cap_exceeded");
  if (executionFeeUpperBound > maxTotalFee) reasons.push("evm_max_total_fee_cap_exceeded");

  if (!transaction.to) {
    reasons.push("evm_contract_creation_blocked");
    decoded = { operation: "contract_creation" };
  } else if (transaction.data === "0x") {
    decoded = { operation: "native_transfer", recipient: transaction.to, amount_atomic: transaction.value_atomic };
    reservation = buildReservation(connector, transaction.to, transaction.value_atomic, "transfer");
    if (!includesAddress(connector.allowed_native_recipients, transaction.to)) reasons.push("evm_native_recipient_not_allowed");
    if (value > BigInt(connector.max_native_value_atomic)) reasons.push("evm_native_value_cap_exceeded");
  } else {
    const selector = transaction.data.slice(0, 10);
    if (MULTICALL_SELECTORS.has(selector)) {
      reasons.push("evm_multicall_blocked");
      decoded = { operation: "multicall", selector };
    } else if (selector !== TRANSFER_SELECTOR && selector !== APPROVE_SELECTOR) {
      reasons.push("evm_unknown_selector");
      decoded = { operation: "unknown", selector };
    } else {
      if (value !== 0n) reasons.push("evm_value_with_token_call");
      if (!includesAddress(connector.allowed_erc20_tokens, transaction.to)) reasons.push("evm_token_not_allowed");
      let call;
      try {
        call = decodeFunctionData({ abi: ERC20_ABI, data: transaction.data });
      } catch {
        throw new ServiceError(400, "invalid_evm_calldata", "ERC-20 calldata could not be decoded exactly");
      }
      const canonicalData = encodeFunctionData({ abi: ERC20_ABI, functionName: call.functionName, args: call.args }).toLowerCase();
      if (canonicalData !== transaction.data) reasons.push("evm_noncanonical_calldata");
      const target = getAddress(call.args[0]);
      const amount = BigInt(call.args[1]);
      if (call.functionName === "transfer") {
        decoded = { operation: "erc20_transfer", token: transaction.to, recipient: target, amount_atomic: amount.toString() };
        reservation = buildReservation(connector, target, amount.toString(), "transfer");
        if (!includesAddress(connector.allowed_erc20_recipients, target)) reasons.push("evm_erc20_recipient_not_allowed");
        if (amount > BigInt(connector.max_erc20_transfer_atomic)) reasons.push("evm_erc20_transfer_cap_exceeded");
      } else {
        decoded = { operation: "erc20_approve", token: transaction.to, spender: target, amount_atomic: amount.toString() };
        reservation = buildReservation(connector, target, amount.toString(), "approval");
        if (!includesAddress(connector.allowed_approval_spenders, target)) reasons.push("evm_approval_spender_not_allowed");
        if (amount === MAX_UINT256) reasons.push("evm_unlimited_approval_blocked");
        if (amount > BigInt(connector.max_erc20_approval_atomic)) reasons.push("evm_erc20_approval_cap_exceeded");
      }
    }
  }

  let normalizedSimulation;
  if (simulation !== undefined) {
    normalizedSimulation = validateEvmSimulationEvidence(simulation);
    assert(normalizedSimulation.chain_id === transaction.chain_id, 400, "simulation_transaction_mismatch", "Simulation chain does not match transaction chain");
    assert(normalizedSimulation.transaction_sha256 === transactionSha256, 400, "simulation_transaction_mismatch", "Simulation evidence is bound to a different transaction");
    if (normalizedSimulation.status === "revert") reasons.push("evm_simulation_reverted");
    if (normalizedSimulation.status !== "unavailable") {
      if (BigInt(transaction.nonce) !== BigInt(normalizedSimulation.pending_nonce)) {
        reasons.push("evm_nonce_mismatch");
      } else {
        nonceReservation = Object.freeze({
          period_key_scope: "wallet_nonce",
          lock_key: `eip155:${transaction.chain_id}:${transaction.from}:nonce:${transaction.nonce}`,
          connector_id: connector.id,
          chain_id: transaction.chain_id,
          from: transaction.from,
          nonce: transaction.nonce,
          amount_atomic: "1",
          max_period_atomic: "1",
          exposure: "nonce_lock",
        });
      }
      if (normalizedSimulation.gas_estimate !== undefined && BigInt(normalizedSimulation.gas_estimate) > gasLimit) reasons.push("evm_gas_limit_below_estimate");
      // Base's oracle result is a pinned, point-in-time estimate. It is useful
      // for policy screening and reservation accounting, but is not a protocol
      // guarantee on the L1 data fee charged when a transaction is included.
      const totalFeeEstimate = executionFeeUpperBound
        + BigInt(normalizedSimulation.l1_fee_estimate_atomic)
        + BigInt(normalizedSimulation.operator_fee_estimate_atomic);
      if (totalFeeEstimate > maxTotalFee) reasons.push("evm_max_total_fee_cap_exceeded");
      feeReservation = Object.freeze({
        period_key_scope: "chain_native_fee",
        fee_domain: `native:eip155:${transaction.chain_id}`,
        amount_atomic: totalFeeEstimate.toString(),
        spend_period_seconds: connector.fee_period_seconds,
        max_period_atomic: connector.max_fee_period_atomic,
        exposure: "network_fee",
      });
    }
  }

  if (reasons.length > 0) {
    return decision("BLOCK", reasons, {
      destination: transaction.to ? `eip155:${transaction.chain_id}:${transaction.to}` : `eip155:${transaction.chain_id}:contract_creation`,
      transaction_sha256: transactionSha256,
      decoded,
      reservation,
      fee_reservation: feeReservation,
      nonce_reservation: nonceReservation,
      simulation: normalizedSimulation,
    });
  }
  if (connector.require_simulation && !normalizedSimulation) {
    return decision("REVIEW", ["evm_simulation_required"], {
      destination: `eip155:${transaction.chain_id}:${transaction.to}`,
      transaction_sha256: transactionSha256,
      decoded,
      reservation,
      fee_reservation: feeReservation,
      nonce_reservation: nonceReservation,
      simulation: undefined,
    });
  }
  if (normalizedSimulation?.status === "unavailable") {
    return decision("REVIEW", ["evm_simulation_unavailable"], {
      destination: `eip155:${transaction.chain_id}:${transaction.to}`,
      transaction_sha256: transactionSha256,
      decoded,
      reservation,
      fee_reservation: feeReservation,
      nonce_reservation: nonceReservation,
      simulation: normalizedSimulation,
    });
  }
  return decision("ALLOW", [], {
    destination: `eip155:${transaction.chain_id}:${transaction.to}`,
    transaction_sha256: transactionSha256,
    decoded,
    reservation,
    fee_reservation: feeReservation,
    nonce_reservation: nonceReservation,
    simulation: normalizedSimulation,
  });
}

export function canonicalEvmTransaction(transaction) {
  return canonicalize(normalizeEvmTransaction(transaction));
}
