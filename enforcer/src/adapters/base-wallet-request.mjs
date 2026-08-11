import { decodeFunctionData, encodeFunctionData, getAddress, isAddress, parseAbi } from "viem";
import { deepFreeze } from "../canonical.mjs";
import { InvalidInputError } from "../errors.mjs";
import { BASE_MAINNET_CHAIN_ID } from "./base-wallet-config.mjs";

export const BASE_WALLET_REQUEST_SCHEMA = "goldkey.base-wallet-request.v1";
export const BASE_WALLET_PROBE_SCHEMA = "goldkey.base-wallet-probe.v1";

const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const IDEMPOTENCY = /^[A-Za-z0-9._:-]{8,128}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);

function exactObject(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError(`${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
  return value;
}

function required(value, keys, name) {
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) throw new InvalidInputError(`${name} is missing required fields`, { fields: missing.sort() });
}

function atomic(value, name, { positive = false, safeInteger = false } = {}) {
  if (typeof value !== "string" || !ATOMIC.test(value) || BigInt(value) > MAX_UINT256 || (positive && value === "0")) {
    throw new InvalidInputError(`${name} must be a ${positive ? "positive " : ""}canonical uint256 atomic-unit string`);
  }
  if (safeInteger && BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) throw new InvalidInputError(`${name} exceeds the supported safe-integer range`);
  return value;
}

function address(value, name) {
  if (!isAddress(value)) throw new InvalidInputError(`${name} must be an EVM address`);
  return getAddress(value);
}

function includesAddress(values, candidate) {
  return values.some((value) => value === candidate);
}

function connectorFor(config, connectorId) {
  if (typeof connectorId !== "string") throw new InvalidInputError("connector_id must be a string");
  const connector = config.connectors.find(({ id }) => id === connectorId);
  if (!connector) throw new InvalidInputError("connector_id is not present in the operator-owned Base wallet config");
  return connector;
}

function operationFor(connector, operation, target) {
  return connector.operations.find((entry) => entry.kind === operation && (entry.token ?? null) === (target ?? null));
}

function normalizeOperation(value, connector) {
  exactObject(value, new Set(["kind", "to", "token", "spender", "amount_atomic"]), "operation");
  required(value, ["kind", "amount_atomic"], "operation");
  if (value.kind === "native_transfer") {
    required(value, ["to"], "operation");
    if (value.token !== undefined || value.spender !== undefined) throw new InvalidInputError("native_transfer must not contain token or spender");
    const to = address(value.to, "operation.to");
    const amount = atomic(value.amount_atomic, "operation.amount_atomic", { positive: true });
    const policy = operationFor(connector, value.kind, null);
    if (!policy || !includesAddress(policy.recipients, to)) throw new InvalidInputError("native transfer recipient is not in the operator-owned connector config");
    if (BigInt(amount) > BigInt(policy.max_amount_atomic)) throw new InvalidInputError("native transfer exceeds the operator-owned amount cap");
    return Object.freeze({ kind: value.kind, to, amount_atomic: amount });
  }
  if (value.kind === "erc20_transfer") {
    required(value, ["token", "to"], "operation");
    if (value.spender !== undefined) throw new InvalidInputError("erc20_transfer must not contain spender");
    const token = address(value.token, "operation.token");
    const to = address(value.to, "operation.to");
    const amount = atomic(value.amount_atomic, "operation.amount_atomic", { positive: true });
    const policy = operationFor(connector, value.kind, token);
    if (!policy || !includesAddress(policy.recipients, to)) throw new InvalidInputError("ERC-20 transfer token/recipient is not in the operator-owned connector config");
    if (BigInt(amount) > BigInt(policy.max_amount_atomic)) throw new InvalidInputError("ERC-20 transfer exceeds the operator-owned amount cap");
    return Object.freeze({ kind: value.kind, token, to, amount_atomic: amount });
  }
  if (value.kind === "erc20_approve") {
    required(value, ["token", "spender"], "operation");
    if (value.to !== undefined) throw new InvalidInputError("erc20_approve must not contain to");
    const token = address(value.token, "operation.token");
    const spender = address(value.spender, "operation.spender");
    const amount = atomic(value.amount_atomic, "operation.amount_atomic");
    const policy = operationFor(connector, value.kind, token);
    if (!policy || !includesAddress(policy.spenders, spender)) throw new InvalidInputError("ERC-20 approval token/spender is not in the operator-owned connector config");
    if (BigInt(amount) > BigInt(policy.max_amount_atomic)) throw new InvalidInputError("ERC-20 approval exceeds the operator-owned amount cap");
    if (BigInt(amount) === MAX_UINT256) throw new InvalidInputError("Unlimited ERC-20 approval is forbidden");
    return Object.freeze({ kind: value.kind, token, spender, amount_atomic: amount });
  }
  throw new InvalidInputError("operation.kind must be native_transfer, erc20_transfer, or erc20_approve");
}

/**
 * Independent signer-side defense. Even though normal calls come from
 * buildBaseWalletCall() through the shared enforcer, the final local callback
 * re-derives the allowed operation from the exact transaction bytes/fields.
 */
export function assertBaseWalletTransactionAllowed({ connector, transaction }) {
  exactObject(transaction, new Set([
    "chain_id", "from", "to", "value_atomic", "data", "nonce", "gas_limit", "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic", "type", "access_list",
  ]), "Base wallet transaction");
  required(transaction, [
    "chain_id", "from", "to", "value_atomic", "data", "nonce", "gas_limit", "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic", "type", "access_list",
  ], "Base wallet transaction");
  if (transaction.chain_id !== connector.chain_id || address(transaction.from, "transaction.from") !== connector.from) {
    throw new InvalidInputError("Base wallet transaction chain/from is not operator-bound");
  }
  if (transaction.type !== "eip1559" || !Array.isArray(transaction.access_list) || transaction.access_list.length !== 0) {
    throw new InvalidInputError("Base wallet transaction must be EIP-1559 with an empty access list");
  }
  const to = address(transaction.to, "transaction.to");
  const value = atomic(transaction.value_atomic, "transaction.value_atomic");
  atomic(transaction.nonce, "transaction.nonce", { safeInteger: true });
  const gasLimit = atomic(transaction.gas_limit, "transaction.gas_limit", { positive: true });
  const maxFee = atomic(transaction.max_fee_per_gas_atomic, "transaction.max_fee_per_gas_atomic", { positive: true });
  const priorityFee = atomic(transaction.max_priority_fee_per_gas_atomic, "transaction.max_priority_fee_per_gas_atomic");
  if (BigInt(gasLimit) > BigInt(connector.max_gas_limit)) throw new InvalidInputError("transaction.gas_limit exceeds the operator-owned connector cap");
  if (BigInt(maxFee) > BigInt(connector.max_fee_per_gas_atomic)) throw new InvalidInputError("transaction.max_fee_per_gas_atomic exceeds the operator-owned connector cap");
  if (BigInt(priorityFee) > BigInt(maxFee) || BigInt(priorityFee) > BigInt(connector.max_priority_fee_per_gas_atomic)) {
    throw new InvalidInputError("transaction.max_priority_fee_per_gas_atomic exceeds an operator-owned fee cap");
  }
  if (typeof transaction.data !== "string" || !/^0x(?:[0-9a-f]{2})*$/.test(transaction.data)) {
    throw new InvalidInputError("transaction.data must be canonical lowercase hexadecimal bytes");
  }

  if (transaction.data === "0x") {
    if (value === "0") throw new InvalidInputError("Native transfer amount must be positive");
    const policy = operationFor(connector, "native_transfer", null);
    if (!policy || !includesAddress(policy.recipients, to)) throw new InvalidInputError("Native transaction recipient is not operator-allowlisted");
    if (BigInt(value) > BigInt(policy.max_amount_atomic)) throw new InvalidInputError("Native transaction exceeds the operator-owned amount cap");
    return Object.freeze({ kind: "native_transfer", to, amount_atomic: value });
  }

  if (value !== "0") throw new InvalidInputError("ERC-20 transaction must carry zero native value");
  let decoded;
  try {
    decoded = decodeFunctionData({ abi: ERC20_ABI, data: transaction.data });
  } catch (cause) {
    throw new InvalidInputError("Only canonical ERC-20 transfer or approve calldata is allowed", { cause });
  }
  const kind = decoded.functionName === "transfer" ? "erc20_transfer" : decoded.functionName === "approve" ? "erc20_approve" : null;
  if (!kind || !Array.isArray(decoded.args) || decoded.args.length !== 2) {
    throw new InvalidInputError("Only canonical ERC-20 transfer or approve calldata is allowed");
  }
  const destination = address(decoded.args[0], kind === "erc20_transfer" ? "transfer recipient" : "approval spender");
  const amount = atomic(BigInt(decoded.args[1]).toString(), "ERC-20 amount", { positive: kind === "erc20_transfer" });
  if (kind === "erc20_approve" && BigInt(amount) === MAX_UINT256) throw new InvalidInputError("Unlimited ERC-20 approval is forbidden");
  const canonicalData = encodeFunctionData({
    abi: ERC20_ABI,
    functionName: decoded.functionName,
    args: [destination, BigInt(amount)],
  }).toLowerCase();
  if (canonicalData !== transaction.data) throw new InvalidInputError("ERC-20 calldata is not in its canonical exact encoding");
  const policy = operationFor(connector, kind, to);
  const destinations = kind === "erc20_transfer" ? policy?.recipients : policy?.spenders;
  if (!policy || !includesAddress(destinations, destination)) throw new InvalidInputError("ERC-20 token/destination is not operator-allowlisted");
  if (BigInt(amount) > BigInt(policy.max_amount_atomic)) throw new InvalidInputError("ERC-20 transaction exceeds the operator-owned amount cap");
  return Object.freeze(kind === "erc20_transfer"
    ? { kind, token: to, to: destination, amount_atomic: amount }
    : { kind, token: to, spender: destination, amount_atomic: amount });
}

export function buildBaseWalletCall({ config, request }) {
  exactObject(request, new Set([
    "schema", "connector_id", "idempotency_key", "nonce", "gas_limit", "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic", "operation",
  ]), "Base wallet request");
  required(request, [
    "schema", "connector_id", "idempotency_key", "nonce", "gas_limit", "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic", "operation",
  ], "Base wallet request");
  if (request.schema !== BASE_WALLET_REQUEST_SCHEMA) throw new InvalidInputError(`Base wallet request schema must be ${BASE_WALLET_REQUEST_SCHEMA}`);
  if (typeof request.idempotency_key !== "string" || !IDEMPOTENCY.test(request.idempotency_key)) throw new InvalidInputError("idempotency_key must be 8-128 safe characters");
  const connector = connectorFor(config, request.connector_id);
  const nonce = atomic(request.nonce, "nonce", { safeInteger: true });
  const gasLimit = atomic(request.gas_limit, "gas_limit", { positive: true });
  const maxFeePerGas = atomic(request.max_fee_per_gas_atomic, "max_fee_per_gas_atomic", { positive: true });
  const maxPriorityFeePerGas = atomic(request.max_priority_fee_per_gas_atomic, "max_priority_fee_per_gas_atomic");
  if (BigInt(maxPriorityFeePerGas) > BigInt(maxFeePerGas)) throw new InvalidInputError("max_priority_fee_per_gas_atomic exceeds max_fee_per_gas_atomic");
  if (BigInt(gasLimit) > BigInt(connector.max_gas_limit)) throw new InvalidInputError("gas_limit exceeds the operator-owned connector cap");
  if (BigInt(maxFeePerGas) > BigInt(connector.max_fee_per_gas_atomic)) throw new InvalidInputError("max_fee_per_gas_atomic exceeds the operator-owned connector cap");
  if (BigInt(maxPriorityFeePerGas) > BigInt(connector.max_priority_fee_per_gas_atomic)) throw new InvalidInputError("max_priority_fee_per_gas_atomic exceeds the operator-owned connector cap");
  const operation = normalizeOperation(request.operation, connector);

  let to;
  let value;
  let data;
  if (operation.kind === "native_transfer") {
    to = operation.to;
    value = operation.amount_atomic;
    data = "0x";
  } else {
    to = operation.token;
    value = "0";
    data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: operation.kind === "erc20_transfer" ? "transfer" : "approve",
      args: operation.kind === "erc20_transfer"
        ? [operation.to, BigInt(operation.amount_atomic)]
        : [operation.spender, BigInt(operation.amount_atomic)],
    }).toLowerCase();
  }
  const transaction = {
    chain_id: BASE_MAINNET_CHAIN_ID,
    from: connector.from,
    to,
    value_atomic: value,
    data,
    nonce,
    gas_limit: gasLimit,
    max_fee_per_gas_atomic: maxFeePerGas,
    max_priority_fee_per_gas_atomic: maxPriorityFeePerGas,
    type: "eip1559",
    access_list: [],
  };
  assertBaseWalletTransactionAllowed({ connector, transaction });
  return deepFreeze({
    connector,
    connectorId: connector.id,
    idempotencyKey: request.idempotency_key,
    operation,
    transaction,
  });
}

export function probeBaseWalletRequest({ config, request }) {
  const call = buildBaseWalletCall({ config, request });
  return deepFreeze({
    schema: BASE_WALLET_PROBE_SCHEMA,
    mode: "probe",
    payment_attempted: false,
    signer_loaded: false,
    transaction_signed: false,
    transaction_broadcast: false,
    connector_id: call.connectorId,
    idempotency_key: call.idempotencyKey,
    operation: call.operation,
    transaction: call.transaction,
    local_caps: {
      max_gas_limit: call.connector.max_gas_limit,
      max_fee_per_gas_atomic: call.connector.max_fee_per_gas_atomic,
      max_priority_fee_per_gas_atomic: call.connector.max_priority_fee_per_gas_atomic,
      max_estimated_network_fee_atomic: call.connector.max_estimated_network_fee_atomic,
      max_wallet_native_exposure_atomic: call.connector.max_wallet_native_exposure_atomic,
    },
  });
}
