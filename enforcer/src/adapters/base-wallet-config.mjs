import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { getAddress, isAddress } from "viem";
import { deepFreeze } from "../canonical.mjs";
import { InvalidInputError, LocalStateError } from "../errors.mjs";

export const BASE_WALLET_CONFIG_SCHEMA = "goldkey.base-wallet-config.v1";
export const BASE_MAINNET_CHAIN_ID = 8453;

const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const IDENTIFIER = /^[A-Za-z0-9._:-]{1,128}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_JSON_BYTES = 256 * 1024;

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

function identifier(value, name) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new InvalidInputError(`${name} must be a safe 1-128 character identifier`);
  return value;
}

function atomic(value, name, { positive = false } = {}) {
  if (typeof value !== "string" || !ATOMIC.test(value) || BigInt(value) > MAX_UINT256 || (positive && value === "0")) {
    throw new InvalidInputError(`${name} must be a ${positive ? "positive " : ""}canonical uint256 atomic-unit string`);
  }
  return value;
}

function address(value, name) {
  if (!isAddress(value)) throw new InvalidInputError(`${name} must be an EVM address`);
  return getAddress(value);
}

function addressList(value, name) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) throw new InvalidInputError(`${name} must contain 1-100 addresses`);
  const normalized = value.map((entry, index) => address(entry, `${name}[${index}]`));
  if (new Set(normalized).size !== normalized.length) throw new InvalidInputError(`${name} must not contain duplicates`);
  return Object.freeze(normalized);
}

function envName(value, name) {
  if (typeof value !== "string" || !ENV_NAME.test(value)) throw new InvalidInputError(`${name} must be an uppercase environment-variable name`);
  return value;
}

function absoluteFrom(baseDirectory, value, name) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096 || value.includes("\0")) throw new InvalidInputError(`${name} must be a bounded filesystem path`);
  return path.resolve(baseDirectory, value);
}

function normalizeSignerReference(value, name, baseDirectory) {
  exactObject(value, new Set(["type", "key_env", "path", "password_env", "clear_env_after_load"]), name);
  if (value.type === "env") {
    required(value, ["type", "key_env"], name);
    if (value.path !== undefined || value.password_env !== undefined) throw new InvalidInputError(`${name} env signer must not contain keystore fields`);
    if (value.clear_env_after_load !== undefined && typeof value.clear_env_after_load !== "boolean") throw new InvalidInputError(`${name}.clear_env_after_load must be boolean`);
    return Object.freeze({
      type: "env",
      key_env: envName(value.key_env, `${name}.key_env`),
      clear_env_after_load: value.clear_env_after_load ?? true,
    });
  }
  if (value.type === "keystore") {
    required(value, ["type", "path", "password_env"], name);
    if (value.key_env !== undefined) throw new InvalidInputError(`${name} keystore signer must not contain key_env`);
    if (value.clear_env_after_load !== undefined && typeof value.clear_env_after_load !== "boolean") throw new InvalidInputError(`${name}.clear_env_after_load must be boolean`);
    return Object.freeze({
      type: "keystore",
      path: absoluteFrom(baseDirectory, value.path, `${name}.path`),
      password_env: envName(value.password_env, `${name}.password_env`),
      clear_env_after_load: value.clear_env_after_load ?? true,
    });
  }
  throw new InvalidInputError(`${name}.type must be env or keystore`);
}

function normalizeOperation(value, name) {
  exactObject(value, new Set(["kind", "token", "recipients", "spenders", "max_amount_atomic"]), name);
  required(value, ["kind", "max_amount_atomic"], name);
  const maximum = atomic(value.max_amount_atomic, `${name}.max_amount_atomic`, { positive: true });
  if (value.kind === "native_transfer") {
    required(value, ["recipients"], name);
    if (value.token !== undefined || value.spenders !== undefined) throw new InvalidInputError(`${name} native transfer must not contain token or spenders`);
    return Object.freeze({ kind: value.kind, recipients: addressList(value.recipients, `${name}.recipients`), max_amount_atomic: maximum });
  }
  if (value.kind === "erc20_transfer") {
    required(value, ["token", "recipients"], name);
    if (value.spenders !== undefined) throw new InvalidInputError(`${name} ERC-20 transfer must not contain spenders`);
    return Object.freeze({ kind: value.kind, token: address(value.token, `${name}.token`), recipients: addressList(value.recipients, `${name}.recipients`), max_amount_atomic: maximum });
  }
  if (value.kind === "erc20_approve") {
    required(value, ["token", "spenders"], name);
    if (value.recipients !== undefined) throw new InvalidInputError(`${name} ERC-20 approve must not contain recipients`);
    return Object.freeze({ kind: value.kind, token: address(value.token, `${name}.token`), spenders: addressList(value.spenders, `${name}.spenders`), max_amount_atomic: maximum });
  }
  throw new InvalidInputError(`${name}.kind must be native_transfer, erc20_transfer, or erc20_approve`);
}

function normalizeConnector(value, index) {
  const name = `connectors[${index}]`;
  exactObject(value, new Set([
    "id", "chain_id", "from", "max_gas_limit", "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic",
    "max_estimated_network_fee_atomic", "max_wallet_native_exposure_atomic", "operations",
  ]), name);
  required(value, [
    "id", "chain_id", "from", "max_gas_limit", "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic",
    "max_estimated_network_fee_atomic", "max_wallet_native_exposure_atomic", "operations",
  ], name);
  if (value.chain_id !== BASE_MAINNET_CHAIN_ID) throw new InvalidInputError(`${name}.chain_id must be Base mainnet 8453`);
  if (!Array.isArray(value.operations) || value.operations.length < 1 || value.operations.length > 100) throw new InvalidInputError(`${name}.operations must contain 1-100 operations`);
  const operations = value.operations.map((entry, operationIndex) => normalizeOperation(entry, `${name}.operations[${operationIndex}]`));
  const operationKeys = operations.map((operation) => `${operation.kind}:${operation.token ?? "native"}`);
  if (new Set(operationKeys).size !== operationKeys.length) throw new InvalidInputError(`${name}.operations must not repeat an operation/token pair`);
  const maxGasLimit = atomic(value.max_gas_limit, `${name}.max_gas_limit`, { positive: true });
  const maxFeePerGas = atomic(value.max_fee_per_gas_atomic, `${name}.max_fee_per_gas_atomic`, { positive: true });
  const maxPriorityFee = atomic(value.max_priority_fee_per_gas_atomic, `${name}.max_priority_fee_per_gas_atomic`);
  const maxEstimatedFee = atomic(value.max_estimated_network_fee_atomic, `${name}.max_estimated_network_fee_atomic`, { positive: true });
  const maxWalletExposure = atomic(value.max_wallet_native_exposure_atomic, `${name}.max_wallet_native_exposure_atomic`, { positive: true });
  if (BigInt(maxPriorityFee) > BigInt(maxFeePerGas)) throw new InvalidInputError(`${name} priority fee cap exceeds max fee cap`);
  if (BigInt(maxEstimatedFee) > BigInt(maxWalletExposure)) throw new InvalidInputError(`${name} estimated network-fee cap exceeds wallet exposure cap`);
  return Object.freeze({
    id: identifier(value.id, `${name}.id`),
    chain_id: BASE_MAINNET_CHAIN_ID,
    from: address(value.from, `${name}.from`),
    max_gas_limit: maxGasLimit,
    max_fee_per_gas_atomic: maxFeePerGas,
    max_priority_fee_per_gas_atomic: maxPriorityFee,
    max_estimated_network_fee_atomic: maxEstimatedFee,
    max_wallet_native_exposure_atomic: maxWalletExposure,
    operations: Object.freeze(operations),
  });
}

export function normalizeBaseWalletConfig(document, { baseDirectory = process.cwd(), filename = "<memory>" } = {}) {
  exactObject(document, new Set([
    "schema", "rpc_url_env", "execution_signer", "connectors",
  ]), "Base wallet config");
  required(document, [
    "schema", "rpc_url_env", "execution_signer", "connectors",
  ], "Base wallet config");
  if (document.schema !== BASE_WALLET_CONFIG_SCHEMA) throw new InvalidInputError(`Base wallet config schema must be ${BASE_WALLET_CONFIG_SCHEMA}`);
  if (!Array.isArray(document.connectors) || document.connectors.length < 1 || document.connectors.length > 64) throw new InvalidInputError("connectors must contain 1-64 entries");
  const connectors = document.connectors.map(normalizeConnector);
  if (new Set(connectors.map(({ id }) => id)).size !== connectors.length) throw new InvalidInputError("connector IDs must be unique");
  return deepFreeze({
    schema: BASE_WALLET_CONFIG_SCHEMA,
    filename: path.resolve(filename),
    rpc_url_env: envName(document.rpc_url_env, "rpc_url_env"),
    execution_signer: normalizeSignerReference(document.execution_signer, "execution_signer", baseDirectory),
    connectors: Object.freeze(connectors),
  });
}

export async function readOperatorJsonFile(filename, { name = "operator file", maximumBytes = MAX_JSON_BYTES, requirePrivate = false } = {}) {
  const resolved = path.resolve(filename);
  let handle;
  try {
    handle = await open(resolved, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch (cause) {
    throw new LocalStateError(`Unable to open ${name} ${resolved} without following symlinks`, { cause });
  }
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new LocalStateError(`${name} must be a regular non-symlink file`);
    if (before.size < 2 || before.size > maximumBytes) throw new LocalStateError(`${name} exceeds its allowed size`);
    if (process.platform !== "win32") {
      const forbidden = requirePrivate ? 0o077 : 0o022;
      if ((before.mode & forbidden) !== 0) throw new LocalStateError(`${name} has unsafe filesystem permissions`);
      const effectiveUid = process.geteuid?.();
      if (effectiveUid !== undefined && before.uid !== 0 && before.uid !== effectiveUid) {
        throw new LocalStateError(`${name} must be owned by root or the wallet process user`);
      }
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (
      bytes.byteLength !== before.size
      || bytes.byteLength > maximumBytes
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs
    ) throw new LocalStateError(`${name} changed while it was being read`);
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch (cause) {
      throw new LocalStateError(`${name} is not valid JSON`, { cause });
    }
  } catch (cause) {
    if (cause instanceof LocalStateError) throw cause;
    throw new LocalStateError(`Unable to read ${name} ${resolved}`, { cause });
  } finally {
    await handle.close().catch(() => {});
  }
}

export async function loadBaseWalletConfig(filename) {
  if (typeof filename !== "string" || filename.length < 1) throw new InvalidInputError("A Base wallet config filename is required");
  const resolved = path.resolve(filename);
  const document = await readOperatorJsonFile(resolved, { name: "Base wallet config" });
  const section = document && typeof document === "object" && !Array.isArray(document) && Object.hasOwn(document, "base_wallet")
    ? document.base_wallet
    : document;
  return normalizeBaseWalletConfig(section, { baseDirectory: path.dirname(resolved), filename: resolved });
}

export function resolveBaseRpcUrl(config, env = process.env) {
  const value = env?.[config.rpc_url_env];
  if (typeof value !== "string" || value.length < 1 || value.length > 4096) throw new InvalidInputError(`Missing HTTPS Base RPC URL in ${config.rpc_url_env}`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new InvalidInputError(`${config.rpc_url_env} must contain an absolute HTTPS URL`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) throw new InvalidInputError(`${config.rpc_url_env} must contain a credential-free HTTPS URL`);
  return value;
}
