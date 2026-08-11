import { chmod, lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import {
  BASE_MAINNET_USDC,
  GUARD_EVM_PAYMENT_ATOMIC,
  GUARD_NETWORK_PAYMENT_ATOMIC,
  RemoteAuthorizer,
} from "../authorization.mjs";
import { GoldKeyEnforcer } from "../enforcer.mjs";
import { InvalidInputError, LocalStateError } from "../errors.mjs";
import { loadOrCreateInstallationIdentity } from "../identity.mjs";
import { createGuardLifecycleHttpClient } from "../lifecycle-http.mjs";
import { SqlitePaymentBudgetStore } from "../payment-budget.mjs";
import { normalizeReceiptKeyset } from "../protocol.mjs";
import { FileOutcomeStore } from "../state-store.mjs";

export const GOLDKEY_GUARD_ORIGIN = "https://goldkey-edge-storefront.noah-ing.workers.dev";
export const GOLDKEY_GUARD_TREASURY = "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b";
export const GUARD_RUNTIME_CONFIG_SCHEMA = "goldkey.enforcer-runtime.v1";

const SHA256 = /^[0-9a-f]{64}$/;
const ENVIRONMENT_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const CALL_KINDS = new Set(["network", "evm"]);

function exactObject(value, keys, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidInputError(`${name} must be an object`);
  }
  const extras = Object.keys(value).filter((key) => !keys.has(key));
  if (extras.length > 0) {
    throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
  }
  return value;
}

function positiveInteger(value, name, { minimum = 1, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new InvalidInputError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function positiveAtomic(value, name) {
  if (typeof value !== "string" || !/^[1-9]\d{0,77}$/.test(value)) {
    throw new InvalidInputError(`${name} must be a canonical positive atomic-unit integer string`);
  }
  return value;
}

function relativePrivatePath(value, name, baseDirectory) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096 || value.includes("\0")) {
    throw new InvalidInputError(`${name} must be a bounded filesystem path`);
  }
  return path.resolve(baseDirectory, value);
}

async function assertNotWritableByOthers(filename, name) {
  let metadata;
  try {
    metadata = await lstat(filename);
  } catch (cause) {
    throw new LocalStateError(`Unable to inspect ${name} ${filename}`, { cause });
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new LocalStateError(`${name} ${filename} must be a regular non-symlink file`);
  }
  if (process.platform !== "win32") {
    if ((metadata.mode & 0o022) !== 0) {
      throw new LocalStateError(`${name} ${filename} must not be writable by group or other users`);
    }
    const effectiveUid = process.geteuid?.();
    if (effectiveUid !== undefined && metadata.uid !== 0 && metadata.uid !== effectiveUid) {
      throw new LocalStateError(`${name} ${filename} must be owned by root or the launcher user`);
    }
  }
  return metadata;
}

async function readBoundedJson(filename, name, maximumBytes = 64 * 1024) {
  const metadata = await assertNotWritableByOthers(filename, name);
  if (metadata.size < 2 || metadata.size > maximumBytes) {
    throw new LocalStateError(`${name} must be 2-${maximumBytes} bytes`);
  }
  let bytes;
  try {
    bytes = await readFile(filename);
  } catch (cause) {
    throw new LocalStateError(`Unable to read ${name} ${filename}`, { cause });
  }
  if (bytes.byteLength !== metadata.size || bytes.byteLength > maximumBytes) {
    throw new LocalStateError(`${name} changed while it was being read`);
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw new LocalStateError(`${name} is not valid UTF-8 JSON`, { cause });
  }
}

export function normalizeGuardRuntimeConfig(raw, { configDirectory = process.cwd() } = {}) {
  const config = exactObject(raw, new Set([
    "schema",
    "policy_sha256",
    "installation_key_file",
    "receipt_keyset_file",
    "state_directory",
    "payment",
  ]), "GoldKey runtime config");
  if (config.schema !== GUARD_RUNTIME_CONFIG_SCHEMA) {
    throw new InvalidInputError(`GoldKey runtime config schema must be ${GUARD_RUNTIME_CONFIG_SCHEMA}`);
  }
  if (typeof config.policy_sha256 !== "string" || !SHA256.test(config.policy_sha256)) {
    throw new InvalidInputError("policy_sha256 must be a lowercase SHA-256 digest");
  }
  const payment = exactObject(config.payment, new Set([
    "payer_private_key_env",
    "budget_database_file",
    "period_seconds",
    "max_period_atomic",
    "max_outstanding_atomic",
    "max_outstanding_count",
    "timeout_ms",
  ]), "GoldKey runtime payment config");
  if (typeof payment.payer_private_key_env !== "string" || !ENVIRONMENT_NAME.test(payment.payer_private_key_env)) {
    throw new InvalidInputError("payment.payer_private_key_env must name one uppercase environment variable");
  }
  return Object.freeze({
    schema: GUARD_RUNTIME_CONFIG_SCHEMA,
    policy_sha256: config.policy_sha256,
    installation_key_file: relativePrivatePath(config.installation_key_file, "installation_key_file", configDirectory),
    receipt_keyset_file: relativePrivatePath(config.receipt_keyset_file, "receipt_keyset_file", configDirectory),
    state_directory: relativePrivatePath(config.state_directory, "state_directory", configDirectory),
    payment: Object.freeze({
      payer_private_key_env: payment.payer_private_key_env,
      budget_database_file: relativePrivatePath(payment.budget_database_file, "payment.budget_database_file", configDirectory),
      period_seconds: positiveInteger(payment.period_seconds, "payment.period_seconds", { minimum: 60, maximum: 31_536_000 }),
      max_period_atomic: positiveAtomic(payment.max_period_atomic, "payment.max_period_atomic"),
      max_outstanding_atomic: positiveAtomic(payment.max_outstanding_atomic, "payment.max_outstanding_atomic"),
      max_outstanding_count: positiveInteger(payment.max_outstanding_count, "payment.max_outstanding_count", { maximum: 1_000_000 }),
      timeout_ms: positiveInteger(payment.timeout_ms ?? 15_000, "payment.timeout_ms", { maximum: 30_000 }),
    }),
  });
}

export async function loadGuardRuntimeConfig(filename) {
  if (typeof filename !== "string" || filename.length < 1) {
    throw new InvalidInputError("A GoldKey runtime config filename is required");
  }
  const resolved = path.resolve(filename);
  const document = await readBoundedJson(resolved, "GoldKey runtime config");
  const raw = document && typeof document === "object" && !Array.isArray(document) && Object.hasOwn(document, "runtime")
    ? document.runtime
    : document;
  return normalizeGuardRuntimeConfig(raw, { configDirectory: path.dirname(resolved) });
}

export async function createConfiguredGuardRuntime({
  config: rawConfig,
  callKind,
  connectors,
  env = process.env,
  fetchImpl = globalThis.fetch,
  serviceOrigin = GOLDKEY_GUARD_ORIGIN,
  treasuryAddress = GOLDKEY_GUARD_TREASURY,
  clock,
  enforcerOptions = {},
} = {}) {
  if (!CALL_KINDS.has(callKind)) throw new InvalidInputError("callKind must be network or evm");
  if (typeof fetchImpl !== "function") throw new InvalidInputError("A fetch implementation is required");
  let parsedServiceOrigin;
  try {
    parsedServiceOrigin = new URL(serviceOrigin);
  } catch {
    throw new InvalidInputError("serviceOrigin must be exactly one HTTPS origin");
  }
  if (parsedServiceOrigin.protocol !== "https:" || serviceOrigin !== parsedServiceOrigin.origin) {
    throw new InvalidInputError("serviceOrigin must be exactly one HTTPS origin");
  }
  const config = normalizeGuardRuntimeConfig(rawConfig);
  const secret = env?.[config.payment.payer_private_key_env];
  if (typeof secret !== "string" || !PRIVATE_KEY.test(secret)) {
    throw new LocalStateError(`Environment variable ${config.payment.payer_private_key_env} must contain one 32-byte EVM private key`);
  }
  const payer = privateKeyToAccount(secret);
  const installationIdentity = await loadOrCreateInstallationIdentity(config.installation_key_file);
  const receiptKeyset = normalizeReceiptKeyset({
    receiptKeyset: await readBoundedJson(config.receipt_keyset_file, "GoldKey receipt keyset"),
  });
  const paymentBudget = new SqlitePaymentBudgetStore({
    filename: config.payment.budget_database_file,
    periodSeconds: config.payment.period_seconds,
    maxPeriodAtomic: config.payment.max_period_atomic,
    maxOutstandingAtomic: config.payment.max_outstanding_atomic,
    maxOutstandingCount: config.payment.max_outstanding_count,
    ...(clock ? { clock } : {}),
  });
  const route = callKind === "evm" ? "evm" : "network";
  const price = callKind === "evm" ? GUARD_EVM_PAYMENT_ATOMIC : GUARD_NETWORK_PAYMENT_ATOMIC;
  const authorizer = new RemoteAuthorizer({
    authorizeUrl: `${serviceOrigin}/v1/guard/paygo/authorize/${route}`,
    fetchImpl,
    installationIdentity,
    receiptKeyset,
    policyHash: config.policy_sha256,
    payment: {
      signer: payer,
      treasuryAddress,
      maxAmountAtomic: price,
      timeoutMs: config.payment.timeout_ms,
      budgetStore: paymentBudget,
    },
    ...(clock ? { clock } : {}),
  });
  const lifecycle = createGuardLifecycleHttpClient({ serviceOrigin, fetchImpl });
  const outcomeStore = new FileOutcomeStore({
    directory: config.state_directory,
    ...(clock ? { clock } : {}),
  });
  const enforcer = new GoldKeyEnforcer({
    installationIdentity,
    outcomeStore,
    authorizer,
    commitAuthorization: lifecycle.commitAuthorization,
    completeAuthorization: lifecycle.completeAuthorization,
    connectors,
    ...(clock ? { clock } : {}),
    ...enforcerOptions,
  });
  return Object.freeze({
    config,
    enforcer,
    installation: Object.freeze({
      installation_id: installationIdentity.installationId,
      public_key_jwk: installationIdentity.publicJwk,
    }),
    payment: Object.freeze({
      asset: BASE_MAINNET_USDC,
      payer: payer.address,
      max_per_authorization_atomic: price,
      budgetStore: paymentBudget,
    }),
  });
}

export async function createConfiguredGuardRuntimeFromFile({ filename, ...options } = {}) {
  return createConfiguredGuardRuntime({
    ...options,
    config: await loadGuardRuntimeConfig(filename),
  });
}

export async function secureConfigFile(filename) {
  if (process.platform !== "win32") await chmod(path.resolve(filename), 0o600);
}
