import { createHash, createPublicKey, verify as verifyBytes } from "node:crypto";
import { getAddress, isAddress } from "viem";
import { canonicalize, sha256 } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";
import { normalizeBoundedJsonSchema } from "./tools.mjs";

export const GUARD_POLICY_SCHEMA = "goldkey.guard-policy.v1";
export const GUARD_POLICY_SIGNING_DOMAIN = "GoldKey Guard Policy v1";
export const GUARD_INSTALLATION_SCHEMA = "goldkey.guard-installation.v1";
export const GUARD_INSTALLATION_SIGNING_DOMAIN = "GoldKey Guard Installation v1";
export const GUARD_INSTALLATION_KEY_PROOF_DOMAIN = "GoldKey Guard Installation Key Proof v1";
export const GUARD_REVOCATION_SCHEMA = "goldkey.guard-revocation.v1";
export const GUARD_REVOCATION_SIGNING_DOMAIN = "GoldKey Guard Revocation v1";

const EFFECTS = new Set(["read", "write", "network", "payment", "execute"]);
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const TOOL_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ATOMIC_PATTERN = /^(0|[1-9]\d{0,77})$/;
const HEX_SIGNATURE_PATTERN = /^0x[0-9a-fA-F]+$/;
const INSTALLATION_ID_PATTERN = /^gki_[A-Za-z0-9_-]{43}$/;
const ED25519_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

function exactKeys(value, allowed, name) {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, "invalid_guard_policy", `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, "invalid_guard_policy", `${name} contains unsupported fields`, { fields: extras.sort() });
}

function safeId(value, name, pattern = ID_PATTERN) {
  assert(typeof value === "string" && pattern.test(value), 400, "invalid_guard_policy", `${name} is invalid`);
  return value;
}

function canonicalDate(value, name) {
  assert(typeof value === "string", 400, "invalid_guard_policy", `${name} must be an ISO date-time`);
  const parsed = Date.parse(value);
  assert(Number.isFinite(parsed) && new Date(parsed).toISOString() === value, 400, "invalid_guard_policy", `${name} must be a canonical ISO date-time`);
  return value;
}

function address(value, name) {
  assert(typeof value === "string" && isAddress(value), 400, "invalid_guard_policy", `${name} must be an EVM address`);
  return getAddress(value);
}

function atomic(value, name) {
  assert(typeof value === "string" && ATOMIC_PATTERN.test(value), 400, "invalid_guard_policy", `${name} must be a canonical atomic-unit integer string of at most 78 digits`);
  return value;
}

function stringArray(value, name, itemValidator, { max = 100, min = 0 } = {}) {
  assert(Array.isArray(value) && value.length >= min && value.length <= max, 400, "invalid_guard_policy", `${name} must contain ${min}-${max} items`);
  const normalized = value.map((item, index) => itemValidator(item, `${name}[${index}]`));
  assert(new Set(normalized.map((item) => String(item).toLowerCase())).size === normalized.length, 400, "invalid_guard_policy", `${name} must not contain duplicates`);
  return normalized;
}

function validateEffect(value, name) {
  assert(EFFECTS.has(value), 400, "invalid_guard_policy", `${name} must be a supported effect`);
  return value;
}

function boundedPolicySchema(value, name) {
  try {
    return normalizeBoundedJsonSchema(value, { cache: true });
  } catch (cause) {
    if (!(cause instanceof ServiceError)) throw cause;
    throw new ServiceError(cause.status, "invalid_guard_policy", `${name} is invalid: ${cause.message}`, {
      schema_error_code: cause.code,
    });
  }
}

function validateMcpConnector(connector) {
  exactKeys(connector, new Set(["id", "kind", "server_id", "tools"]), `connector ${connector.id ?? "?"}`);
  const tools = connector.tools;
  assert(Array.isArray(tools) && tools.length >= 1 && tools.length <= 100, 400, "invalid_guard_policy", "mcp_tool connector tools must contain 1-100 entries");
  const normalizedTools = tools.map((tool, index) => {
    exactKeys(tool, new Set(["name", "effect", "input_schema_sha256", "arguments_schema"]), `mcp tool ${index}`);
    assert(typeof tool.input_schema_sha256 === "string" && SHA256_PATTERN.test(tool.input_schema_sha256), 400, "invalid_guard_policy", `mcp tool ${index} input_schema_sha256 is invalid`);
    return {
      name: safeId(tool.name, `mcp tool ${index} name`, TOOL_PATTERN),
      effect: validateEffect(tool.effect, `mcp tool ${index} effect`),
      input_schema_sha256: tool.input_schema_sha256,
      ...(tool.arguments_schema === undefined ? {} : {
        arguments_schema: boundedPolicySchema(tool.arguments_schema, `mcp tool ${index} arguments_schema`),
      }),
    };
  });
  assert(new Set(normalizedTools.map(({ name }) => name)).size === normalizedTools.length, 400, "invalid_guard_policy", "mcp_tool connector tool names must be unique");
  return {
    id: safeId(connector.id, "connector.id"),
    kind: "mcp_tool",
    server_id: safeId(connector.server_id, "connector.server_id"),
    tools: normalizedTools,
  };
}

function validateHttpsPath(value, name) {
  assert(typeof value === "string" && value.length >= 1 && value.length <= 2048 && value.startsWith("/"), 400, "invalid_guard_policy", `${name} must be an absolute path`);
  assert(!/[?#\r\n]/.test(value) && !value.startsWith("//"), 400, "invalid_guard_policy", `${name} must not contain an origin, query, fragment, or control characters`);
  return value;
}

function validateHttpsConnector(connector) {
  exactKeys(connector, new Set(["id", "kind", "origin", "operations"]), `connector ${connector.id ?? "?"}`);
  let origin;
  try {
    origin = new URL(connector.origin);
  } catch {
    throw new ServiceError(400, "invalid_guard_policy", "https connector origin must be an absolute HTTPS origin");
  }
  assert(origin.protocol === "https:" && !origin.username && !origin.password && connector.origin === origin.origin, 400, "invalid_guard_policy", "https connector origin must be exactly one credential-free HTTPS origin");
  assert(Array.isArray(connector.operations) && connector.operations.length >= 1 && connector.operations.length <= 100, 400, "invalid_guard_policy", "https connector operations must contain 1-100 entries");
  const operations = connector.operations.map((operation, index) => {
    exactKeys(operation, new Set(["id", "method", "path", "effect", "query_schema", "body_schema"]), `https operation ${index}`);
    assert(HTTP_METHODS.has(operation.method), 400, "invalid_guard_policy", `https operation ${index} method is not supported`);
    return {
      id: safeId(operation.id, `https operation ${index} id`),
      method: operation.method,
      path: validateHttpsPath(operation.path, `https operation ${index} path`),
      effect: validateEffect(operation.effect, `https operation ${index} effect`),
      ...(operation.query_schema === undefined ? {} : {
        query_schema: boundedPolicySchema(operation.query_schema, `https operation ${index} query_schema`),
      }),
      ...(operation.body_schema === undefined ? {} : {
        body_schema: boundedPolicySchema(operation.body_schema, `https operation ${index} body_schema`),
      }),
    };
  });
  assert(new Set(operations.map(({ id }) => id)).size === operations.length, 400, "invalid_guard_policy", "https connector operation IDs must be unique");
  return { id: safeId(connector.id, "connector.id"), kind: "https", origin: origin.origin, operations };
}

function validateEvmConnector(connector) {
  exactKeys(connector, new Set([
    "id",
    "kind",
    "chain_id",
    "from",
    "allowed_native_recipients",
    "allowed_erc20_tokens",
    "allowed_erc20_recipients",
    "allowed_approval_spenders",
    "max_native_value_atomic",
    "max_erc20_transfer_atomic",
    "max_erc20_approval_atomic",
    "max_gas_limit",
    "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic",
    "max_total_fee_atomic",
    "fee_period_seconds",
    "max_fee_period_atomic",
    "spend_period_seconds",
    "max_period_atomic",
    "require_simulation",
    "asset_id",
  ]), `connector ${connector.id ?? "?"}`);
  assert(Number.isSafeInteger(connector.chain_id) && connector.chain_id > 0, 400, "invalid_guard_policy", "evm_transaction connector chain_id must be a positive safe integer");
  assert(Number.isSafeInteger(connector.spend_period_seconds) && connector.spend_period_seconds >= 60 && connector.spend_period_seconds <= 31_536_000, 400, "invalid_guard_policy", "evm_transaction connector spend_period_seconds must be 60-31536000");
  assert(Number.isSafeInteger(connector.fee_period_seconds) && connector.fee_period_seconds >= 60 && connector.fee_period_seconds <= 31_536_000, 400, "invalid_guard_policy", "evm_transaction connector fee_period_seconds must be 60-31536000");
  assert(connector.require_simulation === true, 400, "invalid_guard_policy", "evm_transaction connector require_simulation must be true");
  const maxNative = atomic(connector.max_native_value_atomic, "max_native_value_atomic");
  const maxTransfer = atomic(connector.max_erc20_transfer_atomic, "max_erc20_transfer_atomic");
  const maxApproval = atomic(connector.max_erc20_approval_atomic, "max_erc20_approval_atomic");
  const maxGasLimit = atomic(connector.max_gas_limit, "max_gas_limit");
  const maxFeePerGas = atomic(connector.max_fee_per_gas_atomic, "max_fee_per_gas_atomic");
  const maxPriorityFeePerGas = atomic(connector.max_priority_fee_per_gas_atomic, "max_priority_fee_per_gas_atomic");
  const maxTotalFee = atomic(connector.max_total_fee_atomic, "max_total_fee_atomic");
  const maxFeePeriod = atomic(connector.max_fee_period_atomic, "max_fee_period_atomic");
  const maxPeriod = atomic(connector.max_period_atomic, "max_period_atomic");
  assert(BigInt(maxGasLimit) > 0n, 400, "invalid_guard_policy", "max_gas_limit must be greater than zero");
  assert(BigInt(maxFeePerGas) > 0n, 400, "invalid_guard_policy", "max_fee_per_gas_atomic must be greater than zero");
  assert(BigInt(maxPriorityFeePerGas) <= BigInt(maxFeePerGas), 400, "invalid_guard_policy", "max_priority_fee_per_gas_atomic must not exceed max_fee_per_gas_atomic");
  assert(BigInt(maxTotalFee) > 0n, 400, "invalid_guard_policy", "max_total_fee_atomic must be greater than zero");
  assert(BigInt(maxFeePeriod) >= BigInt(maxTotalFee), 400, "invalid_guard_policy", "max_fee_period_atomic must be at least max_total_fee_atomic");
  assert([maxNative, maxTransfer, maxApproval].every((value) => BigInt(value) <= BigInt(maxPeriod)), 400, "invalid_guard_policy", "max_period_atomic must be at least every per-transaction cap");
  const nativeRecipients = stringArray(connector.allowed_native_recipients, "allowed_native_recipients", address);
  const erc20Tokens = stringArray(connector.allowed_erc20_tokens, "allowed_erc20_tokens", address);
  const erc20Recipients = stringArray(connector.allowed_erc20_recipients, "allowed_erc20_recipients", address);
  const approvalSpenders = stringArray(connector.allowed_approval_spenders, "allowed_approval_spenders", address);
  const nativeOnly = nativeRecipients.length > 0;
  const tokenOnly = nativeRecipients.length === 0 && erc20Tokens.length === 1 && (erc20Recipients.length > 0 || approvalSpenders.length > 0);
  assert(nativeOnly || tokenOnly, 400, "invalid_guard_policy", "evm_transaction connector must authorize exactly one native or ERC-20 asset domain");
  if (nativeOnly) {
    assert(erc20Tokens.length === 0 && erc20Recipients.length === 0 && approvalSpenders.length === 0, 400, "invalid_guard_policy", "native evm_transaction connector must not authorize ERC-20 tokens, recipients, or spenders");
    assert(BigInt(maxTransfer) === 0n && BigInt(maxApproval) === 0n, 400, "invalid_guard_policy", "native evm_transaction connector ERC-20 caps must be zero");
  } else {
    assert(BigInt(maxNative) === 0n, 400, "invalid_guard_policy", "ERC-20 evm_transaction connector native cap must be zero");
  }
  const assetId = nativeOnly ? `native:eip155:${connector.chain_id}` : erc20Tokens[0];
  if (connector.asset_id !== undefined) {
    assert(connector.asset_id === assetId, 400, "invalid_guard_policy", "evm_transaction connector asset_id does not match its single asset domain");
  }
  return {
    id: safeId(connector.id, "connector.id"),
    kind: "evm_transaction",
    chain_id: connector.chain_id,
    from: address(connector.from, "connector.from"),
    allowed_native_recipients: nativeRecipients,
    allowed_erc20_tokens: erc20Tokens,
    allowed_erc20_recipients: erc20Recipients,
    allowed_approval_spenders: approvalSpenders,
    max_native_value_atomic: maxNative,
    max_erc20_transfer_atomic: maxTransfer,
    max_erc20_approval_atomic: maxApproval,
    max_gas_limit: maxGasLimit,
    max_fee_per_gas_atomic: maxFeePerGas,
    max_priority_fee_per_gas_atomic: maxPriorityFeePerGas,
    max_total_fee_atomic: maxTotalFee,
    fee_period_seconds: connector.fee_period_seconds,
    max_fee_period_atomic: maxFeePeriod,
    spend_period_seconds: connector.spend_period_seconds,
    max_period_atomic: maxPeriod,
    require_simulation: connector.require_simulation,
    asset_id: assetId,
  };
}

function validateConnector(connector) {
  assert(connector && typeof connector === "object" && !Array.isArray(connector), 400, "invalid_guard_policy", "Each connector must be an object");
  if (connector.kind === "mcp_tool") return validateMcpConnector(connector);
  if (connector.kind === "https") return validateHttpsConnector(connector);
  if (connector.kind === "evm_transaction") return validateEvmConnector(connector);
  throw new ServiceError(400, "invalid_guard_policy", "connector.kind must be mcp_tool, https, or evm_transaction");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function validatePolicyBody(policy) {
  exactKeys(policy, new Set(["schema", "policy_id", "version", "operator_wallet", "audience", "issued_at", "expires_at", "connectors"]), "guard policy");
  assert(policy.schema === GUARD_POLICY_SCHEMA, 400, "invalid_guard_policy", `policy.schema must be ${GUARD_POLICY_SCHEMA}`);
  assert(Number.isSafeInteger(policy.version) && policy.version >= 1, 400, "invalid_guard_policy", "policy.version must be a positive safe integer");
  let audience;
  try {
    audience = new URL(policy.audience);
  } catch {
    throw new ServiceError(400, "invalid_guard_policy", "policy.audience must be an absolute HTTPS origin");
  }
  assert(audience.protocol === "https:" && policy.audience === audience.origin, 400, "invalid_guard_policy", "policy.audience must be exactly one HTTPS origin");
  const issuedAt = canonicalDate(policy.issued_at, "policy.issued_at");
  const expiresAt = canonicalDate(policy.expires_at, "policy.expires_at");
  assert(Date.parse(expiresAt) > Date.parse(issuedAt), 400, "invalid_guard_policy", "policy.expires_at must be after policy.issued_at");
  assert(Array.isArray(policy.connectors) && policy.connectors.length >= 1 && policy.connectors.length <= 64, 400, "invalid_guard_policy", "policy.connectors must contain 1-64 entries");
  const connectors = policy.connectors.map(validateConnector);
  assert(new Set(connectors.map(({ id }) => id)).size === connectors.length, 400, "invalid_guard_policy", "connector IDs must be unique");
  const feeDomains = new Map();
  for (const connector of connectors.filter(({ kind }) => kind === "evm_transaction")) {
    const domain = `native:eip155:${connector.chain_id}`;
    const cap = `${connector.fee_period_seconds}:${connector.max_fee_period_atomic}`;
    const existing = feeDomains.get(domain);
    assert(existing === undefined || existing === cap, 400, "invalid_guard_policy", `All EVM connectors in ${domain} must use the same fee period and cap`);
    feeDomains.set(domain, cap);
  }
  return {
    schema: GUARD_POLICY_SCHEMA,
    policy_id: safeId(policy.policy_id, "policy.policy_id"),
    version: policy.version,
    operator_wallet: address(policy.operator_wallet, "policy.operator_wallet"),
    audience: audience.origin,
    issued_at: issuedAt,
    expires_at: expiresAt,
    connectors,
  };
}

function withoutSignature(policy) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return policy;
  const { signature: _signature, ...body } = policy;
  return body;
}

export function normalizeGuardPolicy(policy) {
  const normalized = validatePolicyBody(withoutSignature(policy));
  return deepFreeze(JSON.parse(canonicalize(normalized)));
}

export function hashGuardPolicy(policy) {
  return sha256(canonicalize(normalizeGuardPolicy(policy)));
}

export function guardPolicySigningMessage(policy) {
  const normalized = normalizeGuardPolicy(policy);
  return `${GUARD_POLICY_SIGNING_DOMAIN}\n${canonicalize(normalized)}`;
}

export function validateSignedGuardPolicy(policy) {
  exactKeys(policy, new Set(["schema", "policy_id", "version", "operator_wallet", "audience", "issued_at", "expires_at", "connectors", "signature"]), "signed guard policy");
  assert(typeof policy.signature === "string" && policy.signature.length <= 8194 && HEX_SIGNATURE_PATTERN.test(policy.signature), 400, "invalid_guard_policy_signature", "policy.signature must be a bounded hex EIP-191 signature");
  const normalized = normalizeGuardPolicy(policy);
  return deepFreeze({ ...normalized, signature: policy.signature });
}

export async function verifyGuardPolicy(policy, { verifyWalletMessage } = {}) {
  assert(typeof verifyWalletMessage === "function", 500, "guard_policy_verifier_missing", "verifyWalletMessage must be configured");
  const normalized = validateSignedGuardPolicy(policy);
  const signingMessage = guardPolicySigningMessage(normalized);
  let valid;
  try {
    valid = await verifyWalletMessage({
      wallet: normalized.operator_wallet,
      message: signingMessage,
      signature: normalized.signature,
    });
  } catch (cause) {
    throw new ServiceError(503, "guard_policy_verification_unavailable", "Unable to verify operator policy signature", { cause: cause.message });
  }
  assert(valid, 401, "invalid_guard_policy_signature", "Guard policy signature does not match the operator wallet");
  return deepFreeze({
    policy: normalized,
    policy_sha256: hashGuardPolicy(normalized),
    signing_message: signingMessage,
  });
}

function exactInstallationKeys(value, allowed, name) {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, "invalid_guard_installation", `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, "invalid_guard_installation", `${name} contains unsupported fields`, { fields: extras.sort() });
}

function installationDate(value, name) {
  assert(typeof value === "string", 400, "invalid_guard_installation", `${name} must be an ISO date-time`);
  const parsed = Date.parse(value);
  assert(Number.isFinite(parsed) && new Date(parsed).toISOString() === value, 400, "invalid_guard_installation", `${name} must be a canonical ISO date-time`);
  return value;
}

function normalizeInstallationPublicJwk(publicKeyJwk) {
  exactInstallationKeys(publicKeyJwk, new Set(["kty", "crv", "x"]), "public_key_jwk");
  assert(
    publicKeyJwk.kty === "OKP" &&
      publicKeyJwk.crv === "Ed25519" &&
      typeof publicKeyJwk.x === "string" &&
      /^[A-Za-z0-9_-]{43}$/.test(publicKeyJwk.x),
    400,
    "invalid_guard_installation",
    "public_key_jwk must be an Ed25519 public-only JWK",
  );
  const decoded = Buffer.from(publicKeyJwk.x, "base64url");
  assert(
    decoded.byteLength === 32 && decoded.toString("base64url") === publicKeyJwk.x,
    400,
    "invalid_guard_installation",
    "public_key_jwk.x must be a canonical 32-byte base64url value",
  );
  return { crv: "Ed25519", kty: "OKP", x: publicKeyJwk.x };
}

export function guardInstallationId(publicKeyJwk) {
  const normalized = normalizeInstallationPublicJwk(publicKeyJwk);
  const fingerprint = createHash("sha256").update(Buffer.from(canonicalize(normalized), "utf8")).digest("base64url");
  return `gki_${fingerprint}`;
}

function normalizeInstallationBody(binding) {
  exactInstallationKeys(binding, new Set(["schema", "installation_id", "operator_wallet", "policy_sha256", "public_key_jwk", "issued_at", "expires_at"]), "guard installation");
  assert(binding.schema === GUARD_INSTALLATION_SCHEMA, 400, "invalid_guard_installation", `installation.schema must be ${GUARD_INSTALLATION_SCHEMA}`);
  assert(typeof binding.installation_id === "string" && INSTALLATION_ID_PATTERN.test(binding.installation_id), 400, "invalid_guard_installation", "installation_id must be a GoldKey installation-key fingerprint");
  assert(typeof binding.operator_wallet === "string" && isAddress(binding.operator_wallet), 400, "invalid_guard_installation", "operator_wallet must be an EVM address");
  assert(typeof binding.policy_sha256 === "string" && SHA256_PATTERN.test(binding.policy_sha256), 400, "invalid_guard_installation", "policy_sha256 must be a lowercase SHA-256 digest");
  const publicKeyJwk = normalizeInstallationPublicJwk(binding.public_key_jwk);
  assert(binding.installation_id === guardInstallationId(publicKeyJwk), 400, "invalid_guard_installation", "installation_id does not match public_key_jwk");
  const issuedAt = installationDate(binding.issued_at, "issued_at");
  const expiresAt = installationDate(binding.expires_at, "expires_at");
  assert(Date.parse(expiresAt) > Date.parse(issuedAt), 400, "invalid_guard_installation", "expires_at must be after issued_at");
  return deepFreeze({
    schema: GUARD_INSTALLATION_SCHEMA,
    installation_id: binding.installation_id,
    operator_wallet: getAddress(binding.operator_wallet),
    policy_sha256: binding.policy_sha256,
    public_key_jwk: publicKeyJwk,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
}

function withoutInstallationSignatures(binding) {
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) return binding;
  const { signature: _signature, key_proof: _keyProof, ...body } = binding;
  return body;
}

export function normalizeGuardInstallation(binding) {
  return normalizeInstallationBody(withoutInstallationSignatures(binding));
}

export function hashGuardInstallation(binding) {
  return sha256(canonicalize(normalizeGuardInstallation(binding)));
}

export function guardInstallationSigningMessage(binding) {
  return `${GUARD_INSTALLATION_SIGNING_DOMAIN}\n${canonicalize(normalizeGuardInstallation(binding))}`;
}

export function guardInstallationKeyProofMessage(binding) {
  return `${GUARD_INSTALLATION_KEY_PROOF_DOMAIN}\n${canonicalize(normalizeGuardInstallation(binding))}`;
}

export function validateSignedGuardInstallation(binding) {
  exactInstallationKeys(binding, new Set(["schema", "installation_id", "operator_wallet", "policy_sha256", "public_key_jwk", "issued_at", "expires_at", "signature", "key_proof"]), "signed guard installation");
  assert(typeof binding.signature === "string" && binding.signature.length <= 8194 && HEX_SIGNATURE_PATTERN.test(binding.signature), 400, "invalid_guard_installation_signature", "installation.signature must be a bounded hex EIP-191 signature");
  assert(typeof binding.key_proof === "string" && ED25519_SIGNATURE_PATTERN.test(binding.key_proof), 400, "invalid_guard_installation_key_proof", "installation.key_proof must be a canonical 64-byte Ed25519 signature");
  const proofBytes = Buffer.from(binding.key_proof, "base64url");
  assert(proofBytes.byteLength === 64 && proofBytes.toString("base64url") === binding.key_proof, 400, "invalid_guard_installation_key_proof", "installation.key_proof must be canonical base64url");
  return deepFreeze({ ...normalizeGuardInstallation(binding), signature: binding.signature, key_proof: binding.key_proof });
}

export async function verifyGuardInstallation(binding, { verifyWalletMessage } = {}) {
  assert(typeof verifyWalletMessage === "function", 500, "guard_installation_verifier_missing", "verifyWalletMessage must be configured");
  const normalized = validateSignedGuardInstallation(binding);
  const signingMessage = guardInstallationSigningMessage(normalized);
  let valid;
  try {
    valid = await verifyWalletMessage({ wallet: normalized.operator_wallet, message: signingMessage, signature: normalized.signature });
  } catch (cause) {
    throw new ServiceError(503, "guard_installation_verification_unavailable", "Unable to verify operator installation signature", { cause: cause.message });
  }
  assert(valid, 401, "invalid_guard_installation_signature", "Guard installation signature does not match the operator wallet");
  let keyProofValid = false;
  try {
    keyProofValid = verifyBytes(
      null,
      Buffer.from(guardInstallationKeyProofMessage(normalized), "utf8"),
      createPublicKey({ key: normalized.public_key_jwk, format: "jwk" }),
      Buffer.from(normalized.key_proof, "base64url"),
    );
  } catch {
    keyProofValid = false;
  }
  assert(keyProofValid, 401, "invalid_guard_installation_key_proof", "Guard installation key proof does not match public_key_jwk");
  return deepFreeze({
    installation: normalized,
    installation_sha256: hashGuardInstallation(normalized),
    signing_message: signingMessage,
  });
}

function revocationKeys(value, allowed, name) {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, "invalid_guard_revocation", `${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  assert(extras.length === 0, 400, "invalid_guard_revocation", `${name} contains unsupported fields`, { fields: extras.sort() });
}

function withoutRevocationSignature(revocation) {
  if (!revocation || typeof revocation !== "object" || Array.isArray(revocation)) return revocation;
  const { signature: _signature, ...body } = revocation;
  return body;
}

export function normalizeGuardRevocation(revocation) {
  const body = withoutRevocationSignature(revocation);
  revocationKeys(body, new Set(["schema", "target_kind", "target_id", "operator_wallet", "audience", "issued_at"]), "guard revocation");
  assert(body.schema === GUARD_REVOCATION_SCHEMA, 400, "invalid_guard_revocation", `revocation.schema must be ${GUARD_REVOCATION_SCHEMA}`);
  assert(body.target_kind === "policy" || body.target_kind === "installation", 400, "invalid_guard_revocation", "target_kind must be policy or installation");
  if (body.target_kind === "policy") {
    assert(typeof body.target_id === "string" && SHA256_PATTERN.test(body.target_id), 400, "invalid_guard_revocation", "Policy target_id must be its lowercase SHA-256 hash");
  } else {
    assert(typeof body.target_id === "string" && ID_PATTERN.test(body.target_id), 400, "invalid_guard_revocation", "Installation target_id is invalid");
  }
  let audience;
  try {
    audience = new URL(body.audience);
  } catch {
    throw new ServiceError(400, "invalid_guard_revocation", "revocation.audience must be an absolute HTTPS origin");
  }
  assert(audience.protocol === "https:" && body.audience === audience.origin, 400, "invalid_guard_revocation", "revocation.audience must be exactly one HTTPS origin");
  return deepFreeze({
    schema: GUARD_REVOCATION_SCHEMA,
    target_kind: body.target_kind,
    target_id: body.target_id,
    operator_wallet: address(body.operator_wallet, "revocation.operator_wallet"),
    audience: audience.origin,
    issued_at: canonicalDate(body.issued_at, "revocation.issued_at"),
  });
}

export function guardRevocationSigningMessage(revocation) {
  return `${GUARD_REVOCATION_SIGNING_DOMAIN}\n${canonicalize(normalizeGuardRevocation(revocation))}`;
}

export function validateSignedGuardRevocation(revocation) {
  revocationKeys(revocation, new Set(["schema", "target_kind", "target_id", "operator_wallet", "audience", "issued_at", "signature"]), "signed guard revocation");
  assert(typeof revocation.signature === "string" && revocation.signature.length <= 8194 && HEX_SIGNATURE_PATTERN.test(revocation.signature), 400, "invalid_guard_revocation_signature", "revocation.signature must be a bounded hex EIP-191 signature");
  return deepFreeze({ ...normalizeGuardRevocation(revocation), signature: revocation.signature });
}

export async function verifyGuardRevocation(revocation, { verifyWalletMessage } = {}) {
  assert(typeof verifyWalletMessage === "function", 500, "guard_revocation_verifier_missing", "verifyWalletMessage must be configured");
  const normalized = validateSignedGuardRevocation(revocation);
  const signingMessage = guardRevocationSigningMessage(normalized);
  let valid;
  try {
    valid = await verifyWalletMessage({
      wallet: normalized.operator_wallet,
      message: signingMessage,
      signature: normalized.signature,
    });
  } catch (cause) {
    throw new ServiceError(503, "guard_revocation_verification_unavailable", "Unable to verify operator revocation signature", { cause: cause.message });
  }
  assert(valid, 401, "invalid_guard_revocation_signature", "Guard revocation signature does not match the operator wallet");
  return deepFreeze({ revocation: normalized, signing_message: signingMessage });
}
