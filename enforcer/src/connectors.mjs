import { getAddress, isAddress } from "viem";
import { assertSafeIdentifier, deepFreeze, isCanonicalSha256 } from "./canonical.mjs";
import { InvalidInputError } from "./errors.mjs";

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const EFFECTS = new Set(["read", "write", "network", "payment", "execute"]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const ATOMIC = /^(0|[1-9]\d{0,77})$/;
const MAX_UINT256 = (1n << 256n) - 1n;

function exactKeys(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError(`${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
}

function effect(value, name) {
  if (!EFFECTS.has(value)) throw new InvalidInputError(`${name} must be a supported effect`);
  return value;
}

function positiveAtomic(value, name) {
  if (typeof value !== "string" || !ATOMIC.test(value) || BigInt(value) > MAX_UINT256 || BigInt(value) === 0n) {
    throw new InvalidInputError(`${name} must be a positive canonical uint256 atomic-unit string`);
  }
  return value;
}

function safePath(value, name) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048 || !value.startsWith("/") || value.startsWith("//") || /[?#\\\r\n\0]/.test(value)) {
    throw new InvalidInputError(`${name} must be one bounded absolute URL path`);
  }
  const probe = new URL(value, "https://goldkey.invalid");
  if (probe.pathname !== value) throw new InvalidInputError(`${name} must not contain dot segments or URL-normalizing syntax`);
  return value;
}

function normalizeTrustedHeaders(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError("trusted_headers must be an object");
  const headers = {};
  for (const [rawName, rawValue] of Object.entries(value)) {
    const name = rawName.toLowerCase();
    if (!HEADER_NAME.test(name) || typeof rawValue !== "string" || rawValue.length > 8192 || /[\r\n\0]/.test(rawValue)) {
      throw new InvalidInputError("trusted_headers contains an invalid header");
    }
    if (["host", "content-length", "connection", "transfer-encoding", "upgrade", "te", "trailer", "proxy-connection"].includes(name)) {
      throw new InvalidInputError(`trusted_headers must not set ${name}`);
    }
    headers[name] = rawValue;
  }
  return Object.freeze(headers);
}

function normalizeMcpConnector(connector) {
  exactKeys(connector, new Set(["id", "kind", "server_id", "tools", "invokeTool"]), `connector ${connector.id ?? "?"}`);
  if (typeof connector.invokeTool !== "function") throw new InvalidInputError("MCP connector requires an operator-bound invokeTool callback");
  if (!Array.isArray(connector.tools) || connector.tools.length < 1 || connector.tools.length > 100) throw new InvalidInputError("MCP connector requires 1-100 tools");
  const tools = connector.tools.map((tool, index) => {
    exactKeys(tool, new Set(["name", "effect", "input_schema_sha256"]), `MCP tool ${index}`);
    if (!isCanonicalSha256(tool.input_schema_sha256)) throw new InvalidInputError(`MCP tool ${index} schema hash is invalid`);
    return Object.freeze({
      name: assertSafeIdentifier(tool.name, `MCP tool ${index} name`, { max: 256 }),
      effect: effect(tool.effect, `MCP tool ${index} effect`),
      input_schema_sha256: tool.input_schema_sha256,
    });
  });
  if (new Set(tools.map(({ name }) => name)).size !== tools.length) throw new InvalidInputError("MCP tool names must be unique");
  return Object.freeze({
    id: assertSafeIdentifier(connector.id, "connector.id"),
    kind: "mcp_tool",
    server_id: assertSafeIdentifier(connector.server_id, "connector.server_id"),
    tools: Object.freeze(tools),
    invokeTool: connector.invokeTool,
  });
}

function normalizeHttpsConnector(connector) {
  exactKeys(connector, new Set(["id", "kind", "origin", "operations", "trusted_headers"]), `connector ${connector.id ?? "?"}`);
  let origin;
  try {
    origin = new URL(connector.origin);
  } catch {
    throw new InvalidInputError("HTTPS connector origin must be an absolute URL");
  }
  if (origin.protocol !== "https:" || origin.username || origin.password || connector.origin !== origin.origin) {
    throw new InvalidInputError("HTTPS connector origin must be exactly one credential-free HTTPS origin");
  }
  if (!Array.isArray(connector.operations) || connector.operations.length < 1 || connector.operations.length > 100) throw new InvalidInputError("HTTPS connector requires 1-100 operations");
  const operations = connector.operations.map((operation, index) => {
    exactKeys(operation, new Set(["id", "method", "path", "effect"]), `HTTPS operation ${index}`);
    if (!METHODS.has(operation.method)) throw new InvalidInputError(`HTTPS operation ${index} method is invalid`);
    return Object.freeze({
      id: assertSafeIdentifier(operation.id, `HTTPS operation ${index} id`),
      method: operation.method,
      path: safePath(operation.path, `HTTPS operation ${index} path`),
      effect: effect(operation.effect, `HTTPS operation ${index} effect`),
    });
  });
  if (new Set(operations.map(({ id }) => id)).size !== operations.length) throw new InvalidInputError("HTTPS operation IDs must be unique");
  return Object.freeze({
    id: assertSafeIdentifier(connector.id, "connector.id"),
    kind: "https",
    origin: origin.origin,
    operations: Object.freeze(operations),
    trusted_headers: normalizeTrustedHeaders(connector.trusted_headers),
  });
}

function normalizeEvmConnector(connector) {
  exactKeys(connector, new Set([
    "id",
    "kind",
    "chain_id",
    "from",
    "max_estimated_network_fee_atomic",
    "max_wallet_native_exposure_atomic",
    "recheckFeeExposure",
    "signAndBroadcast",
  ]), `connector ${connector.id ?? "?"}`);
  if (!Number.isSafeInteger(connector.chain_id) || connector.chain_id < 1) throw new InvalidInputError("EVM connector chain_id must be a positive safe integer");
  if (!isAddress(connector.from)) throw new InvalidInputError("EVM connector from must be an EVM address");
  const maxEstimatedNetworkFee = positiveAtomic(connector.max_estimated_network_fee_atomic, "EVM connector max_estimated_network_fee_atomic");
  const maxWalletNativeExposure = positiveAtomic(connector.max_wallet_native_exposure_atomic, "EVM connector max_wallet_native_exposure_atomic");
  if (BigInt(maxEstimatedNetworkFee) > BigInt(maxWalletNativeExposure)) {
    throw new InvalidInputError("EVM connector estimated network-fee cap must not exceed its wallet-native exposure cap");
  }
  if (typeof connector.recheckFeeExposure !== "function") throw new InvalidInputError("EVM connector requires an operator-bound recheckFeeExposure callback");
  if (typeof connector.signAndBroadcast !== "function") throw new InvalidInputError("EVM connector requires an operator-bound signAndBroadcast callback");
  return Object.freeze({
    id: assertSafeIdentifier(connector.id, "connector.id"),
    kind: "evm_transaction",
    chain_id: connector.chain_id,
    from: getAddress(connector.from),
    max_estimated_network_fee_atomic: maxEstimatedNetworkFee,
    max_wallet_native_exposure_atomic: maxWalletNativeExposure,
    recheckFeeExposure: connector.recheckFeeExposure,
    signAndBroadcast: connector.signAndBroadcast,
  });
}

export function normalizeConnectorRegistry(connectors) {
  if (!Array.isArray(connectors) || connectors.length < 1 || connectors.length > 64) throw new InvalidInputError("connectors must contain 1-64 operator-controlled connectors");
  const normalized = connectors.map((connector) => {
    if (connector?.kind === "mcp_tool") return normalizeMcpConnector(connector);
    if (connector?.kind === "https") return normalizeHttpsConnector(connector);
    if (connector?.kind === "evm_transaction") return normalizeEvmConnector(connector);
    throw new InvalidInputError("Connector kind must be mcp_tool, https, or evm_transaction");
  });
  if (new Set(normalized.map(({ id }) => id)).size !== normalized.length) throw new InvalidInputError("Connector IDs must be unique");
  return new Map(normalized.map((connector) => [connector.id, deepFreeze(connector)]));
}
