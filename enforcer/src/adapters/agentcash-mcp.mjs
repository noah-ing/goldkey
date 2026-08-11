import { spawn as defaultSpawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  access as defaultAccess,
  lstat as defaultLstat,
  open as defaultOpen,
} from "node:fs/promises";
import path from "node:path";
import { canonicalBytes, canonicalSha256, canonicalize, deepFreeze } from "../canonical.mjs";
import { InvalidInputError, LocalStateError } from "../errors.mjs";
import { resolvePublicAddresses } from "../network.mjs";
import { hashGuardCall, normalizeGuardCall } from "../protocol.mjs";

export const AGENTCASH_ADAPTER_SCHEMA = "goldkey.agentcash-mcp-adapter.v1";
export const AGENTCASH_MCP_PROTOCOL_VERSION = "2025-06-18";
export const GOLDKEY_AGENTCASH_GUARD_ORIGIN = "https://goldkey-edge-storefront.noah-ing.workers.dev";

const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);
const BODYLESS_METHODS = new Set(["GET", "DELETE"]);
const PAYMENT_NETWORKS = new Set(["base", "solana", "tempo"]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const USD = /^(?:0|[1-9]\d{0,3})(?:\.\d{1,6})?$/;
const MAX_BODY_BYTES = 48 * 1024;
const MAX_OPERATIONS = 64;
const MAX_HEADERS = 16;
const MAX_STDERR_BYTES = 64 * 1024;
const MIN_TIMEOUT_MS = 250;
const MAX_TIMEOUT_MS = 14_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_CONFIG_BYTES = 1024 * 1024;
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "proxy-authenticate",
  "set-cookie",
  "www-authenticate",
  "x-api-key",
]);
const HOP_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
const SAFE_REQUEST_HEADERS = new Set(["accept"]);
const SAFE_RESPONSE_HEADERS = new Set([
  "cache-control",
  "content-language",
  "content-length",
  "content-type",
  "date",
  "etag",
  "expires",
  "last-modified",
  "retry-after",
  "x-request-id",
]);

const normalizedConfigs = new WeakSet();

export class AgentCashAdapterError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = "AgentCashAdapterError";
    this.code = code;
    if (details !== undefined) this.details = deepFreeze(details);
  }
}

function exactKeys(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidInputError(`${name} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new InvalidInputError(`${name} must be a plain object`);
  }
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) {
    throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
  }
}

function requiredString(value, name, { max = 2048, pattern } = {}) {
  if (typeof value !== "string" || value.length < 1 || value.length > max || value.includes("\0")) {
    throw new InvalidInputError(`${name} must be a bounded non-empty string`);
  }
  if (pattern && !pattern.test(value)) throw new InvalidInputError(`${name} has an invalid format`);
  return value;
}

function safeIdentifier(value, name, max = 128) {
  if (typeof value !== "string" || value.length < 1 || value.length > max || !/^[A-Za-z0-9._:-]+$/.test(value)) {
    throw new InvalidInputError(`${name} must use only letters, digits, dot, underscore, colon, or hyphen`);
  }
  return value;
}

function normalizeOrigin(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new InvalidInputError(`${name} must be an absolute HTTPS origin`);
  }
  if (url.protocol !== "https:" || url.username || url.password || value !== url.origin) {
    throw new InvalidInputError(`${name} must be exactly one credential-free HTTPS origin`);
  }
  return url.origin;
}

function normalizeTargetUrl(value, guardOrigin, name) {
  requiredString(value, name, { max: 2048 });
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new InvalidInputError(`${name} must be an absolute HTTPS URL`);
  }
  if (
    url.protocol !== "https:"
    || url.username
    || url.password
    || url.hash
    || url.search
    || url.href !== value
  ) throw new InvalidInputError(`${name} must be one canonical credential-free HTTPS URL without a query or fragment`);
  if (url.origin === guardOrigin) {
    throw new InvalidInputError(`${name} must not target the GoldKey Guard origin; Guard authorization and the upstream x402 purchase are separate payments`);
  }
  return url.href;
}

function normalizeHeaders(value = {}) {
  exactKeys(value, new Set(Object.keys(value)), "operation.headers");
  const entries = Object.entries(value);
  if (entries.length > MAX_HEADERS) throw new InvalidInputError(`operation.headers must contain at most ${MAX_HEADERS} entries`);
  const headers = {};
  for (const [rawName, rawValue] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    const name = rawName.toLowerCase();
    if (
      !HEADER_NAME.test(rawName)
      || typeof rawValue !== "string"
      || rawValue.length > 2048
      || rawValue !== rawValue.trim()
      || /[\r\n\0]/.test(rawValue)
    ) {
      throw new InvalidInputError("operation.headers contains an invalid header");
    }
    if (Object.hasOwn(headers, name)) throw new InvalidInputError(`operation.headers repeats ${name}`);
    if (
      HOP_HEADERS.has(name)
      || SENSITIVE_HEADERS.has(name)
      || name.startsWith("x-payment")
      || name.startsWith("payment-")
    ) throw new InvalidInputError(`operation.headers must not set sensitive or transport-controlled header ${name}`);
    if (name === "content-type") throw new InvalidInputError("operation.headers must not set content-type; JSON body operations set it exactly");
    if (!SAFE_REQUEST_HEADERS.has(name)) throw new InvalidInputError(`operation.headers may set only the non-secret ${[...SAFE_REQUEST_HEADERS].join(", ")} header`);
    if (name === "accept" && rawValue !== "application/json") {
      throw new InvalidInputError("operation.headers.accept must be exactly application/json");
    }
    headers[name] = rawValue;
  }
  return Object.freeze(headers);
}

function inputSchema({ method, url, paymentNetwork, maxAmountUsd, headers }) {
  const binding = {
    adapter_schema: AGENTCASH_ADAPTER_SCHEMA,
    upstream_url: url,
    method,
    payment_protocol: "x402",
    payment_network: paymentNetwork,
    max_amount_usd: maxAmountUsd,
    headers,
  };
  if (BODY_METHODS.has(method)) {
    return deepFreeze({
      type: "object",
      additionalProperties: false,
      "x-goldkey-agentcash-binding": binding,
      properties: {
        body: {
          type: "object",
          description: "JSON object sent to the operator-pinned upstream endpoint.",
        },
      },
      required: ["body"],
    });
  }
  return deepFreeze({
    type: "object",
    additionalProperties: false,
    "x-goldkey-agentcash-binding": binding,
    properties: {},
  });
}

function normalizeOperation(value, index, guardOrigin) {
  exactKeys(value, new Set(["name", "url", "method", "payment_network", "max_amount_usd", "headers"]), `operation ${index}`);
  const name = safeIdentifier(value.name, `operation ${index}.name`, 256);
  const method = requiredString(value.method, `operation ${index}.method`, { max: 8 });
  if (!BODY_METHODS.has(method) && !BODYLESS_METHODS.has(method)) {
    throw new InvalidInputError(`operation ${index}.method must be GET, POST, PUT, PATCH, or DELETE`);
  }
  if (!PAYMENT_NETWORKS.has(value.payment_network)) {
    throw new InvalidInputError(`operation ${index}.payment_network must be base, solana, or tempo`);
  }
  const maximum = requiredString(value.max_amount_usd, `operation ${index}.max_amount_usd`, { max: 16, pattern: USD });
  const numericMaximum = Number(maximum);
  if (!Number.isFinite(numericMaximum) || numericMaximum <= 0 || numericMaximum > 1000) {
    throw new InvalidInputError(`operation ${index}.max_amount_usd must be greater than zero and no more than 1000 USD`);
  }
  const url = normalizeTargetUrl(value.url, guardOrigin, `operation ${index}.url`);
  const headers = normalizeHeaders(value.headers);
  const schema = inputSchema({
    method,
    url,
    paymentNetwork: value.payment_network,
    maxAmountUsd: maximum,
    headers,
  });
  return deepFreeze({
    name,
    url,
    method,
    payment_network: value.payment_network,
    max_amount_usd: maximum,
    headers,
    input_schema: schema,
    input_schema_sha256: canonicalSha256(schema),
  });
}

export function normalizeAgentCashAdapterConfig(value) {
  if (normalizedConfigs.has(value)) return value;
  exactKeys(value, new Set([
    "schema",
    "connector_id",
    "server_id",
    "guard_origin",
    "node_command",
    "agentcash_command",
    "agentcash_version",
    "credential_mode",
    "working_directory",
    "request_timeout_ms",
    "max_response_bytes",
    "operations",
  ]), "AgentCash adapter config");
  if (value.schema !== AGENTCASH_ADAPTER_SCHEMA) {
    throw new InvalidInputError(`AgentCash adapter config.schema must be ${AGENTCASH_ADAPTER_SCHEMA}`);
  }
  const nodeCommand = requiredString(value.node_command, "node_command", { max: 1024 });
  if (!path.isAbsolute(nodeCommand) || /[\r\n]/.test(nodeCommand)) {
    throw new InvalidInputError("node_command must be an absolute operator-controlled Node.js executable path");
  }
  const command = requiredString(value.agentcash_command, "agentcash_command", { max: 1024 });
  if (!path.isAbsolute(command) || /[\r\n]/.test(command)) {
    throw new InvalidInputError("agentcash_command must be an absolute operator-controlled executable path");
  }
  const workingDirectory = requiredString(value.working_directory, "working_directory", { max: 1024 });
  if (!path.isAbsolute(workingDirectory) || /[\r\n]/.test(workingDirectory)) {
    throw new InvalidInputError("working_directory must be an absolute operator-controlled path");
  }
  const version = requiredString(value.agentcash_version, "agentcash_version", { max: 32, pattern: SEMVER });
  if (!new Set(["wallet_files", "environment"]).has(value.credential_mode)) {
    throw new InvalidInputError("credential_mode must be wallet_files or environment");
  }
  if (!Number.isSafeInteger(value.request_timeout_ms) || value.request_timeout_ms < MIN_TIMEOUT_MS || value.request_timeout_ms > MAX_TIMEOUT_MS) {
    throw new InvalidInputError(`request_timeout_ms must be ${MIN_TIMEOUT_MS}-${MAX_TIMEOUT_MS}`);
  }
  if (!Number.isSafeInteger(value.max_response_bytes) || value.max_response_bytes < 1024 || value.max_response_bytes > MAX_RESPONSE_BYTES) {
    throw new InvalidInputError(`max_response_bytes must be 1024-${MAX_RESPONSE_BYTES}`);
  }
  const guardOrigin = normalizeOrigin(value.guard_origin, "guard_origin");
  if (guardOrigin !== GOLDKEY_AGENTCASH_GUARD_ORIGIN) {
    throw new InvalidInputError(`guard_origin must be the live GoldKey Guard origin ${GOLDKEY_AGENTCASH_GUARD_ORIGIN}`);
  }
  if (!Array.isArray(value.operations) || value.operations.length < 1 || value.operations.length > MAX_OPERATIONS) {
    throw new InvalidInputError(`operations must contain 1-${MAX_OPERATIONS} operator-controlled entries`);
  }
  const operations = value.operations.map((operation, index) => normalizeOperation(operation, index, guardOrigin));
  if (new Set(operations.map(({ name }) => name)).size !== operations.length) {
    throw new InvalidInputError("operation names must be unique");
  }
  const normalized = deepFreeze({
    schema: AGENTCASH_ADAPTER_SCHEMA,
    connector_id: safeIdentifier(value.connector_id, "connector_id"),
    server_id: safeIdentifier(value.server_id, "server_id"),
    guard_origin: guardOrigin,
    node_command: nodeCommand,
    agentcash_command: command,
    agentcash_version: version,
    credential_mode: value.credential_mode,
    working_directory: workingDirectory,
    request_timeout_ms: value.request_timeout_ms,
    max_response_bytes: value.max_response_bytes,
    operations,
  });
  normalizedConfigs.add(normalized);
  return normalized;
}

async function readAgentCashConfigFile(filename, { lstatImpl = defaultLstat, openImpl = defaultOpen } = {}) {
  if (typeof filename !== "string" || filename.length < 1) {
    throw new InvalidInputError("An AgentCash adapter config filename is required");
  }
  const resolved = path.resolve(filename);
  const parent = path.dirname(resolved);
  let parentMetadata;
  try {
    parentMetadata = await lstatImpl(parent);
  } catch (cause) {
    throw new LocalStateError(`Unable to inspect AgentCash adapter config directory ${parent}`, { cause });
  }
  if (!parentMetadata.isDirectory() || parentMetadata.isSymbolicLink()) {
    throw new LocalStateError(`AgentCash adapter config directory ${parent} must be a non-symlink directory`);
  }
  if (process.platform !== "win32") {
    if ((parentMetadata.mode & 0o022) !== 0) {
      throw new LocalStateError(`AgentCash adapter config directory ${parent} must not be writable by group or other users`);
    }
    const effectiveUid = process.geteuid?.();
    if (effectiveUid !== undefined && parentMetadata.uid !== 0 && parentMetadata.uid !== effectiveUid) {
      throw new LocalStateError(`AgentCash adapter config directory ${parent} must be owned by root or the launcher user`);
    }
  }
  let handle;
  let bytes;
  try {
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    handle = await openImpl(resolved, fsConstants.O_RDONLY | noFollow);
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 2 || metadata.size > MAX_CONFIG_BYTES) {
      throw new LocalStateError(`AgentCash adapter config ${resolved} must be a regular 2-${MAX_CONFIG_BYTES} byte file`);
    }
    if (process.platform !== "win32") {
      if ((metadata.mode & 0o022) !== 0) throw new LocalStateError(`AgentCash adapter config ${resolved} must not be writable by group or other users`);
      const effectiveUid = process.geteuid?.();
      if (effectiveUid !== undefined && metadata.uid !== 0 && metadata.uid !== effectiveUid) {
        throw new LocalStateError(`AgentCash adapter config ${resolved} must be owned by root or the launcher user`);
      }
    }
    bytes = await handle.readFile();
    if (bytes.byteLength !== metadata.size || bytes.byteLength > MAX_CONFIG_BYTES) {
      throw new LocalStateError(`AgentCash adapter config ${resolved} changed while it was being read`);
    }
  } catch (cause) {
    if (cause instanceof LocalStateError) throw cause;
    throw new LocalStateError(`Unable to read AgentCash adapter config ${resolved}`, { cause });
  } finally {
    await handle?.close?.();
  }
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw new InvalidInputError(`AgentCash adapter config ${resolved} is not valid JSON`, { cause: cause.message });
  }
  exactKeys(document, new Set(Object.keys(document)), "AgentCash adapter config document");
  const section = Object.hasOwn(document, "agentcash") ? document.agentcash : document;
  exactKeys(section, new Set(Object.keys(section)), "agentcash config section");
  const configDirectory = path.dirname(resolved);
  const withResolvedPaths = {
    ...section,
    node_command: typeof section.node_command === "string" && !path.isAbsolute(section.node_command)
      ? path.resolve(configDirectory, section.node_command)
      : section.node_command,
    agentcash_command: typeof section.agentcash_command === "string" && !path.isAbsolute(section.agentcash_command)
      ? path.resolve(configDirectory, section.agentcash_command)
      : section.agentcash_command,
    working_directory: typeof section.working_directory === "string" && !path.isAbsolute(section.working_directory)
      ? path.resolve(configDirectory, section.working_directory)
      : section.working_directory,
  };
  return Object.freeze({
    filename: resolved,
    document: deepFreeze(document),
    agentCashConfig: normalizeAgentCashAdapterConfig(withResolvedPaths),
  });
}

/**
 * Loads either a standalone AgentCash JSON document or the `agentcash` section
 * of the same combined document that contains the shared `runtime` section.
 */
export async function loadAgentCashAdapterConfigFile(filename, options) {
  return readAgentCashConfigFile(filename, options);
}

function childEnvironment(config, environment) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new InvalidInputError("AgentCash environment must be an operator-controlled object");
  }
  const home = requiredString(environment.HOME, "AgentCash HOME", { max: 1024 });
  if (!path.isAbsolute(home)) throw new InvalidInputError("AgentCash HOME must be absolute");
  const result = {
    HOME: home,
    CI: "1",
    NO_COLOR: "1",
    FORCE_COLOR: "0",
  };
  if (config.credential_mode === "environment") {
    const evm = requiredString(environment.X402_PRIVATE_KEY, "X402_PRIVATE_KEY", { max: 66, pattern: /^0x[0-9a-fA-F]{64}$/ });
    const solana = requiredString(environment.X402_SOLANA_PRIVATE_KEY, "X402_SOLANA_PRIVATE_KEY", { max: 128, pattern: /^[1-9A-HJ-NP-Za-km-z]+$/ });
    result.X402_PRIVATE_KEY = evm;
    result.X402_SOLANA_PRIVATE_KEY = solana;
  }
  return Object.freeze(result);
}

async function assertWalletFiles(config, environment, lstatImpl) {
  if (config.credential_mode !== "wallet_files") return Object.freeze([]);
  const walletDirectory = path.join(environment.HOME, ".agentcash");
  let directoryMetadata;
  try {
    directoryMetadata = await lstatImpl(walletDirectory);
  } catch (cause) {
    throw new AgentCashAdapterError("agentcash_wallet_not_ready", "AgentCash wallet directory must exist before the adapter starts", {
      cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
    });
  }
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new AgentCashAdapterError("agentcash_wallet_not_ready", "AgentCash wallet directory must be a non-symlink directory");
  }
  if (process.platform !== "win32" && (directoryMetadata.mode & 0o022) !== 0) {
    throw new AgentCashAdapterError("agentcash_wallet_permissions", "AgentCash wallet directory must not be writable by group or other users");
  }
  if (typeof process.getuid === "function" && Number.isSafeInteger(directoryMetadata.uid) && directoryMetadata.uid !== process.getuid()) {
    throw new AgentCashAdapterError("agentcash_wallet_owner", "AgentCash wallet directory must be owned by the adapter process user");
  }
  const filenames = ["wallet.json", "solana-wallet.json"];
  const checked = [];
  for (const filename of filenames) {
    const absolute = path.join(environment.HOME, ".agentcash", filename);
    let metadata;
    try {
      metadata = await lstatImpl(absolute);
    } catch (cause) {
      throw new AgentCashAdapterError("agentcash_wallet_not_ready", `AgentCash wallet file ${filename} must exist before the adapter starts`, {
        filename,
        cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
      });
    }
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new AgentCashAdapterError("agentcash_wallet_not_ready", `AgentCash wallet file ${filename} must be a regular non-symlink file`, { filename });
    }
    if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
      throw new AgentCashAdapterError("agentcash_wallet_permissions", `AgentCash wallet file ${filename} must have mode 0600`, { filename });
    }
    if (typeof process.getuid === "function" && Number.isSafeInteger(metadata.uid) && metadata.uid !== process.getuid()) {
      throw new AgentCashAdapterError("agentcash_wallet_owner", `AgentCash wallet file ${filename} must be owned by the adapter process user`, { filename });
    }
    checked.push(filename);
  }
  return Object.freeze(checked);
}

async function assertExecutionSurface(config, { lstatImpl, accessImpl }) {
  const executableMetadata = [];
  for (const [label, filename] of [["Node.js", config.node_command], ["AgentCash", config.agentcash_command]]) {
    let metadata;
    try {
      metadata = await lstatImpl(filename);
      await accessImpl(filename, fsConstants.X_OK);
    } catch (cause) {
      throw new AgentCashAdapterError("agentcash_executable_not_ready", `Pinned ${label} command must exist and be executable`, {
        cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
      });
    }
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new AgentCashAdapterError("agentcash_executable_not_ready", `Pinned ${label} command must be a regular non-symlink executable`);
    }
    executableMetadata.push(metadata);
  }
  let workingMetadata;
  try {
    workingMetadata = await lstatImpl(config.working_directory);
  } catch (cause) {
    throw new AgentCashAdapterError("agentcash_working_directory", "AgentCash working_directory must exist before startup", {
      cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
    });
  }
  if (!workingMetadata.isDirectory() || workingMetadata.isSymbolicLink()) {
    throw new AgentCashAdapterError("agentcash_working_directory", "AgentCash working_directory must be a non-symlink directory");
  }
  if (process.platform !== "win32") {
    if (executableMetadata.some((metadata) => (metadata.mode & 0o022) !== 0) || (workingMetadata.mode & 0o022) !== 0) {
      throw new AgentCashAdapterError("agentcash_mutable_execution_surface", "AgentCash executable and working_directory must not be writable by group or other users");
    }
    const effectiveUid = process.geteuid?.();
    if (
      effectiveUid !== undefined
      && (executableMetadata.some((metadata) => metadata.uid !== 0 && metadata.uid !== effectiveUid)
        || workingMetadata.uid !== 0 && workingMetadata.uid !== effectiveUid)
    ) throw new AgentCashAdapterError("agentcash_execution_owner", "AgentCash executable and working_directory must be owned by root or the adapter user");
  }
}

function processDiagnostic(stderrBytes, stderrHash) {
  return Object.freeze({
    stderr_bytes: stderrBytes,
    stderr_sha256: stderrHash.copy().digest("hex"),
  });
}

function rpcFailure(message, details) {
  return new AgentCashAdapterError("agentcash_mcp_failed", message, details);
}

export function runAgentCashMcpRpc({
  nodeCommand,
  agentCashCommand,
  expectedVersion,
  workingDirectory,
  environment,
  method,
  params,
  signal,
  deadlineAt,
  maxResponseBytes = MAX_RESPONSE_BYTES,
  clock = () => Date.now(),
  spawnImpl = defaultSpawn,
}) {
  if (signal?.aborted) throw new AgentCashAdapterError("agentcash_deadline", "AgentCash MCP request was aborted before process start");
  const remaining = deadlineAt - clock();
  if (!Number.isSafeInteger(deadlineAt) || remaining <= 0) {
    throw new AgentCashAdapterError("agentcash_deadline", "AgentCash MCP request has no remaining deadline");
  }
  if (typeof spawnImpl !== "function") throw new InvalidInputError("spawnImpl must be a function");
  return new Promise((resolve, reject) => {
    let child;
    let settled = false;
    let stdoutBuffer = Buffer.alloc(0);
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const stderrHash = createHash("sha256");
    const pending = new Map();
    let killTimer;
    const deadlineTimer = setTimeout(() => fail(new AgentCashAdapterError("agentcash_deadline", "AgentCash MCP request exceeded its deadline")), remaining);
    deadlineTimer.unref?.();

    const terminate = () => {
      try {
        child?.kill?.("SIGTERM");
      } catch {
        // Outcome remains conservative; process diagnostics never include secrets.
      }
      killTimer = setTimeout(() => {
        try { child?.kill?.("SIGKILL"); } catch { /* best effort */ }
      }, 200);
      killTimer.unref?.();
    };

    const cleanup = () => {
      clearTimeout(deadlineTimer);
      signal?.removeEventListener("abort", onAbort);
    };

    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      terminate();
      for (const waiter of pending.values()) waiter.reject(error);
      pending.clear();
      reject(error);
    };

    const succeed = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      terminate();
      pending.clear();
      resolve(value);
    };

    const onAbort = () => fail(new AgentCashAdapterError("agentcash_deadline", "AgentCash MCP request was aborted; payment outcome may be ambiguous"));
    signal?.addEventListener("abort", onAbort, { once: true });

    const send = (message) => {
      if (settled) throw rpcFailure("AgentCash MCP process is no longer available");
      const bytes = Buffer.from(JSON.stringify(message) + "\n", "utf8");
      child.stdin.write(bytes);
    };

    const request = (id, requestMethod, requestParams = {}) => new Promise((resolveRequest, rejectRequest) => {
      pending.set(String(id), { resolve: resolveRequest, reject: rejectRequest });
      try {
        send({ jsonrpc: "2.0", id, method: requestMethod, params: requestParams });
      } catch (error) {
        pending.delete(String(id));
        rejectRequest(error);
      }
    });

    const acceptLine = (line) => {
      let message;
      try {
        message = JSON.parse(line.toString("utf8"));
      } catch {
        fail(rpcFailure("AgentCash MCP emitted non-JSON stdout", processDiagnostic(stderrBytes, stderrHash)));
        return;
      }
      if (message?.method === "ping" && Object.hasOwn(message, "id")) {
        try { send({ jsonrpc: "2.0", id: message.id, result: {} }); } catch (error) { fail(error); }
        return;
      }
      if (!Object.hasOwn(message ?? {}, "id")) return;
      const waiter = pending.get(String(message.id));
      if (!waiter) {
        fail(rpcFailure("AgentCash MCP returned an unexpected response id", processDiagnostic(stderrBytes, stderrHash)));
        return;
      }
      pending.delete(String(message.id));
      if (message.error) {
        waiter.reject(rpcFailure("AgentCash MCP returned a JSON-RPC error", {
          rpc_code: Number.isSafeInteger(message.error.code) ? message.error.code : null,
          ...processDiagnostic(stderrBytes, stderrHash),
        }));
      } else if (!Object.hasOwn(message, "result")) {
        waiter.reject(rpcFailure("AgentCash MCP response omitted result", processDiagnostic(stderrBytes, stderrHash)));
      } else {
        waiter.resolve(message.result);
      }
    };

    try {
      child = spawnImpl(nodeCommand, [agentCashCommand, "server", "--quiet"], {
        cwd: workingDirectory,
        env: environment,
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (cause) {
      fail(new AgentCashAdapterError("agentcash_spawn_failed", "Unable to start the pinned AgentCash executable", {
        cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
      }));
      return;
    }

    child.stderr.on("data", (chunk) => {
      const bytes = Buffer.from(chunk);
      stderrBytes += bytes.byteLength;
      stderrHash.update(bytes);
      if (stderrBytes > MAX_STDERR_BYTES) fail(rpcFailure("AgentCash MCP stderr exceeded its bounded diagnostic limit", processDiagnostic(stderrBytes, stderrHash)));
    });
    child.stdout.on("data", (chunk) => {
      if (settled) return;
      const bytes = Buffer.from(chunk);
      stdoutBytes += bytes.byteLength;
      if (stdoutBytes > maxResponseBytes) {
        fail(new AgentCashAdapterError("agentcash_response_too_large", "AgentCash MCP response exceeded the configured limit", {
          response_bytes: stdoutBytes,
        }));
        return;
      }
      stdoutBuffer = Buffer.concat([stdoutBuffer, bytes]);
      while (true) {
        const newline = stdoutBuffer.indexOf(0x0a);
        if (newline < 0) break;
        const line = stdoutBuffer.subarray(0, newline);
        stdoutBuffer = stdoutBuffer.subarray(newline + 1);
        if (line.byteLength > 0) acceptLine(line);
        if (settled) return;
      }
    });
    child.on("error", (cause) => fail(new AgentCashAdapterError("agentcash_spawn_failed", "Pinned AgentCash process failed", {
      cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
      ...processDiagnostic(stderrBytes, stderrHash),
    })));
    child.on("close", (code, processSignal) => {
      if (settled) return;
      fail(new AgentCashAdapterError("agentcash_process_closed", "AgentCash MCP process closed before returning the requested result", {
        exit_code: Number.isSafeInteger(code) ? code : null,
        process_signal: typeof processSignal === "string" ? processSignal : null,
        ...processDiagnostic(stderrBytes, stderrHash),
      }));
    });
    child.stdin.on("error", (cause) => fail(new AgentCashAdapterError("agentcash_stdin_failed", "Unable to send the bounded request to AgentCash MCP", {
      cause_code: typeof cause?.code === "string" ? cause.code : "unknown",
    })));

    child.once("spawn", async () => {
      try {
        const initialized = await request("goldkey-init", "initialize", {
          protocolVersion: AGENTCASH_MCP_PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: "goldkey-agentcash-adapter", version: "1.0.0" },
        });
        if (
          initialized?.protocolVersion !== AGENTCASH_MCP_PROTOCOL_VERSION
          || initialized?.serverInfo?.name !== "agentcash"
          || initialized?.serverInfo?.version !== expectedVersion
        ) {
          throw new AgentCashAdapterError("agentcash_version_mismatch", "AgentCash MCP identity or pinned version did not match adapter config", {
            expected_version: expectedVersion,
            received_version: typeof initialized?.serverInfo?.version === "string" ? initialized.serverInfo.version : null,
          });
        }
        send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
        const result = await request("goldkey-call", method, params);
        succeed(result);
      } catch (error) {
        fail(error instanceof Error ? error : rpcFailure("AgentCash MCP request failed"));
      }
    });
  });
}

function operationArguments(operation, value) {
  exactKeys(value, BODY_METHODS.has(operation.method) ? new Set(["body"]) : new Set(), `arguments for ${operation.name}`);
  if (BODY_METHODS.has(operation.method) && !Object.hasOwn(value, "body")) {
    throw new InvalidInputError(`arguments for ${operation.name} must contain body`);
  }
  if (!BODY_METHODS.has(operation.method)) return Object.freeze({});
  const body = value.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new InvalidInputError(`arguments.body for ${operation.name} must be a JSON object`);
  }
  const canonical = canonicalBytes(body);
  if (canonical.byteLength > MAX_BODY_BYTES) {
    throw new InvalidInputError(`arguments.body for ${operation.name} exceeds ${MAX_BODY_BYTES} canonical bytes`);
  }
  return deepFreeze({ body: JSON.parse(canonical.toString("utf8")) });
}

function safeHeaders(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return Object.freeze({});
  const output = {};
  for (const [rawName, rawValue] of Object.entries(value)) {
    const name = rawName.toLowerCase();
    if (!SAFE_RESPONSE_HEADERS.has(name) || typeof rawValue !== "string" || rawValue.length > 8192 || /[\r\n\0]/.test(rawValue)) continue;
    output[name] = rawValue;
  }
  return Object.freeze(output);
}

function parsedTextObject(content) {
  if (content?.type !== "text" || typeof content.text !== "string") return undefined;
  try {
    const parsed = JSON.parse(content.text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function isAgentCashErrorContent(content) {
  const parsed = parsedTextObject(content);
  return parsed
    && typeof parsed.cause === "string"
    && (typeof parsed.message === "string" || typeof parsed.surface === "string" || typeof parsed.type === "string");
}

function safeContent(content) {
  if (!content || typeof content !== "object" || Array.isArray(content)) {
    throw new AgentCashAdapterError("agentcash_invalid_result", "AgentCash MCP returned malformed content");
  }
  if (content.type === "text" && typeof content.text === "string") return Object.freeze({ type: "text", text: content.text });
  if (["image", "audio"].includes(content.type) && typeof content.mimeType === "string" && typeof content.data === "string") {
    return Object.freeze({ type: content.type, mimeType: content.mimeType, data: content.data });
  }
  throw new AgentCashAdapterError("agentcash_invalid_result", "AgentCash MCP returned an unsupported content type");
}

function normalizeFetchResult(result, operation) {
  if (!result || typeof result !== "object" || Array.isArray(result) || !Array.isArray(result.content)) {
    throw new AgentCashAdapterError("agentcash_invalid_result", "AgentCash MCP returned an invalid tool result");
  }
  if (result.isError === true || result.content.length < 2 || isAgentCashErrorContent(result.content[0])) {
    throw new AgentCashAdapterError("agentcash_fetch_failed", "AgentCash reported a failed or ambiguous x402 fetch");
  }
  const metadata = parsedTextObject(result.content.at(-1));
  if (!metadata || !metadata.headers || typeof metadata.headers !== "object" || Array.isArray(metadata.headers)) {
    throw new AgentCashAdapterError("agentcash_invalid_result", "AgentCash success result omitted its response metadata");
  }
  let payment = null;
  if (metadata.protocol !== undefined) {
    if (metadata.protocol !== "x402" || metadata.network !== operation.payment_network || typeof metadata.price !== "string" || metadata.price.length > 128) {
      throw new AgentCashAdapterError("agentcash_payment_mismatch", "AgentCash payment metadata did not match the operator-pinned x402 network");
    }
    let settlement = null;
    if (metadata.payment !== null && metadata.payment !== undefined) {
      if (
        !metadata.payment
        || typeof metadata.payment !== "object"
        || Array.isArray(metadata.payment)
        || metadata.payment.success !== true
        || typeof metadata.payment.transactionHash !== "string"
        || metadata.payment.transactionHash.length < 1
        || metadata.payment.transactionHash.length > 256
      ) throw new AgentCashAdapterError("agentcash_payment_unsettled", "AgentCash did not report a successful x402 settlement");
      settlement = Object.freeze({ success: true, transaction_hash: metadata.payment.transactionHash });
    }
    payment = Object.freeze({
      protocol: "x402",
      network: operation.payment_network,
      price: metadata.price,
      settlement,
      max_amount_usd: operation.max_amount_usd,
    });
  }
  return deepFreeze({
    content: result.content.slice(0, -1).map(safeContent),
    payment,
    response_headers: safeHeaders(metadata.headers),
  });
}

function toolListHasSupportedFetch(result) {
  if (!result || typeof result !== "object" || !Array.isArray(result.tools)) return false;
  const fetchTool = result.tools.find((tool) => tool?.name === "fetch");
  const properties = fetchTool?.inputSchema?.properties;
  if (!properties || typeof properties !== "object") return false;
  return ["url", "method", "body", "headers", "timeout", "paymentProtocol", "paymentNetwork", "maxAmount"]
    .every((name) => Object.hasOwn(properties, name));
}

async function publicTarget(operation, resolverOptions) {
  const url = new URL(operation.url);
  return resolvePublicAddresses(url.hostname, resolverOptions);
}

function invocationRequest(config, operation, argumentsValue, deadlineAt, clock) {
  const remaining = deadlineAt - clock();
  if (remaining <= 0) throw new AgentCashAdapterError("agentcash_deadline", "No deadline remains for the AgentCash call");
  const timeout = Math.min(config.request_timeout_ms, Math.max(1, remaining - 100));
  const headers = {
    ...operation.headers,
    ...(BODY_METHODS.has(operation.method) ? { "content-type": "application/json" } : {}),
  };
  return deepFreeze({
    name: "fetch",
    arguments: {
      url: operation.url,
      method: operation.method,
      ...(argumentsValue.body === undefined ? {} : { body: argumentsValue.body }),
      headers,
      timeout,
      paymentProtocol: "x402",
      paymentNetwork: operation.payment_network,
      maxAmount: Number(operation.max_amount_usd),
      stream: false,
    },
  });
}

/**
 * Boots AgentCash without making a purchase, verifies the exact version and
 * documented fetch tool, then returns the operator-bound GoldKey connector.
 */
export async function prepareAgentCashAdapter({
  config: rawConfig,
  environment = process.env,
  lstatImpl = defaultLstat,
  accessImpl = defaultAccess,
  resolve4,
  resolve6,
  rpcImpl = runAgentCashMcpRpc,
  spawnImpl = defaultSpawn,
  clock = () => Date.now(),
} = {}) {
  const config = normalizeAgentCashAdapterConfig(rawConfig);
  const childEnv = childEnvironment(config, environment);
  await assertExecutionSurface(config, { lstatImpl, accessImpl });
  const walletFiles = await assertWalletFiles(config, childEnv, lstatImpl);
  const resolverOptions = {
    ...(resolve4 ? { resolve4 } : {}),
    ...(resolve6 ? { resolve6 } : {}),
  };
  for (const operation of config.operations) await publicTarget(operation, resolverOptions);

  const probeDeadline = clock() + Math.min(config.request_timeout_ms, 5_000);
  const probe = await rpcImpl({
    nodeCommand: config.node_command,
    agentCashCommand: config.agentcash_command,
    expectedVersion: config.agentcash_version,
    workingDirectory: config.working_directory,
    environment: childEnv,
    method: "tools/list",
    params: {},
    deadlineAt: probeDeadline,
    maxResponseBytes: config.max_response_bytes,
    clock,
    spawnImpl,
  });
  if (!toolListHasSupportedFetch(probe)) {
    throw new AgentCashAdapterError("agentcash_incompatible", "Pinned AgentCash MCP server does not expose the documented bounded fetch parameters");
  }

  const connector = Object.freeze({
    id: config.connector_id,
    kind: "mcp_tool",
    server_id: config.server_id,
    tools: Object.freeze(config.operations.map((operation) => Object.freeze({
      name: operation.name,
      effect: "payment",
      input_schema_sha256: operation.input_schema_sha256,
    }))),
    invokeTool: async ({ serverId, tool, arguments: proposedArguments, signal, deadlineAt }) => {
      if (serverId !== config.server_id) throw new InvalidInputError("AgentCash connector server_id changed after configuration");
      const operation = config.operations.find(({ name }) => name === tool);
      if (!operation) throw new InvalidInputError("AgentCash operation is not operator-configured");
      const argumentsValue = operationArguments(operation, proposedArguments);
      await publicTarget(operation, resolverOptions);
      const request = invocationRequest(config, operation, argumentsValue, deadlineAt, clock);
      const result = await rpcImpl({
        nodeCommand: config.node_command,
        agentCashCommand: config.agentcash_command,
        expectedVersion: config.agentcash_version,
        workingDirectory: config.working_directory,
        environment: childEnv,
        method: "tools/call",
        params: request,
        signal,
        deadlineAt,
        maxResponseBytes: config.max_response_bytes,
        clock,
        spawnImpl,
      });
      return normalizeFetchResult(result, operation);
    },
  });

  const createInvoker = (enforcer) => {
    if (!enforcer || typeof enforcer.guardMcpTool !== "function") {
      throw new InvalidInputError("AgentCash adapter requires an injected GoldKey guardMcpTool enforcement primitive");
    }
    return async (input) => {
      exactKeys(input, new Set(["operation", "arguments", "idempotencyKey"]), "AgentCash guarded invocation");
      const operation = config.operations.find(({ name }) => name === input.operation);
      if (!operation) throw new InvalidInputError("AgentCash invocation operation is not operator-configured");
      const argumentsValue = operationArguments(operation, input.arguments ?? {});
      await publicTarget(operation, resolverOptions);
      return enforcer.guardMcpTool({
        connectorId: config.connector_id,
        tool: operation.name,
        arguments: argumentsValue,
        idempotencyKey: input.idempotencyKey,
      });
    };
  };

  return Object.freeze({
    config,
    connector,
    createInvoker,
    preflight: Object.freeze({
      agentcash_version: config.agentcash_version,
      credential_mode: config.credential_mode,
      wallet_files_checked: walletFiles,
      operations_checked: config.operations.length,
      note: "AgentCash credentials were not read or returned by GoldKey",
    }),
    tool_manifest: Object.freeze(config.operations.map((operation) => Object.freeze({
      name: operation.name,
      effect: "payment",
      destination: `mcp://${config.server_id}/${operation.name}`,
      upstream_url: operation.url,
      input_schema: operation.input_schema,
      input_schema_sha256: operation.input_schema_sha256,
      max_amount_usd: operation.max_amount_usd,
      payment_network: operation.payment_network,
    }))),
  });
}

/**
 * Produces a deterministic, zero-side-effect onboarding artifact. It does not
 * resolve DNS, spawn AgentCash, call GoldKey, sign, authorize, or pay.
 */
export function inspectAgentCashInvocation({ config: rawConfig, operation: operationName, arguments: proposedArguments = {}, idempotencyKey }) {
  const config = normalizeAgentCashAdapterConfig(rawConfig);
  const operation = config.operations.find(({ name }) => name === operationName);
  if (!operation) throw new InvalidInputError("AgentCash inspection operation is not operator-configured");
  safeIdentifier(idempotencyKey, "idempotencyKey");
  if (idempotencyKey.length < 8) throw new InvalidInputError("idempotencyKey must contain at least 8 characters");
  const argumentsValue = operationArguments(operation, proposedArguments);
  const guardCall = normalizeGuardCall({
    kind: "mcp_tool",
    connector_id: config.connector_id,
    tool: operation.name,
    input_schema_sha256: operation.input_schema_sha256,
    arguments: argumentsValue,
  });
  const toolCall = invocationRequest(config, operation, argumentsValue, Number.MAX_SAFE_INTEGER, () => 0);
  const initialize = {
    jsonrpc: "2.0",
    id: "goldkey-init",
    method: "initialize",
    params: {
      protocolVersion: AGENTCASH_MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "goldkey-agentcash-adapter", version: "1.0.0" },
    },
  };
  const initialized = { jsonrpc: "2.0", method: "notifications/initialized", params: {} };
  const call = { jsonrpc: "2.0", id: "goldkey-call", method: "tools/call", params: toolCall };
  return deepFreeze({
    schema: "goldkey.agentcash-inspection.v1",
    discovery_only: true,
    agentcash_process_started: false,
    tool_calls_invoked: false,
    authorization_or_payment_attempted: false,
    signature_created: false,
    idempotency_key: idempotencyKey,
    policy_binding: {
      connector_id: config.connector_id,
      server_id: config.server_id,
      tool: operation.name,
      effect: "payment",
      destination: `mcp://${config.server_id}/${operation.name}`,
      upstream_url: operation.url,
      input_schema: operation.input_schema,
      input_schema_sha256: operation.input_schema_sha256,
      payment_protocol: "x402",
      payment_network: operation.payment_network,
      max_amount_usd: operation.max_amount_usd,
    },
    canonical_guarded_call: canonicalize(guardCall),
    guarded_call_sha256: hashGuardCall(guardCall),
    guarded_call: guardCall,
    agentcash_stdio: {
      command: config.node_command,
      argv: [config.agentcash_command, "server", "--quiet"],
      stdin_json_lines: [
        canonicalize(initialize),
        canonicalize(initialized),
        canonicalize(call),
      ],
      request_timeout_ms: config.request_timeout_ms,
      note: "Runtime may only reduce timeout_ms to fit the remaining signed Guard deadline.",
    },
  });
}
