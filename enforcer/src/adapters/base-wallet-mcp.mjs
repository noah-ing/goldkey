import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { deepFreeze } from "../canonical.mjs";
import {
  AmbiguousOutcomeError,
  GoldKeyEnforcerError,
  InvalidInputError,
  LocalStateError,
} from "../errors.mjs";
import { BASE_WALLET_REQUEST_SCHEMA, buildBaseWalletCall, probeBaseWalletRequest } from "./base-wallet-request.mjs";

const IMPLEMENTATION = Object.freeze({ name: "goldkey-base-wallet", version: "1.0.0" });
const MAX_RESULT_BYTES = 64 * 1024;
const ENFORCEMENT_DENIED = -32003;
const AMBIGUOUS_OUTCOME = -32004;

const TOOL_KINDS = Object.freeze({
  goldkey_base_native_transfer: "native_transfer",
  goldkey_base_erc20_transfer: "erc20_transfer",
  goldkey_base_erc20_approve: "erc20_approve",
});

function exactObject(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidInputError(`${name} must be an object`);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) throw new InvalidInputError(`${name} contains unsupported fields`, { fields: extras.sort() });
  return value;
}

function commonProperties() {
  return {
    connector_id: { type: "string", description: "Operator-configured Base wallet connector ID." },
    idempotency_key: { type: "string", pattern: "^[A-Za-z0-9._:-]{8,128}$" },
    nonce: { type: "string", pattern: "^(0|[1-9][0-9]*)$", description: "Exact pending wallet nonce." },
    gas_limit: { type: "string", pattern: "^[1-9][0-9]*$" },
    max_fee_per_gas_atomic: { type: "string", pattern: "^[1-9][0-9]*$" },
    max_priority_fee_per_gas_atomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
    amount_atomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
    probe: {
      type: "boolean",
      default: false,
      description: "When true, validate locally without loading runtime/signer, authorizing, paying, signing, or broadcasting.",
    },
  };
}

function operationEntries(config, kind) {
  const entries = [];
  for (const connector of config.connectors) {
    for (const operation of connector.operations) {
      if (operation.kind === kind) entries.push({ connector, operation });
    }
  }
  return entries;
}

function inputSchema(config, kind, entries) {
  const properties = commonProperties();
  let destinationField;
  if (kind === "native_transfer") {
    destinationField = "to";
    properties.to = { type: "string", description: "Operator-allowlisted native-token recipient." };
  } else if (kind === "erc20_transfer") {
    destinationField = "to";
    properties.token = { type: "string", description: "Operator-allowlisted ERC-20 token." };
    properties.to = { type: "string", description: "Operator-allowlisted ERC-20 recipient." };
  } else {
    destinationField = "spender";
    properties.token = { type: "string", description: "Operator-allowlisted ERC-20 token." };
    properties.spender = { type: "string", description: "Operator-allowlisted bounded approval spender." };
  }
  const variants = entries.map(({ connector, operation }) => ({
    type: "object",
    properties: {
      connector_id: { const: connector.id },
      ...(operation.token ? { token: { const: operation.token } } : {}),
      [destinationField]: {
        enum: kind === "erc20_approve" ? operation.spenders : operation.recipients,
      },
    },
    required: ["connector_id", ...(operation.token ? ["token"] : []), destinationField],
  }));
  return deepFreeze({
    type: "object",
    properties,
    required: [
      "connector_id", "idempotency_key", "nonce", "gas_limit", "max_fee_per_gas_atomic",
      "max_priority_fee_per_gas_atomic", "amount_atomic", ...(kind === "native_transfer" ? ["to"] : ["token", destinationField]),
    ],
    additionalProperties: false,
    oneOf: variants,
  });
}

function buildTools(config) {
  const descriptions = {
    native_transfer: "Request one exact operator-capped native ETH transfer on Base through GoldKey authorization.",
    erc20_transfer: "Request one exact operator-capped ERC-20 transfer on Base through GoldKey authorization.",
    erc20_approve: "Request one exact bounded ERC-20 approval on Base through GoldKey authorization; unlimited approvals are forbidden.",
  };
  const tools = [];
  for (const [name, kind] of Object.entries(TOOL_KINDS)) {
    const entries = operationEntries(config, kind);
    if (entries.length === 0) continue;
    tools.push(deepFreeze({ name, description: descriptions[kind], inputSchema: inputSchema(config, kind, entries) }));
  }
  return Object.freeze(tools);
}

function requestFromArguments(kind, value) {
  const operationFields = kind === "native_transfer"
    ? ["to"]
    : kind === "erc20_transfer" ? ["token", "to"] : ["token", "spender"];
  const allowed = new Set([
    "connector_id", "idempotency_key", "nonce", "gas_limit", "max_fee_per_gas_atomic",
    "max_priority_fee_per_gas_atomic", "amount_atomic", "probe", ...operationFields,
  ]);
  const args = exactObject(value, allowed, "wallet tool arguments");
  if (args.probe !== undefined && typeof args.probe !== "boolean") throw new InvalidInputError("probe must be boolean");
  const operation = kind === "native_transfer"
    ? { kind, to: args.to, amount_atomic: args.amount_atomic }
    : kind === "erc20_transfer"
      ? { kind, token: args.token, to: args.to, amount_atomic: args.amount_atomic }
      : { kind, token: args.token, spender: args.spender, amount_atomic: args.amount_atomic };
  return {
    probe: args.probe === true,
    request: {
      schema: BASE_WALLET_REQUEST_SCHEMA,
      connector_id: args.connector_id,
      idempotency_key: args.idempotency_key,
      nonce: args.nonce,
      gas_limit: args.gas_limit,
      max_fee_per_gas_atomic: args.max_fee_per_gas_atomic,
      max_priority_fee_per_gas_atomic: args.max_priority_fee_per_gas_atomic,
      operation,
    },
  };
}

function mcpResult(value) {
  let text;
  try {
    text = JSON.stringify(value, (_, entry) => typeof entry === "bigint" ? entry.toString() : entry);
  } catch (cause) {
    throw new LocalStateError("Wallet result is not serializable", { cause });
  }
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_RESULT_BYTES) {
    throw new LocalStateError("Wallet result exceeds the MCP response safety limit");
  }
  const structured = JSON.parse(text);
  if (!structured || typeof structured !== "object" || Array.isArray(structured)) {
    throw new LocalStateError("Wallet result must be an object");
  }
  return deepFreeze({
    content: [{ type: "text", text }],
    structuredContent: structured,
  });
}

function toMcpError(error) {
  if (error instanceof McpError) return error;
  if (error instanceof AmbiguousOutcomeError) {
    return new McpError(AMBIGUOUS_OUTCOME, "GoldKey recorded an ambiguous wallet outcome; do not retry automatically", { code: error.code });
  }
  if (error instanceof GoldKeyEnforcerError) {
    const invalid = error.code === "invalid_input" || error.code === "idempotency_conflict" || error.code === "replay_detected";
    return new McpError(
      invalid ? ErrorCode.InvalidParams : ENFORCEMENT_DENIED,
      invalid ? "GoldKey rejected the wallet request" : "GoldKey did not authorize the wallet request",
      { code: error.code },
    );
  }
  return new McpError(ENFORCEMENT_DENIED, "GoldKey wallet enforcement failed closed", { code: "enforcement_failed" });
}

export function createBaseWalletMcpFacade({ config, executableWalletFactory } = {}) {
  if (!config || !Array.isArray(config.connectors)) throw new InvalidInputError("A normalized Base wallet config is required");
  if (typeof executableWalletFactory !== "function") throw new InvalidInputError("An executable wallet factory is required");
  const tools = buildTools(config);
  const toolsByName = new Map(tools.map((tool) => [tool.name, tool]));
  let executablePromise;

  async function callTool(name, args) {
    const kind = TOOL_KINDS[name];
    if (!kind || !toolsByName.has(name)) throw new InvalidInputError("Wallet tool is not exposed by operator config");
    const parsed = requestFromArguments(kind, args);
    if (parsed.probe) return mcpResult(probeBaseWalletRequest({ config, request: parsed.request }));
    buildBaseWalletCall({ config, request: parsed.request });
    executablePromise ??= Promise.resolve().then(executableWalletFactory);
    const wallet = await executablePromise;
    if (!wallet || typeof wallet.execute !== "function") throw new LocalStateError("Executable wallet factory returned an invalid wallet");
    return mcpResult(await wallet.execute(parsed.request));
  }

  return Object.freeze({ tools, callTool });
}

function safeLog(stream, error) {
  const message = (error instanceof Error ? error.message : String(error)).replace(/[\0\r\n]+/g, " ").slice(0, 1000);
  stream.write(`[goldkey-wallet] protocol error: ${message}\n`);
}

export async function serveBaseWalletMcp({
  config,
  executableWalletFactory,
  input = process.stdin,
  output = process.stdout,
  stderr = process.stderr,
  transport,
  serverFactory = () => new Server(IMPLEMENTATION, {
    capabilities: { tools: { listChanged: false } },
    enforceStrictCapabilities: true,
  }),
} = {}) {
  if (!stderr || typeof stderr.write !== "function") throw new InvalidInputError("MCP stderr must be writable");
  const facade = createBaseWalletMcpFacade({ config, executableWalletFactory });
  const server = await serverFactory();
  if (!server || typeof server.setRequestHandler !== "function" || typeof server.connect !== "function") {
    throw new InvalidInputError("MCP server factory returned an invalid server");
  }
  let resolveClosed;
  const closed = new Promise((resolve) => { resolveClosed = resolve; });
  server.fallbackRequestHandler = async (request) => {
    throw new McpError(ErrorCode.MethodNotFound, `Unsupported wallet MCP method ${request.method}`);
  };
  server.fallbackNotificationHandler = async () => {};
  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    if (request.params?.cursor !== undefined) throw new McpError(ErrorCode.InvalidParams, "Wallet tools do not use pagination");
    return { tools: facade.tools };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    if (request.params.task !== undefined) throw new McpError(ErrorCode.MethodNotFound, "Task-augmented wallet calls are not supported");
    if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, "Wallet request was cancelled before enforcement");
    try {
      return await facade.callTool(request.params.name, request.params.arguments ?? {});
    } catch (error) {
      throw toMcpError(error);
    }
  });
  server.onerror = (error) => safeLog(stderr, error);
  server.onclose = () => resolveClosed();
  const stdioTransport = transport ?? new StdioServerTransport(input, output, { maxBufferSize: 256 * 1024 });
  await server.connect(stdioTransport);
  return Object.freeze({
    tools: facade.tools,
    close: async () => { await server.close(); resolveClosed(); },
    waitForClose: () => closed,
  });
}
