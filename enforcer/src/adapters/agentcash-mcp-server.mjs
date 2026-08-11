import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { assertIdempotencyKey, deepFreeze } from "../canonical.mjs";
import {
  AmbiguousOutcomeError,
  GoldKeyEnforcerError,
  InvalidInputError,
} from "../errors.mjs";

export const AGENTCASH_IDEMPOTENCY_META_KEY = "com.goldkey/idempotency-key";

const IMPLEMENTATION = Object.freeze({ name: "goldkey-agentcash", version: "1.0.0" });
const ENFORCEMENT_DENIED = -32003;
const AMBIGUOUS_OUTCOME = -32004;

function safeLog(stream, scope, error) {
  const raw = error instanceof Error ? error.message : String(error);
  stream.write(`[goldkey-agentcash] ${scope}: ${raw.replace(/[\0\r\n]+/g, " ").slice(0, 1000)}\n`);
}

function requestIdempotencyKey(request) {
  const supplied = request.params._meta?.[AGENTCASH_IDEMPOTENCY_META_KEY];
  if (supplied === undefined) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Every AgentCash purchase requires stable MCP _meta["${AGENTCASH_IDEMPOTENCY_META_KEY}"]`,
    );
  }
  try {
    return assertIdempotencyKey(supplied);
  } catch {
    throw new McpError(
      ErrorCode.InvalidParams,
      `${AGENTCASH_IDEMPOTENCY_META_KEY} must be an 8-128 character safe idempotency key`,
    );
  }
}

function enforcementError(error) {
  if (error instanceof McpError) return error;
  if (error instanceof AmbiguousOutcomeError) {
    return new McpError(AMBIGUOUS_OUTCOME, "GoldKey recorded an ambiguous AgentCash outcome; do not retry automatically", {
      code: error.code,
    });
  }
  if (error instanceof GoldKeyEnforcerError) {
    const invalid = ["invalid_input", "idempotency_conflict", "replay_detected"].includes(error.code);
    return new McpError(
      invalid ? ErrorCode.InvalidParams : ENFORCEMENT_DENIED,
      invalid ? "GoldKey rejected the guarded AgentCash request" : "GoldKey did not authorize the AgentCash request",
      { code: error.code },
    );
  }
  return new McpError(ENFORCEMENT_DENIED, "GoldKey AgentCash enforcement failed closed", {
    code: typeof error?.code === "string" ? error.code : "enforcement_failed",
  });
}

function exposedTools(adapter) {
  if (!adapter || typeof adapter.createInvoker !== "function" || !Array.isArray(adapter.tool_manifest)) {
    throw new InvalidInputError("A prepared AgentCash adapter is required");
  }
  return Object.freeze(adapter.tool_manifest.map((tool) => deepFreeze({
    name: tool.name,
    title: `Guarded AgentCash: ${tool.name}`,
    description: `GoldKey-guarded x402 purchase at the operator-pinned ${tool.upstream_url} endpoint (maximum ${tool.max_amount_usd} USD on ${tool.payment_network}).`,
    inputSchema: tool.input_schema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  })));
}

function callResult(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.content)) {
    throw new McpError(ENFORCEMENT_DENIED, "Guarded AgentCash connector returned an invalid result");
  }
  const metadata = deepFreeze({
    payment: value.payment ?? null,
    response_headers: value.response_headers ?? {},
  });
  return {
    content: value.content,
    structuredContent: metadata,
    _meta: { "com.goldkey/agentcash": metadata },
  };
}

/**
 * Serves only prepared, operator-configured AgentCash operations to an MCP host.
 * Every tools/call enters the injected Guard primitive before AgentCash starts.
 */
export async function serveAgentCashGuardMcp({
  adapter,
  enforcer,
  transport,
  input = process.stdin,
  output = process.stdout,
  stderr = process.stderr,
} = {}) {
  if (!enforcer || typeof enforcer.guardMcpTool !== "function") {
    throw new InvalidInputError("AgentCash MCP server requires an injected GoldKey enforcer");
  }
  if (!stderr || typeof stderr.write !== "function") throw new InvalidInputError("AgentCash MCP stderr must be writable");
  const tools = exposedTools(adapter);
  const toolNames = new Set(tools.map(({ name }) => name));
  const invoke = adapter.createInvoker(enforcer);
  const server = new Server(IMPLEMENTATION, {
    capabilities: { tools: { listChanged: false } },
    enforceStrictCapabilities: true,
  });
  let closed = false;
  let resolveClosed;
  const closedPromise = new Promise((resolve) => { resolveClosed = resolve; });
  const markClosed = () => {
    if (closed) return;
    closed = true;
    resolveClosed();
  };
  server.fallbackRequestHandler = async (request) => {
    throw new McpError(ErrorCode.MethodNotFound, `Unsupported guarded AgentCash MCP method ${request.method}`);
  };
  server.fallbackNotificationHandler = async () => {};
  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    if (request.params?.cursor !== undefined) throw new McpError(ErrorCode.InvalidParams, "Guarded AgentCash tools are one unpaginated snapshot");
    return { tools };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    if (request.params.task !== undefined) throw new McpError(ErrorCode.MethodNotFound, "Task-augmented tools/call is not supported");
    if (!toolNames.has(request.params.name)) throw new McpError(ErrorCode.InvalidParams, "Tool is not in the operator-configured AgentCash allowlist");
    if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, "AgentCash request was cancelled before enforcement");
    try {
      return callResult(await invoke({
        operation: request.params.name,
        arguments: request.params.arguments ?? {},
        idempotencyKey: requestIdempotencyKey(request),
      }));
    } catch (error) {
      throw enforcementError(error);
    }
  });
  server.onerror = (error) => safeLog(stderr, "downstream protocol error", error);
  server.onclose = markClosed;
  const downstream = transport ?? new StdioServerTransport(input, output, {
    maxBufferSize: adapter.config.max_response_bytes,
  });
  try {
    await server.connect(downstream);
  } catch (cause) {
    markClosed();
    throw cause;
  }
  const close = async () => {
    if (closed) return;
    try {
      await server.close();
    } finally {
      markClosed();
    }
  };
  return Object.freeze({
    tools,
    close,
    waitForClose: () => closedPromise,
  });
}
