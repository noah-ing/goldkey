import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import {
  assertIdempotencyKey,
  canonicalSha256,
  deepFreeze,
} from "../canonical.mjs";
import {
  AmbiguousOutcomeError,
  GoldKeyEnforcerError,
  InvalidInputError,
} from "../errors.mjs";
import {
  MCP_IDEMPOTENCY_META_KEY,
  assertNormalizedMcpStdioConfig,
  assertNormalizedMcpStdioInspectionConfig,
} from "./mcp-stdio-config.mjs";
import { StrictStdioClientTransport } from "./mcp-stdio-transport.mjs";

const IMPLEMENTATION = Object.freeze({ name: "goldkey-mcp-stdio", version: "1.0.0" });
const MAX_DISCOVERY_PAGES = 100;
const MAX_DISCOVERED_TOOLS = 1_000;
const ENFORCEMENT_DENIED = -32003;
const AMBIGUOUS_OUTCOME = -32004;
const MAX_ERROR_DIAGNOSTIC_BYTES = 4096;
const MAX_ERROR_DIAGNOSTICS_PER_SCOPE = 16;
const errorDiagnosticCounts = new Map();

function timeoutAfter(milliseconds, label) {
  let timer;
  const promise = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} exceeded ${milliseconds}ms`)), milliseconds);
    timer.unref?.();
  });
  return { promise, clear: () => clearTimeout(timer) };
}

async function withinStartupTimeout(operation, milliseconds, label) {
  const timeout = timeoutAfter(milliseconds, label);
  try {
    return await Promise.race([Promise.resolve().then(operation), timeout.promise]);
  } finally {
    timeout.clear();
  }
}

function safeLog(stream, scope, error) {
  const raw = error instanceof Error ? error.message : String(error);
  const count = (errorDiagnosticCounts.get(scope) ?? 0) + 1;
  errorDiagnosticCounts.set(scope, count);
  if (count > MAX_ERROR_DIAGNOSTICS_PER_SCOPE) return;
  // Bound conversion as well as output: a hostile protocol error must not
  // make diagnostics allocate proportional to its message length.
  const bytes = Buffer.from(raw.slice(0, MAX_ERROR_DIAGNOSTIC_BYTES), "utf8");
  const sample = bytes.subarray(0, MAX_ERROR_DIAGNOSTIC_BYTES);
  const hash = createHash("sha256").update(sample).digest("hex");
  stream.write(
    `[goldkey-mcp] ${scope}: count=${count} sha256=${hash} sampled_bytes=${sample.byteLength} truncated=${raw.length > MAX_ERROR_DIAGNOSTIC_BYTES || bytes.byteLength > sample.byteLength}\n`,
  );
}

function cloneTool(tool) {
  return deepFreeze(structuredClone(tool));
}

async function discoverUpstreamTools(client, config) {
  const discovered = new Map();
  const cursors = new Set();
  let cursor;
  let pages = 0;
  do {
    pages += 1;
    if (pages > MAX_DISCOVERY_PAGES) throw new InvalidInputError("MCP upstream tools/list exceeded the page limit");
    const result = await client.listTools(
      cursor === undefined ? {} : { cursor },
      {
        timeout: config.upstream.startup_timeout_ms,
        maxTotalTimeout: config.upstream.startup_timeout_ms,
      },
    );
    for (const tool of result.tools) {
      if (discovered.has(tool.name)) throw new InvalidInputError(`MCP upstream returned duplicate tool ${tool.name}`);
      if (discovered.size >= MAX_DISCOVERED_TOOLS) {
        throw new InvalidInputError(`MCP upstream exposes more than ${MAX_DISCOVERED_TOOLS} tools`);
      }
      discovered.set(tool.name, cloneTool(tool));
    }
    cursor = result.nextCursor;
    if (cursor !== undefined) {
      if (cursors.has(cursor)) throw new InvalidInputError("MCP upstream repeated a tools/list cursor");
      cursors.add(cursor);
    }
  } while (cursor !== undefined);

  return Object.freeze([...discovered.values()]);
}

function selectConfiguredTools(discoveredTools, config) {
  const discovered = new Map(discoveredTools.map((tool) => [tool.name, tool]));
  const guarded = [];
  for (const configured of config.connector.tools) {
    const upstream = discovered.get(configured.name);
    if (!upstream) throw new InvalidInputError(`Configured guarded tool ${configured.name} is absent upstream`);
    const actualHash = canonicalSha256(upstream.inputSchema);
    if (actualHash !== configured.input_schema_sha256) {
      throw new InvalidInputError(`Configured guarded tool ${configured.name} input schema hash does not match upstream`, {
        expected: configured.input_schema_sha256,
        actual: actualHash,
      });
    }
    if (upstream.execution?.taskSupport === "required") {
      throw new InvalidInputError(`Configured guarded tool ${configured.name} requires unsupported task execution`);
    }
    guarded.push(upstream);
  }
  return Object.freeze(guarded);
}

function requestIdempotencyKey(request) {
  const supplied = request.params._meta?.[MCP_IDEMPOTENCY_META_KEY];
  if (supplied === undefined) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `MCP tools/call requires a durable explicit ${MCP_IDEMPOTENCY_META_KEY} idempotency key`,
    );
  }
  try {
    return assertIdempotencyKey(supplied);
  } catch (cause) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `${MCP_IDEMPOTENCY_META_KEY} must be an 8-128 character safe idempotency key`,
      { code: cause.code ?? "invalid_input" },
    );
  }
}

function enforcementError(error) {
  if (error instanceof McpError) return error;
  if (error instanceof AmbiguousOutcomeError) {
    return new McpError(AMBIGUOUS_OUTCOME, "GoldKey recorded an ambiguous outcome; do not retry automatically", {
      code: error.code,
    });
  }
  if (error instanceof GoldKeyEnforcerError) {
    const invalid = error.code === "invalid_input" || error.code === "idempotency_conflict" || error.code === "replay_detected";
    return new McpError(
      invalid ? ErrorCode.InvalidParams : ENFORCEMENT_DENIED,
      invalid ? "GoldKey rejected the guarded tool request" : "GoldKey did not authorize the guarded tool request",
      { code: error.code },
    );
  }
  return new McpError(ENFORCEMENT_DENIED, "GoldKey enforcement failed closed", { code: "enforcement_failed" });
}

function defaultClientFactory() {
  return new Client(IMPLEMENTATION, {
    capabilities: {},
    enforceStrictCapabilities: true,
  });
}

function defaultTransportFactory(config, stderr) {
  return new StrictStdioClientTransport({
    command: config.upstream.command,
    args: config.upstream.args,
    cwd: config.upstream.cwd,
    env: config.upstream.env,
    maxMessageBytes: config.upstream.max_message_bytes,
    stderr,
  });
}

/**
 * Discovery-only inspection starts the exact pinned upstream and sends
 * initialize plus tools/list pagination. GoldKey does not instantiate its
 * runtime or authorizer, sign, pay, or send tools/call. An arbitrary upstream
 * can still have side effects when it handles initialization or discovery.
 */
export async function inspectMcpStdioUpstream({
  config,
  stderr = process.stderr,
  clientFactory = defaultClientFactory,
  upstreamTransportFactory = defaultTransportFactory,
} = {}) {
  assertNormalizedMcpStdioInspectionConfig(config);
  if (!stderr || typeof stderr.write !== "function") throw new InvalidInputError("MCP inspection stderr must be writable");
  if (typeof clientFactory !== "function" || typeof upstreamTransportFactory !== "function") {
    throw new InvalidInputError("MCP inspection factories must be functions");
  }
  const client = await clientFactory();
  const transport = await upstreamTransportFactory(config, stderr);
  if (!client || typeof client.connect !== "function" || typeof client.listTools !== "function" || typeof client.close !== "function") {
    throw new InvalidInputError("MCP inspection client factory returned an invalid client");
  }
  if (!transport || typeof transport.start !== "function" || typeof transport.close !== "function") {
    throw new InvalidInputError("MCP inspection transport factory returned an invalid transport");
  }
  client.fallbackRequestHandler = async (request) => {
    throw new McpError(ErrorCode.MethodNotFound, `Unsupported upstream callback ${request.method}`);
  };
  client.fallbackNotificationHandler = async () => {};
  client.onerror = (error) => safeLog(stderr, "inspection protocol error", error);
  try {
    await withinStartupTimeout(
      () => client.connect(transport),
      config.upstream.startup_timeout_ms,
      "MCP inspection initialization",
    );
    const tools = await withinStartupTimeout(
      () => discoverUpstreamTools(client, config),
      config.upstream.startup_timeout_ms,
      "MCP inspection tool discovery",
    );
    return Object.freeze(tools.map((tool) => Object.freeze({
      name: tool.name,
      input_schema_sha256: canonicalSha256(tool.inputSchema),
    })));
  } finally {
    await Promise.allSettled([client.close(), transport.close()]);
  }
}

/**
 * Starts and validates the fixed upstream before any downstream MCP client can
 * connect. The returned connector is the only callback a GoldKeyEnforcer needs
 * to forward one authorized tools/call request.
 */
export async function prepareMcpStdioProxy({
  config,
  stderr = process.stderr,
  clock = () => Date.now(),
  clientFactory = defaultClientFactory,
  upstreamTransportFactory = defaultTransportFactory,
} = {}) {
  assertNormalizedMcpStdioConfig(config);
  if (!stderr || typeof stderr.write !== "function") throw new InvalidInputError("MCP proxy stderr must be writable");
  if (typeof clock !== "function") throw new InvalidInputError("MCP proxy clock must be a function");
  if (typeof clientFactory !== "function" || typeof upstreamTransportFactory !== "function") {
    throw new InvalidInputError("MCP proxy factories must be functions");
  }

  const client = await clientFactory();
  if (!client || typeof client.connect !== "function" || typeof client.listTools !== "function" || typeof client.callTool !== "function") {
    throw new InvalidInputError("MCP upstream client factory returned an invalid client");
  }
  const upstreamTransport = await upstreamTransportFactory(config, stderr);
  if (!upstreamTransport || typeof upstreamTransport.start !== "function" || typeof upstreamTransport.close !== "function") {
    throw new InvalidInputError("MCP upstream transport factory returned an invalid transport");
  }

  client.fallbackRequestHandler = async (request) => {
    throw new McpError(ErrorCode.MethodNotFound, `Unsupported upstream callback ${request.method}`);
  };
  // Notifications cannot receive an error response. They are deliberately
  // consumed locally and never forwarded to the downstream client.
  client.fallbackNotificationHandler = async () => {};

  let downstreamServer;
  let closing = false;
  let closed = false;
  let resolveClosed;
  const closedPromise = new Promise((resolve) => { resolveClosed = resolve; });

  function markClosed() {
    if (closed) return;
    closed = true;
    resolveClosed();
  }

  async function close() {
    if (closing) return closedPromise;
    closing = true;
    await Promise.allSettled([
      downstreamServer?.close?.(),
      client.close?.(),
      upstreamTransport.close?.(),
    ]);
    markClosed();
    return closedPromise;
  }

  client.onerror = (error) => {
    safeLog(stderr, "upstream protocol error", error);
    close().catch((closeError) => safeLog(stderr, "close error", closeError));
  };
  client.onclose = () => {
    if (!closing) safeLog(stderr, "upstream closed", new Error("exclusive upstream connection ended"));
    close().catch((closeError) => safeLog(stderr, "close error", closeError));
  };

  let tools;
  try {
    await withinStartupTimeout(
      () => client.connect(upstreamTransport),
      config.upstream.startup_timeout_ms,
      "MCP upstream initialization",
    );
    const discoveredTools = await withinStartupTimeout(
      () => discoverUpstreamTools(client, config),
      config.upstream.startup_timeout_ms,
      "MCP upstream tool discovery",
    );
    tools = selectConfiguredTools(discoveredTools, config);
  } catch (cause) {
    await close();
    throw cause;
  }

  const toolNames = new Set(tools.map(({ name }) => name));
  const connector = Object.freeze({
    id: config.connector.id,
    kind: "mcp_tool",
    server_id: config.connector.server_id,
    tools: config.connector.tools,
    invokeTool: async ({ serverId, tool, arguments: argumentsValue, signal, deadlineAt }) => {
      if (closed || closing) throw new Error("MCP upstream is closed");
      if (serverId !== config.connector.server_id || !toolNames.has(tool)) {
        throw new InvalidInputError("MCP invocation is outside the prepared operator-controlled connector");
      }
      const remaining = deadlineAt - clock();
      if (!Number.isSafeInteger(deadlineAt) || remaining <= 0) throw new Error("MCP invocation deadline has expired");
      return client.callTool(
        { name: tool, arguments: argumentsValue },
        undefined,
        { signal, timeout: remaining, maxTotalTimeout: remaining },
      );
    },
  });

  async function serve({ enforcer, transport, input = process.stdin, output = process.stdout } = {}) {
    if (closed || closing) throw new InvalidInputError("Cannot serve a closed MCP proxy");
    if (downstreamServer) throw new InvalidInputError("MCP proxy already has a downstream server");
    if (!enforcer || typeof enforcer.guardMcpTool !== "function") {
      throw new InvalidInputError("MCP proxy requires an injected GoldKeyEnforcer");
    }
    const server = new Server(IMPLEMENTATION, {
      capabilities: { tools: { listChanged: false } },
      enforceStrictCapabilities: true,
    });
    downstreamServer = server;
    server.fallbackRequestHandler = async (request) => {
      throw new McpError(ErrorCode.MethodNotFound, `Unsupported guarded MCP method ${request.method}`);
    };
    // Unsupported downstream notifications are never forwarded upstream.
    server.fallbackNotificationHandler = async () => {};
    server.setRequestHandler(ListToolsRequestSchema, async (request) => {
      if (request.params?.cursor !== undefined) {
        throw new McpError(ErrorCode.InvalidParams, "The guarded tool snapshot has no pagination cursor");
      }
      return { tools };
    });
    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      if (request.params.task !== undefined) {
        throw new McpError(ErrorCode.MethodNotFound, "Task-augmented tools/call is not supported by this guarded proxy");
      }
      if (!toolNames.has(request.params.name)) {
        throw new McpError(ErrorCode.InvalidParams, "Tool is not in the operator-controlled guarded allowlist");
      }
      if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, "Guarded tool request was cancelled before enforcement");
      const idempotencyKey = requestIdempotencyKey(request);
      try {
        return await enforcer.guardMcpTool({
          connectorId: config.connector.id,
          tool: request.params.name,
          arguments: request.params.arguments ?? {},
          idempotencyKey,
        });
      } catch (error) {
        throw enforcementError(error);
      }
    });
    server.onerror = (error) => {
      safeLog(stderr, "downstream protocol error", error);
      close().catch((closeError) => safeLog(stderr, "close error", closeError));
    };
    server.onclose = () => {
      close().catch((closeError) => safeLog(stderr, "close error", closeError));
    };
    const downstreamTransport = transport ?? new StdioServerTransport(input, output, {
      maxBufferSize: config.upstream.max_message_bytes,
    });
    await server.connect(downstreamTransport);
    return Object.freeze({ tools, waitForClose: () => closedPromise });
  }

  return Object.freeze({
    config,
    connector,
    tools,
    serve,
    close,
    waitForClose: () => closedPromise,
  });
}
