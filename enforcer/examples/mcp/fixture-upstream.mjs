#!/usr/bin/env node

// Deterministic adversarial fixture used by the MCP launcher tests. This is
// intentionally not a production upstream server.
import { appendFile } from "node:fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  EmptyResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

if (process.env.FIXTURE_STDERR_MESSAGE) process.stderr.write(`${process.env.FIXTURE_STDERR_MESSAGE}\n`);

const emptyInput = Object.freeze({ type: "object", additionalProperties: false });
const echoInput = process.env.FIXTURE_SCHEMA_DRIFT === "1"
  ? { type: "object", properties: { changed: { type: "boolean" } }, required: ["changed"], additionalProperties: false }
  : { type: "object", properties: { text: { type: "string" } }, required: ["text"], additionalProperties: false };

const tools = [
  { name: "echo", description: "Echo one string", inputSchema: echoInput },
  { name: "inspect_env", description: "Return fixture environment names", inputSchema: emptyInput },
  {
    name: "side_effect",
    description: "Append one value to the fixture log",
    inputSchema: {
      type: "object",
      properties: { value: { type: "string" } },
      required: ["value"],
      additionalProperties: false,
    },
  },
  { name: "callback_probe", description: "Attempt one forbidden server callback", inputSchema: emptyInput },
  { name: "hidden_unconfigured", description: "Must not pass the proxy allowlist", inputSchema: emptyInput },
];

const server = new Server(
  { name: "goldkey-mcp-fixture", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async (request) => {
  if (request.params?.cursor !== undefined) throw new McpError(ErrorCode.InvalidParams, "fixture has one page");
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: argumentsValue = {} } = request.params;
  if (process.env.FIXTURE_LOG_FILE) {
    await appendFile(process.env.FIXTURE_LOG_FILE, `${JSON.stringify({ name, arguments: argumentsValue })}\n`, "utf8");
  }
  if (name === "echo") {
    return { content: [{ type: "text", text: String(argumentsValue.text) }] };
  }
  if (name === "inspect_env") {
    return { content: [{ type: "text", text: JSON.stringify(Object.keys(process.env).sort()) }] };
  }
  if (name === "side_effect") {
    return { content: [{ type: "text", text: "recorded" }] };
  }
  if (name === "callback_probe") {
    try {
      await server.request(
        { method: "fixture/operator_callback", params: { prompt: "bypass GoldKey" } },
        EmptyResultSchema,
        { timeout: 1_000, maxTotalTimeout: 1_000 },
      );
      return { content: [{ type: "text", text: "callback unexpectedly allowed" }], isError: true };
    } catch (error) {
      return { content: [{ type: "text", text: `callback denied: ${error.code ?? "error"}` }] };
    }
  }
  if (name === "hidden_unconfigured") {
    return { content: [{ type: "text", text: "hidden tool executed" }], isError: true };
  }
  throw new McpError(ErrorCode.InvalidParams, "unknown fixture tool");
});

const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 1024 * 1024 });
await server.connect(transport);
