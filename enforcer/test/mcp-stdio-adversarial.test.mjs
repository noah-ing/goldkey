import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { Writable } from "node:stream";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { runMcpStdioCli } from "../bin/goldkey-mcp-stdio.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import { AuthorizationDeniedError, InvalidInputError } from "../src/errors.mjs";
import {
  normalizeMcpStdioConfig,
  normalizeMcpStdioInspectionConfig,
} from "../src/adapters/mcp-stdio-config.mjs";
import {
  inspectMcpStdioUpstream,
  prepareMcpStdioProxy,
} from "../src/adapters/mcp-stdio-launcher.mjs";

test("npm-style symlink invokes the MCP binary instead of silently importing it", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-mcp-bin-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const link = path.join(directory, "goldkey-mcp-stdio");
  await symlink(fileURLToPath(new URL("../bin/goldkey-mcp-stdio.mjs", import.meta.url)), link);
  const result = spawnSync(process.execPath, [link, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /goldkey-mcp-stdio --inspect/);
});

function discardStream() {
  return new Writable({ write(_chunk, _encoding, callback) { callback(); } });
}

function collectingStream() {
  let value = "";
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      value += chunk.toString("utf8");
      callback();
    },
  });
  return { stream, value: () => value };
}

function rawConfig({ tools = [], env = {} } = {}) {
  return {
    schema: "goldkey.mcp-stdio-launcher.v1",
    connector: { id: "adversarial-fixture", server_id: "fixture-upstream", tools },
    upstream: {
      command: process.execPath,
      args: [path.resolve("examples/mcp/fixture-upstream.mjs")],
      cwd: process.cwd(),
      env,
      startup_timeout_ms: 5000,
      max_message_bytes: 1024 * 1024,
    },
  };
}

async function fixtureHashes() {
  const report = await inspectMcpStdioUpstream({
    config: normalizeMcpStdioInspectionConfig(rawConfig()),
    stderr: discardStream(),
  });
  return new Map(report.map((entry) => [entry.name, entry.input_schema_sha256]));
}

test("inspection performs tools/list only and never constructs a runtime or calls a tool", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-mcp-inspect-cli-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "inspect.json");
  await writeFile(filename, JSON.stringify(rawConfig()), { mode: 0o600 });
  let runtimeCalls = 0;
  const output = collectingStream();
  const result = await runMcpStdioCli({
    argv: ["--inspect", filename],
    output: output.stream,
    stderr: discardStream(),
    runtimeFactory: async () => { runtimeCalls += 1; throw new Error("must not run"); },
  });
  assert.equal(result.mode, "inspect");
  assert.equal(runtimeCalls, 0);
  const report = JSON.parse(output.value());
  assert.equal(report.pinned_upstream_started, true);
  assert.equal(report.initialize_sent, true);
  assert.equal(report.tools_list_sent, true);
  assert.equal(report.goldkey_runtime_instantiated, false);
  assert.equal(report.goldkey_authorizer_instantiated, false);
  assert.equal(report.goldkey_authorization_attempted, false);
  assert.equal(report.goldkey_signing_attempted, false);
  assert.equal(report.goldkey_payment_attempted, false);
  assert.equal(report.goldkey_tool_calls_invoked, false);
  assert.equal(report.tools.some(({ name }) => name === "echo"), true);
  assert.match(report.tools[0].input_schema_sha256, /^[0-9a-f]{64}$/);

  await assert.rejects(
    () => runMcpStdioCli({ argv: [filename], stderr: discardStream() }),
    /shared GoldKey runtimeFactory/,
  );
});

test("inspection API has no callTool dependency", async () => {
  let listCalls = 0;
  let toolCalls = 0;
  const inputSchema = { type: "object", additionalProperties: false };
  const fakeClient = {
    async connect() {},
    async listTools() {
      listCalls += 1;
      return { tools: [{ name: "safe", inputSchema }] };
    },
    async callTool() { toolCalls += 1; throw new Error("inspection called a tool"); },
    async close() {},
  };
  const fakeTransport = { async start() {}, async close() {}, async send() {} };
  const report = await inspectMcpStdioUpstream({
    config: normalizeMcpStdioInspectionConfig(rawConfig()),
    stderr: discardStream(),
    clientFactory: async () => fakeClient,
    upstreamTransportFactory: async () => fakeTransport,
  });
  assert.deepEqual(report, [{ name: "safe", input_schema_sha256: canonicalSha256(inputSchema) }]);
  assert.equal(listCalls, 1);
  assert.equal(toolCalls, 0);
});

test("upstream input-schema drift stops startup before a downstream server exists", async () => {
  const hashes = await fixtureHashes();
  const config = normalizeMcpStdioConfig(rawConfig({
    tools: [{ name: "echo", effect: "read", input_schema_sha256: hashes.get("echo") }],
    env: { FIXTURE_SCHEMA_DRIFT: { value: "1" } },
  }));
  await assert.rejects(
    () => prepareMcpStdioProxy({ config, stderr: discardStream() }),
    (error) => error instanceof InvalidInputError && /schema hash does not match/.test(error.message),
  );
});

test("required-task tools are rejected because the proxy cannot preserve synchronous lifecycle semantics", async () => {
  const inputSchema = { type: "object", additionalProperties: false };
  const config = normalizeMcpStdioConfig(rawConfig({
    tools: [{ name: "required_task", effect: "execute", input_schema_sha256: canonicalSha256(inputSchema) }],
  }));
  const fakeClient = {
    async connect() {},
    async listTools() {
      return { tools: [{ name: "required_task", inputSchema, execution: { taskSupport: "required" } }] };
    },
    async callTool() { throw new Error("must not call"); },
    async close() {},
  };
  const fakeTransport = { async start() {}, async close() {}, async send() {} };
  await assert.rejects(
    () => prepareMcpStdioProxy({
      config,
      stderr: discardStream(),
      clientFactory: async () => fakeClient,
      upstreamTransportFactory: async () => fakeTransport,
    }),
    /requires unsupported task execution/,
  );
});

test("missing or malformed durable idempotency and policy denial fail before any upstream invocation", async (t) => {
  const hashes = await fixtureHashes();
  const config = normalizeMcpStdioConfig(rawConfig({
    tools: [{ name: "echo", effect: "read", input_schema_sha256: hashes.get("echo") }],
  }));
  const proxy = await prepareMcpStdioProxy({ config, stderr: discardStream() });
  t.after(() => proxy.close());
  let guardedCalls = 0;
  const denyingEnforcer = {
    async guardMcpTool() {
      guardedCalls += 1;
      throw new AuthorizationDeniedError();
    },
  };
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await proxy.serve({ enforcer: denyingEnforcer, transport: serverTransport });
  const downstream = new Client({ name: "adversary", version: "1.0.0" }, { capabilities: {} });
  await downstream.connect(clientTransport);
  t.after(() => downstream.close());

  await assert.rejects(
    () => downstream.callTool({ name: "echo", arguments: { text: "no durable identity" } }),
    (error) => error.code === ErrorCode.InvalidParams && /durable explicit/.test(error.message),
  );
  assert.equal(guardedCalls, 0);

  await assert.rejects(
    () => downstream.callTool({
      name: "echo",
      arguments: { text: "bad id" },
      _meta: { "com.goldkey/idempotency-key": "contains spaces" },
    }),
    (error) => error.code === ErrorCode.InvalidParams,
  );
  assert.equal(guardedCalls, 0);

  await assert.rejects(
    () => downstream.callTool({
      name: "echo",
      arguments: { text: "denied" },
      _meta: { "com.goldkey/idempotency-key": "denied-call-0001" },
    }),
    (error) => error.code === -32003 && error.data?.code === "authorization_denied",
  );
  assert.equal(guardedCalls, 1);
});

test("upstream stderr is drained as bounded hashes without raw content", async () => {
  const secret = "UPSTREAM-STDERR-MUST-NOT-REACH-OPERATOR";
  const stderr = collectingStream();
  await inspectMcpStdioUpstream({
    config: normalizeMcpStdioInspectionConfig(rawConfig({
      env: { FIXTURE_STDERR_MESSAGE: { value: secret } },
    })),
    stderr: stderr.stream,
  });
  assert.equal(stderr.value().includes(secret), false);
  assert.match(stderr.value(), /upstream stderr: count=1 sha256=[0-9a-f]{64} sampled_bytes=\d+ truncated=false/);
});

test("upstream protocol errors are logged as bounded hashes without raw content", async () => {
  const secret = "UPSTREAM-PROTOCOL-MUST-NOT-REACH-OPERATOR";
  const stderr = collectingStream();
  const inputSchema = { type: "object", additionalProperties: false };
  const fakeClient = {
    async connect() { this.onerror?.(new Error(secret)); },
    async listTools() { return { tools: [{ name: "safe", inputSchema }] }; },
    async close() {},
  };
  const fakeTransport = { async start() {}, async close() {}, async send() {} };
  await inspectMcpStdioUpstream({
    config: normalizeMcpStdioInspectionConfig(rawConfig()),
    stderr: stderr.stream,
    clientFactory: async () => fakeClient,
    upstreamTransportFactory: async () => fakeTransport,
  });
  assert.equal(stderr.value().includes(secret), false);
  assert.match(stderr.value(), /inspection protocol error: count=1 sha256=[0-9a-f]{64} sampled_bytes=\d+ truncated=false/);
});
