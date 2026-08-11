#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  inspectAgentCashInvocation,
  loadAgentCashAdapterConfigFile,
  prepareAgentCashAdapter,
} from "../src/adapters/agentcash-mcp.mjs";
import { serveAgentCashGuardMcp } from "../src/adapters/agentcash-mcp-server.mjs";
import { InvalidInputError, LocalStateError } from "../src/errors.mjs";

const MAX_REQUEST_BYTES = 64 * 1024;

function usage() {
  return [
    "Usage:",
    "  goldkey-agentcash <combined-config.json>",
    "  goldkey-agentcash --inspect <combined-config.json> <request.json>",
    "",
    "Inspection is side-effect free. It prints the canonical Guard call, policy",
    "binding, and exact AgentCash MCP command/stdin without starting AgentCash,",
    "signing, authorizing, invoking a tool, or attempting either payment.",
  ].join("\n");
}

function safeMessage(error) {
  return (error instanceof Error ? error.message : String(error)).replace(/[\0\r\n]+/g, " ").slice(0, 2000);
}

async function loadInspectionRequest(filename) {
  if (typeof filename !== "string" || filename.length < 1) throw new InvalidInputError("An AgentCash inspection request filename is required");
  const resolved = path.resolve(filename);
  let metadata;
  try {
    metadata = await lstat(resolved);
  } catch (cause) {
    throw new LocalStateError(`Unable to inspect AgentCash request ${resolved}`, { cause });
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 2 || metadata.size > MAX_REQUEST_BYTES) {
    throw new LocalStateError(`AgentCash request ${resolved} must be a regular 2-${MAX_REQUEST_BYTES} byte non-symlink file`);
  }
  let document;
  try {
    document = JSON.parse(await readFile(resolved, "utf8"));
  } catch (cause) {
    throw new InvalidInputError(`AgentCash inspection request ${resolved} is not valid JSON`, { cause: cause.message });
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) throw new InvalidInputError("AgentCash inspection request must be an object");
  const extras = Object.keys(document).filter((key) => !new Set(["operation", "arguments", "idempotencyKey"]).has(key));
  if (extras.length > 0) throw new InvalidInputError("AgentCash inspection request contains unsupported fields", { fields: extras.sort() });
  return document;
}

export async function runAgentCashCli({
  argv = process.argv.slice(2),
  env = process.env,
  input = process.stdin,
  output = process.stdout,
  stderr = process.stderr,
  runtimeFactory,
  downstreamTransport,
  adapterFactory = prepareAgentCashAdapter,
} = {}) {
  if (!Array.isArray(argv)) throw new InvalidInputError("AgentCash launcher argv must be an array");
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0])) {
    output.write(usage() + "\n");
    return Object.freeze({ mode: "help" });
  }
  if (argv.length === 1) {
    if (typeof runtimeFactory !== "function") {
      throw new InvalidInputError("Normal AgentCash launch requires the shared GoldKey runtimeFactory integration");
    }
    const loaded = await loadAgentCashAdapterConfigFile(argv[0]);
    const adapter = await adapterFactory({ config: loaded.agentCashConfig, environment: env });
    const runtime = await runtimeFactory({
      configFilename: loaded.filename,
      document: loaded.document,
      agentCashConfig: loaded.agentCashConfig,
      connector: adapter.connector,
      env,
    });
    const enforcer = runtime?.enforcer ?? runtime;
    const server = await serveAgentCashGuardMcp({
      adapter,
      enforcer,
      ...(downstreamTransport ? { transport: downstreamTransport } : { input, output }),
      stderr,
    });
    try {
      await server.waitForClose();
      return Object.freeze({ mode: "serve" });
    } finally {
      await server.close();
    }
  }
  if (argv.length !== 3 || argv[0] !== "--inspect") throw new InvalidInputError(usage());
  const loaded = await loadAgentCashAdapterConfigFile(argv[1]);
  const request = await loadInspectionRequest(argv[2]);
  const report = inspectAgentCashInvocation({ config: loaded.agentCashConfig, ...request });
  output.write(JSON.stringify(report, null, 2) + "\n");
  return Object.freeze({ mode: "inspect", report });
}

function isDirectEntry() {
  if (!process.argv[1]) return false;
  try {
    return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
  } catch {
    return false;
  }
}

const direct = isDirectEntry();

if (direct) {
  const inspectionOrHelp = process.argv[2] === "--inspect" || ["--help", "-h"].includes(process.argv[2]);
  const runtimeFactory = inspectionOrHelp
    ? undefined
    : (await import("../src/adapters/runtime-factory.mjs")).createMcpAdapterRuntime;
  runAgentCashCli({ runtimeFactory }).catch((error) => {
    process.stderr.write(`goldkey-agentcash: ${safeMessage(error)}\n`);
    process.exitCode = 1;
  });
}
