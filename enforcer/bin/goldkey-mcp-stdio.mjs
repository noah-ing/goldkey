#!/usr/bin/env node

import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  loadMcpStdioConfigFile,
  loadMcpStdioInspectionConfigFile,
} from "../src/adapters/mcp-stdio-config.mjs";
import {
  inspectMcpStdioUpstream,
  prepareMcpStdioProxy,
} from "../src/adapters/mcp-stdio-launcher.mjs";
import { InvalidInputError } from "../src/errors.mjs";

const INSPECTION_SCHEMA = "goldkey.mcp-stdio-inspection.v1";

function usage() {
  return [
    "Usage:",
    "  goldkey-mcp-stdio <config.yaml|config.json>",
    "  goldkey-mcp-stdio --inspect <config.yaml|config.json>",
    "",
    "--inspect starts the pinned upstream and sends initialize plus tools/list.",
    "GoldKey does not construct its runtime or authorizer, sign, pay, or invoke tools.",
  ].join("\n");
}

function fatalMessage(error) {
  const raw = error instanceof Error ? error.message : String(error);
  const bytes = Buffer.from(raw.slice(0, 4096), "utf8").subarray(0, 4096);
  const hash = createHash("sha256").update(bytes).digest("hex");
  return `failure_sha256=${hash} sampled_bytes=${bytes.byteLength} truncated=${raw.length > 4096 || bytes.byteLength === 4096}`;
}

/**
 * Shared-runtime entry point. Normal launch requires an injected runtimeFactory
 * so this adapter cannot accidentally create a second policy/payment runtime.
 */
export async function runMcpStdioCli({
  argv = process.argv.slice(2),
  env = process.env,
  input = process.stdin,
  output = process.stdout,
  stderr = process.stderr,
  runtimeFactory,
  downstreamTransport,
} = {}) {
  if (!Array.isArray(argv)) throw new InvalidInputError("MCP launcher argv must be an array");
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    output.write(`${usage()}\n`);
    return { mode: "help" };
  }
  if (argv[0] === "--inspect") {
    if (argv.length !== 2) throw new InvalidInputError("--inspect requires exactly one YAML/JSON config filename");
    const loaded = await loadMcpStdioInspectionConfigFile(argv[1], { env });
    const tools = await inspectMcpStdioUpstream({ config: loaded.mcpStdioConfig, stderr });
    const report = Object.freeze({
      schema: INSPECTION_SCHEMA,
      pinned_upstream_started: true,
      initialize_sent: true,
      tools_list_sent: true,
      goldkey_runtime_instantiated: false,
      goldkey_authorizer_instantiated: false,
      goldkey_authorization_attempted: false,
      goldkey_signing_attempted: false,
      goldkey_payment_attempted: false,
      goldkey_tool_calls_invoked: false,
      server_id: loaded.mcpStdioConfig.connector.server_id,
      tools,
    });
    output.write(`${JSON.stringify(report, null, 2)}\n`);
    return { mode: "inspect", report };
  }
  if (argv.length !== 1) throw new InvalidInputError("Normal MCP launch requires exactly one YAML/JSON config filename");
  if (typeof runtimeFactory !== "function") {
    throw new InvalidInputError("Normal MCP launch requires the shared GoldKey runtimeFactory integration");
  }

  const loaded = await loadMcpStdioConfigFile(argv[0], { env });
  const proxy = await prepareMcpStdioProxy({ config: loaded.mcpStdioConfig, stderr });
  let receivedSignal;
  const onSigint = () => {
    receivedSignal = "SIGINT";
    proxy.close().catch(() => {});
  };
  const onSigterm = () => {
    receivedSignal = "SIGTERM";
    proxy.close().catch(() => {});
  };
  process.once("SIGINT", onSigint);
  process.once("SIGTERM", onSigterm);
  try {
    const runtime = await runtimeFactory({
      configFilename: loaded.filename,
      document: loaded.document,
      mcpStdioConfig: loaded.mcpStdioConfig,
      connector: proxy.connector,
    });
    const enforcer = runtime?.enforcer ?? runtime;
    await proxy.serve({
      enforcer,
      ...(downstreamTransport ? { transport: downstreamTransport } : { input, output }),
    });
    await proxy.waitForClose();
    if (receivedSignal) process.exitCode = receivedSignal === "SIGINT" ? 130 : 143;
    return { mode: "serve", signal: receivedSignal };
  } catch (cause) {
    await proxy.close();
    throw cause;
  } finally {
    process.removeListener("SIGINT", onSigint);
    process.removeListener("SIGTERM", onSigterm);
  }
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
  runMcpStdioCli({ runtimeFactory }).catch((error) => {
    process.stderr.write(`goldkey-mcp-stdio: ${fatalMessage(error)}\n`);
    process.exitCode = 1;
  });
}
