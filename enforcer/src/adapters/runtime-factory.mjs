import path from "node:path";
import { InvalidInputError, LocalStateError } from "../errors.mjs";
import {
  GOLDKEY_GUARD_ORIGIN,
  createConfiguredGuardRuntime,
  loadGuardRuntimeConfig,
  normalizeGuardRuntimeConfig,
} from "./runtime.mjs";

function runtimeSection(document, filename) {
  if (!document || typeof document !== "object" || Array.isArray(document) || !Object.hasOwn(document, "runtime")) {
    throw new InvalidInputError("Combined adapter config must contain a runtime section");
  }
  return normalizeGuardRuntimeConfig(document.runtime, { configDirectory: path.dirname(path.resolve(filename)) });
}

export async function createMcpAdapterRuntime({
  configFilename,
  document,
  connector,
  agentCashConfig,
  env = process.env,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!connector || connector.kind !== "mcp_tool") {
    throw new InvalidInputError("MCP runtime requires one prepared operator-controlled MCP connector");
  }
  if (agentCashConfig !== undefined && agentCashConfig?.guard_origin !== GOLDKEY_GUARD_ORIGIN) {
    throw new InvalidInputError(`AgentCash guard_origin must be ${GOLDKEY_GUARD_ORIGIN}`);
  }
  return createConfiguredGuardRuntime({
    config: runtimeSection(document, configFilename),
    callKind: "network",
    connectors: [connector],
    env,
    fetchImpl,
  });
}

export async function createBaseWalletRuntime({
  walletConfig,
  evmConnectors,
  env = process.env,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!walletConfig?.filename || !Array.isArray(evmConnectors) || evmConnectors.length < 1) {
    throw new InvalidInputError("Base wallet runtime requires its loaded config and prepared EVM connectors");
  }
  const runtime = await createConfiguredGuardRuntime({
    config: await loadGuardRuntimeConfig(walletConfig.filename),
    callKind: "evm",
    connectors: evmConnectors,
    env,
    fetchImpl,
  });
  if (evmConnectors.some(({ from }) => from === runtime.payment.payer)) {
    throw new LocalStateError("Guard authorization payer and execution signer must be separate wallets");
  }
  return runtime;
}
