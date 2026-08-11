import path from "node:path";
import { pathToFileURL } from "node:url";
import { InvalidInputError, LocalStateError } from "../errors.mjs";
import { createGuardedBaseWallet } from "./base-wallet.mjs";
import { loadBaseWalletConfig, readOperatorJsonFile } from "./base-wallet-config.mjs";
import { buildBaseWalletCall, probeBaseWalletRequest } from "./base-wallet-request.mjs";
import { createBaseWalletConnectorBindings } from "./base-wallet-signer.mjs";

export const BASE_WALLET_RUNTIME_ENV = "GOLDKEY_WALLET_RUNTIME_MODULE";

function parseArguments(argv) {
  if (!Array.isArray(argv)) throw new InvalidInputError("CLI arguments must be an array");
  if (argv.length === 1 && ["help", "--help", "-h"].includes(argv[0])) return Object.freeze({ command: "help" });
  const [command, ...rest] = argv;
  if (!new Set(["probe", "execute"]).has(command)) throw new InvalidInputError("Command must be probe or execute");
  const values = {};
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!new Set(["--config", "--request"]).has(flag) || typeof value !== "string" || value.startsWith("--")) {
      throw new InvalidInputError("Use --config <file> and --request <file>");
    }
    if (Object.hasOwn(values, flag)) throw new InvalidInputError(`${flag} may only be provided once`);
    values[flag] = value;
  }
  if (rest.length !== 4 || !values["--config"] || !values["--request"]) {
    throw new InvalidInputError("Use --config <file> and --request <file>");
  }
  return Object.freeze({ command, configPath: values["--config"], requestPath: values["--request"] });
}

export async function loadBaseWalletRuntimeFactory(env = process.env) {
  const specifier = env?.[BASE_WALLET_RUNTIME_ENV];
  if (typeof specifier !== "string" || specifier.length < 1 || specifier.length > 4096 || specifier.includes("\0")) {
    throw new LocalStateError(`Execute requires an absolute local runtime module path in ${BASE_WALLET_RUNTIME_ENV}`);
  }
  let resolved;
  if (specifier.startsWith("file:")) {
    let parsed;
    try {
      parsed = new URL(specifier);
    } catch {
      throw new LocalStateError(`${BASE_WALLET_RUNTIME_ENV} is not a valid file URL`);
    }
    if (parsed.protocol !== "file:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new LocalStateError(`${BASE_WALLET_RUNTIME_ENV} must be a local file URL without query or fragment`);
    }
    resolved = parsed.href;
  } else {
    if (!path.isAbsolute(specifier)) throw new LocalStateError(`${BASE_WALLET_RUNTIME_ENV} must be an absolute path or file URL`);
    resolved = pathToFileURL(specifier).href;
  }
  let runtime;
  try {
    runtime = await import(resolved);
  } catch (cause) {
    throw new LocalStateError("Unable to load the operator-owned GoldKey wallet runtime module", { cause });
  }
  const factory = runtime.createGoldKeyWalletRuntime ?? runtime.createBaseWalletRuntime;
  if (typeof factory !== "function") {
    throw new LocalStateError("Wallet runtime module must export createBaseWalletRuntime() or createGoldKeyWalletRuntime()");
  }
  return factory;
}

function resolveEnforcer(runtime) {
  const enforcer = runtime?.enforcer ?? runtime;
  if (!enforcer || typeof enforcer.guardEvmTransaction !== "function") {
    throw new LocalStateError("Wallet runtime factory did not return a configured GoldKey enforcer");
  }
  return enforcer;
}

export async function createExecutableBaseWallet({
  config,
  env = process.env,
  runtimeFactory,
  runtimeFactoryLoader = loadBaseWalletRuntimeFactory,
  connectorBindingsFactory = createBaseWalletConnectorBindings,
} = {}) {
  const connectorBindings = await connectorBindingsFactory({ config, env });
  const factory = runtimeFactory ?? await runtimeFactoryLoader(env);
  if (typeof factory !== "function") throw new LocalStateError("A GoldKey wallet runtime factory is required for execute");
  const runtime = await factory(Object.freeze({
    walletConfig: config,
    evmConnectors: connectorBindings.connectors,
    operatorPublicClient: connectorBindings.publicClient,
    env,
  }));
  return createGuardedBaseWallet({ config, enforcer: resolveEnforcer(runtime) });
}

function helpText() {
  return [
    "Usage:",
    "  goldkey-wallet probe   --config <operator.json> --request <request.json>",
    "  goldkey-wallet execute --config <operator.json> --request <request.json>",
    "",
    "probe performs local validation only: it does not load a signer, call RPC, authorize, pay, sign, or broadcast.",
    "The packaged launcher uses GoldKey's shared runtime from the same combined config.",
    `Library callers may override it with an operator module named by ${BASE_WALLET_RUNTIME_ENV}.`,
  ].join("\n");
}

export async function runBaseWalletCli({
  argv,
  env = process.env,
  runtimeFactory,
  runtimeFactoryLoader = loadBaseWalletRuntimeFactory,
  connectorBindingsFactory = createBaseWalletConnectorBindings,
} = {}) {
  const parsed = parseArguments(argv);
  if (parsed.command === "help") return Object.freeze({ kind: "help", text: helpText() });

  const config = await loadBaseWalletConfig(parsed.configPath);
  const request = await readOperatorJsonFile(parsed.requestPath, {
    name: "Base wallet request",
    maximumBytes: 64 * 1024,
  });
  if (parsed.command === "probe") {
    return Object.freeze({ kind: "result", value: probeBaseWalletRequest({ config, request }) });
  }

  // Reject malformed, over-cap, or non-allowlisted operations before the
  // process ever opens the signer or contacts an RPC/runtime.
  buildBaseWalletCall({ config, request });
  const wallet = await createExecutableBaseWallet({
    config,
    env,
    runtimeFactory,
    runtimeFactoryLoader,
    connectorBindingsFactory,
  });
  return Object.freeze({ kind: "result", value: await wallet.execute(request) });
}

export function safeBaseWalletCliError(error) {
  return Object.freeze({
    ok: false,
    code: typeof error?.code === "string" ? error.code : "wallet_error",
    message: typeof error?.message === "string" ? error.message : "Base wallet command failed",
  });
}
