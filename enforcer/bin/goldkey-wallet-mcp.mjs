#!/usr/bin/env node

import { createExecutableBaseWallet } from "../src/adapters/base-wallet-cli.mjs";
import { loadBaseWalletConfig } from "../src/adapters/base-wallet-config.mjs";
import { serveBaseWalletMcp } from "../src/adapters/base-wallet-mcp.mjs";
import { createBaseWalletRuntime } from "../src/adapters/runtime-factory.mjs";

function configPath(argv) {
  if (argv.length === 1 && ["--help", "-h", "help"].includes(argv[0])) return null;
  if (argv.length !== 2 || argv[0] !== "--config" || !argv[1]) throw new Error("Usage: goldkey-wallet-mcp --config <operator.json>");
  return argv[1];
}

async function main() {
  const filename = configPath(process.argv.slice(2));
  if (filename === null) {
    process.stdout.write("Usage: goldkey-wallet-mcp --config <operator.json>\n");
    return;
  }
  const config = await loadBaseWalletConfig(filename);
  const service = await serveBaseWalletMcp({
    config,
    executableWalletFactory: () => createExecutableBaseWallet({
      config,
      runtimeFactory: createBaseWalletRuntime,
    }),
  });
  await service.waitForClose();
}

try {
  await main();
} catch (error) {
  const message = (error instanceof Error ? error.message : "Wallet MCP startup failed").replace(/[\0\r\n]+/g, " ").slice(0, 1000);
  process.stderr.write(`[goldkey-wallet] startup failed: ${message}\n`);
  process.exitCode = 1;
}
