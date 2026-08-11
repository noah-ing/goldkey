#!/usr/bin/env node

import { runBaseWalletCli, safeBaseWalletCliError } from "../src/adapters/base-wallet-cli.mjs";

async function main() {
  try {
    const runtimeFactory = process.argv[2] === "execute"
      ? (await import("../src/adapters/runtime-factory.mjs")).createBaseWalletRuntime
      : undefined;
    const outcome = await runBaseWalletCli({
      argv: process.argv.slice(2),
      runtimeFactory,
    });
    if (outcome.kind === "help") {
      process.stdout.write(outcome.text + "\n");
      return;
    }
    process.stdout.write(JSON.stringify({ ok: true, result: outcome.value }, null, 2) + "\n");
  } catch (error) {
    process.stderr.write(JSON.stringify(safeBaseWalletCliError(error)) + "\n");
    process.exitCode = 1;
  }
}

await main();
