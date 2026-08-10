import readline from "node:readline";
import { createChainService } from "../src/chain.mjs";
import { calculateQuote, renderCommerceResponse } from "../src/commerce.mjs";
import { loadConfig } from "../src/config.mjs";

const config = loadConfig();
const chain = createChainService(config);
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of input) {
  if (!line.trim()) continue;
  try {
    const request = JSON.parse(line);
    const supply = await chain.supplyState();
    const quote = calculateQuote(request, config, chain, supply);
    process.stdout.write(`${JSON.stringify({ ok: true, quote, sales_message: renderCommerceResponse(quote) })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, error: { code: error.code ?? "invalid_request", message: error.message } })}\n`);
  }
}
