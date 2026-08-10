import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { calculateQuote, calculateRenewalQuote } from "../src/commerce.mjs";

const config = { termDays: 365, callsPerTerm: 10_000, contractAddress: "0x0000000000000000000000000000000000000001", usdcAddress: "0x0000000000000000000000000000000000000002", chainId: 8453, publicOrigin: "https://goldkey.example" };
const chain = { purchaseTransactions: (_wallet, quantity) => [{ quantity: Number(quantity) }] };

test("quote selects paygo below break-even", () => {
  const quote = calculateQuote({ forecast_calls: 3000 }, config, chain);
  assert.equal(quote.recommendation, "PAYGO");
  assert.equal(quote.paygo_cost_usdc, "30.00");
  assert.equal(quote.key_count, 0);
  assert.equal(quote.next_action, "USE_PAYGO");
  const soldOut = calculateQuote({ forecast_calls: 10_000 }, config, chain, 0);
  assert.equal(soldOut.key_count, 0);
  assert.ok(soldOut.reason_codes.includes("primary_supply_exhausted"));
});

test("quote selects one key above break-even", () => {
  const quote = calculateQuote({ forecast_calls: 7200 }, config, chain);
  assert.equal(quote.recommendation, "BUY_1_KEY");
  assert.equal(quote.key_purchase_cost_usdc, "50.00");
  assert.equal(quote.optimized_total_cost_usdc, "50.00");
  assert.equal(quote.raw_savings_usdc, "22.00");
  assert.equal(quote.next_action, "PROVIDE_WALLET");
  assert.deepEqual(quote.unsigned_transactions, []);
});

test("quote optimizes multiple keys and respects risk costs", () => {
  const two = calculateQuote({ forecast_calls: 18_200 }, config, chain);
  assert.equal(two.key_count, 2);
  assert.equal(two.key_purchase_cost_usdc, "100.00");
  assert.equal(two.optimized_total_cost_usdc, "100.00");
  assert.equal(two.raw_savings_usdc, "82.00");

  const hybrid = calculateQuote({ forecast_calls: 12_000 }, config, chain);
  assert.equal(hybrid.key_count, 1);
  assert.equal(hybrid.key_purchase_cost_usdc, "50.00");
  assert.equal(hybrid.overflow_paygo_cost_usdc, "20.00");
  assert.equal(hybrid.optimized_total_cost_usdc, "70.00");

  const risk = calculateQuote({ forecast_calls: 5200, switching_cost_usdc: "1.00", risk_reserve_usdc: "2.00" }, config, chain);
  assert.equal(risk.recommendation, "TRIAL");
  assert.equal(risk.next_action, "MEASURE_USAGE");
  assert.deepEqual(risk.unsigned_transactions, []);
});

test("quote emits transaction-ready batches only when wallet is supplied", () => {
  const quote = calculateQuote({ forecast_calls: 210_000, wallet: "0x000000000000000000000000000000000000dEaD", purchase_authority: false }, config, chain);
  assert.equal(quote.key_count, 21);
  assert.deepEqual(quote.unsigned_transactions, [
    { quantity: 20, sequence: 1, depends_on: [] },
    { quantity: 1, sequence: 2, depends_on: [1] },
  ]);
  assert.equal(quote.authorization_status, "INFO_ONLY");
  assert.equal(quote.next_action, "OBTAIN_PURCHASE_AUTHORITY");

  const authorized = calculateQuote({ forecast_calls: 7200, wallet: "0x000000000000000000000000000000000000dEaD", purchase_authority: true }, config, chain);
  assert.equal(authorized.next_action, "SIGN_UNSIGNED_TRANSACTIONS");
  const authorityWithoutWallet = calculateQuote({ forecast_calls: 7200, purchase_authority: true }, config, chain);
  assert.equal(authorityWithoutWallet.next_action, "PROVIDE_WALLET");
});

test("quote respects paused sales, live fields, and pass-purchase budget", () => {
  const supply = {
    totalMinted: "10",
    remaining: "9990",
    blockNumber: "123",
    mintPriceAtomic: "50000000",
    paymentToken: "0x0000000000000000000000000000000000000002",
    paymentTokenDecimals: 6,
    termsHash: "0xterms",
    termsUri: "https://example.com/terms",
    salesPaused: true,
  };
  const paused = calculateQuote({ forecast_calls: 7200 }, config, chain, supply);
  assert.equal(paused.key_count, 0);
  assert.ok(paused.reason_codes.includes("primary_sales_paused"));
  assert.equal(paused.supply_block_number, "123");
  assert.equal(paused.payment_token_decimals, 6);

  const budgeted = calculateQuote({ forecast_calls: 18_200, pass_purchase_budget_usdc: "50.00" }, config, chain);
  assert.equal(budgeted.key_count, 1);
  assert.equal(budgeted.overflow_paygo_calls, 8200);
});

test("renewal quote waits for expiry and only emits transactions for a qualified expired term", () => {
  const renewalChain = { renewalTransactions: (tokenId) => [{ tokenId }] };
  const pass = {
    tokenId: "7",
    owner: "0x000000000000000000000000000000000000dEaD",
    term: "2",
    ownershipEpoch: "1",
    expiresAt: Date.now() + 86_400_000,
    active: true,
  };
  const waiting = calculateRenewalQuote({ forecast_calls: 7200 }, config, renewalChain, pass);
  assert.equal(waiting.recommendation, "RENEW_AFTER_EXPIRY");
  assert.equal(waiting.next_action, "WAIT_UNTIL_EXPIRY");
  assert.deepEqual(waiting.unsigned_transactions, []);

  const expired = calculateRenewalQuote({ forecast_calls: 7200, wallet: pass.owner, purchase_authority: true }, config, renewalChain, { ...pass, active: false, expiresAt: Date.now() - 1000 });
  assert.equal(expired.recommendation, "RENEW_NOW");
  assert.equal(expired.next_action, "SIGN_UNSIGNED_TRANSACTIONS");
  assert.deepEqual(expired.unsigned_transactions, [{ tokenId: "7", sequence: 1, depends_on: [] }]);
});

test("a live BUY quote with an ordered transaction plan validates against the published schema", () => {
  const schema = JSON.parse(readFileSync(new URL("../agent/goldkey-commerce-response.schema.json", import.meta.url), "utf8"));
  const ajv = new Ajv2020({ strict: true });
  addFormats(ajv);
  const quote = calculateQuote({ forecast_calls: 7200, wallet: "0x000000000000000000000000000000000000dEaD" }, config, {
    purchasePlanTransactions: () => [{
      sequence: 1,
      batch_index: null,
      depends_on: [],
      purpose: "Approve the exact total USDC purchase amount",
      to: config.usdcAddress,
      value: "0",
      data: "0x1234",
      asset_amount_atomic: "50000000",
    }],
  }, {
    totalMinted: "7",
    remaining: "9993",
    blockNumber: "123",
    mintPriceAtomic: "50000000",
    paymentToken: config.usdcAddress,
    paymentTokenDecimals: 6,
    termsHash: `0x${"ab".repeat(32)}`,
    termsUri: "https://goldkey.example/terms",
    salesPaused: false,
  });
  const validate = ajv.compile(schema);
  assert.equal(validate(quote), true, JSON.stringify(validate.errors));
});
