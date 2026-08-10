import { randomUUID } from "node:crypto";
import { getAddress, isAddress } from "viem";
import { ServiceError, assert } from "./errors.mjs";

function parseUsdToCents(value, name, fallback = 0) {
  if (value === undefined) return fallback;
  const text = String(value);
  assert(/^\d+(?:\.\d{1,2})?$/.test(text), 400, "invalid_money", `${name} must be a non-negative USDC amount with at most two decimals`);
  const [whole, fraction = ""] = text.split(".");
  const cents = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  assert(cents <= BigInt(Number.MAX_SAFE_INTEGER), 400, "money_too_large", `${name} is too large`);
  return Number(cents);
}

function cents(value) {
  return (value / 100).toFixed(2);
}

function normalizedSupply(state) {
  const supplied = typeof state === "object" && state !== null
    ? state
    : { remaining: state ?? 10_000 };
  const remaining = Number(supplied.remaining);
  assert(Number.isSafeInteger(remaining) && remaining >= 0, 503, "invalid_supply_state", "Onchain remaining supply is invalid");
  return {
    remaining,
    totalMinted: supplied.totalMinted === undefined ? undefined : String(supplied.totalMinted),
    termsHash: supplied.termsHash,
    termsUri: supplied.termsUri,
    blockNumber: supplied.blockNumber === undefined ? undefined : String(supplied.blockNumber),
    mintPriceAtomic: supplied.mintPriceAtomic === undefined ? "50000000" : String(supplied.mintPriceAtomic),
    paymentToken: supplied.paymentToken,
    paymentTokenDecimals: supplied.paymentTokenDecimals ?? 6,
    salesPaused: supplied.salesPaused === true,
  };
}

function actionFor(recommendation, hasWallet, authority) {
  if (recommendation === "TRIAL" || recommendation === "DO_NOT_BUY") return "MEASURE_USAGE";
  if (!recommendation.startsWith("BUY_")) return "USE_PAYGO";
  if (!hasWallet) return "PROVIDE_WALLET";
  if (!authority) return "OBTAIN_PURCHASE_AUTHORITY";
  return "SIGN_UNSIGNED_TRANSACTIONS";
}

function sequenceTransactions(transactions) {
  return transactions.map((transaction, index) => ({
    ...transaction,
    sequence: index + 1,
    depends_on: index === 0 ? [] : [index],
  }));
}

export function calculateQuote(input, config, chain, supplyState = 10_000) {
  assert(input && typeof input === "object" && !Array.isArray(input), 400, "invalid_input", "request must be an object");
  const forecastCalls = Number(input.forecast_calls);
  assert(Number.isSafeInteger(forecastCalls) && forecastCalls >= 0 && forecastCalls <= 10_000_000, 400, "invalid_forecast", "forecast_calls must be an integer from 0 to 10,000,000");
  const switchingCost = parseUsdToCents(input.switching_cost_usdc, "switching_cost_usdc");
  const riskReserve = parseUsdToCents(input.risk_reserve_usdc, "risk_reserve_usdc");
  const budgetValue = input.pass_purchase_budget_usdc ?? input.budget_usdc;
  const budget = parseUsdToCents(budgetValue, "pass_purchase_budget_usdc", 1_000_000_00);
  const supply = normalizedSupply(supplyState);
  const supplyLimit = supply.remaining;
  const maxKeys = supply.salesPaused
    ? 0
    : Math.min(supplyLimit, 1000, Math.floor(budget / 5000), Math.ceil(forecastCalls / 10_000) + 1);
  const paygoCost = forecastCalls;

  let best = { keys: 0, cost: paygoCost };
  for (let keys = 1; keys <= maxKeys; keys += 1) {
    const overflowCalls = Math.max(0, forecastCalls - keys * 10_000);
    const cost = keys * 5000 + overflowCalls;
    if (cost < best.cost) best = { keys, cost };
  }
  const rawSavings = paygoCost - best.cost;
  const passPurchaseCost = best.keys * 5000;
  const overflowPaygoCost = best.cost - passPurchaseCost;
  const riskAdjustedSavings = rawSavings - switchingCost - riskReserve;
  const authority = input.purchase_authority === true;
  let recommendation = "PAYGO";
  if (best.keys > 0 && riskAdjustedSavings > 0) recommendation = `BUY_${best.keys}_KEY${best.keys === 1 ? "" : "S"}`;
  if (forecastCalls === 0) recommendation = "DO_NOT_BUY";
  if (best.keys > 0 && riskAdjustedSavings <= 0) recommendation = "TRIAL";

  let wallet;
  const hasWallet = input.wallet !== undefined;
  if (hasWallet) {
    if (!isAddress(input.wallet)) throw new ServiceError(400, "invalid_wallet", "wallet must be an EVM address");
    wallet = getAddress(input.wallet);
  }
  const nextAction = actionFor(recommendation, hasWallet, authority);
  let unsignedTransactions = [];
  if (recommendation.startsWith("BUY_") && wallet) {
    if (typeof chain.purchasePlanTransactions === "function") {
      unsignedTransactions = chain.purchasePlanTransactions(wallet, best.keys);
    } else {
      let remaining = best.keys;
      while (remaining > 0) {
        const batch = Math.min(20, remaining);
        unsignedTransactions.push(...chain.purchaseTransactions(wallet, batch));
        remaining -= batch;
      }
      unsignedTransactions = sequenceTransactions(unsignedTransactions);
    }
  }

  const quoteCreatedAt = new Date();
  const quoteValidUntil = new Date(quoteCreatedAt.getTime() + 5 * 60_000);
  const reasonCodes = [
    ...(supply.salesPaused ? ["primary_sales_paused"] : []),
    ...(!supply.salesPaused && supplyLimit === 0 ? ["primary_supply_exhausted"] : []),
    ...(best.keys === 0 ? ["paygo_is_cheaper_or_equal"] : ["pass_reduces_expected_cost"]),
    ...(riskAdjustedSavings <= 0 ? ["risk_adjusted_savings_not_positive"] : []),
  ];

  return {
    schema: "goldkey.commerce-response.v1",
    quote_id: randomUUID(),
    quote_created_at: quoteCreatedAt.toISOString(),
    quote_valid_until: quoteValidUntil.toISOString(),
    recommendation,
    reason_codes: [...new Set(reasonCodes)],
    assumptions: ["Each eligible call costs 0.01 USDC on paygo.", "Each GoldKey costs 50 USDC and includes 10,000 calls for one 365-day term.", "Network gas and switching costs are excluded unless supplied."],
    paygo_cost_usdc: cents(paygoCost),
    key_count: best.keys,
    key_purchase_cost_usdc: cents(passPurchaseCost),
    overflow_paygo_calls: overflowPaygoCost,
    overflow_paygo_cost_usdc: cents(overflowPaygoCost),
    optimized_total_cost_usdc: cents(best.cost),
    raw_savings_usdc: cents(rawSavings),
    risk_adjusted_savings_usdc: cents(riskAdjustedSavings),
    break_even_calls: 5000,
    forecast_calls: forecastCalls,
    term_days: config.termDays,
    included_calls_per_key: config.callsPerTerm,
    contract: config.contractAddress,
    chain_id: config.chainId,
    supply_remaining: supplyLimit,
    supply_total_minted: supply.totalMinted,
    supply_block_number: supply.blockNumber,
    sales_paused: supply.salesPaused,
    onchain_mint_price_atomic: supply.mintPriceAtomic,
    payment_token: supply.paymentToken ?? config.usdcAddress,
    payment_token_decimals: supply.paymentTokenDecimals,
    terms_hash: supply.termsHash,
    terms_uri: supply.termsUri ?? `${config.publicOrigin}/terms`,
    response_schema_url: `${config.publicOrigin}/schemas/commerce-response-v1.json`,
    authorization_status: authority ? "DECLARED_AUTHORIZED" : "INFO_ONLY",
    next_action: nextAction,
    unsigned_transactions: unsignedTransactions,
  };
}

export function renderCommerceResponse(quote) {
  if (quote.key_count > 0 && quote.recommendation.startsWith("BUY_")) {
    const overflow = quote.overflow_paygo_calls > 0 ? ` Remaining overflow is ${quote.overflow_paygo_calls.toLocaleString("en-US")} paygo calls costing ${quote.overflow_paygo_cost_usdc} USDC, for ${quote.optimized_total_cost_usdc} USDC total.` : "";
    const transactionMessage = quote.next_action === "PROVIDE_WALLET"
      ? "Provide the purchasing wallet to generate exact unsigned transactions."
      : quote.next_action === "OBTAIN_PURCHASE_AUTHORITY"
      ? "Exact unsigned transactions are included, but purchase authority must be obtained before signing."
      : "Exact ordered unsigned transactions are included for the authorized wallet to sign.";
    return `Your forecast is ${quote.forecast_calls.toLocaleString("en-US")} eligible calls before expiration. Paygo would cost ${quote.paygo_cost_usdc} USDC. ${quote.key_count} GoldKey${quote.key_count === 1 ? "" : "s"} ${quote.key_count === 1 ? "costs" : "cost"} ${quote.key_purchase_cost_usdc} USDC.${overflow} Projected savings are ${quote.raw_savings_usdc} USDC before supplied risk costs. Break-even is 5,000 calls per key. Recommendation: ${quote.recommendation}. ${transactionMessage}`;
  }
  if (quote.recommendation === "TRIAL") {
    return `The forecast does not justify a risk-adjusted 50 USDC purchase yet. Paygo costs ${quote.paygo_cost_usdc} USDC and the optimized pass-plus-overflow mix costs ${quote.optimized_total_cost_usdc} USDC before switching cost and reserve. Recommendation: TRIAL or PAYGO, then recalculate after measured usage changes.`;
  }
  if (quote.recommendation === "DO_NOT_BUY") {
    return "Do not buy GoldKey without expected eligible usage. Recommendation: DO_NOT_BUY. Use the fixed public demo or paygo first.";
  }
  return `Do not buy GoldKey for this forecast. At ${quote.forecast_calls.toLocaleString("en-US")} calls, paygo costs ${quote.paygo_cost_usdc} USDC versus 50.00 USDC for one key. Recommendation: PAYGO. Recalculate if the remaining-term forecast exceeds 5,000 calls.`;
}

export function calculateRenewalQuote(input, config, chain, pass) {
  assert(input && typeof input === "object" && !Array.isArray(input), 400, "invalid_input", "request must be an object");
  const forecastCalls = Number(input.forecast_calls);
  assert(Number.isSafeInteger(forecastCalls) && forecastCalls >= 0 && forecastCalls <= 10_000_000, 400, "invalid_forecast", "forecast_calls must be an integer from 0 to 10,000,000");
  const switchingCost = parseUsdToCents(input.switching_cost_usdc, "switching_cost_usdc");
  const riskReserve = parseUsdToCents(input.risk_reserve_usdc, "risk_reserve_usdc");
  const paygoCost = forecastCalls;
  const overflowCalls = Math.max(0, forecastCalls - config.callsPerTerm);
  const renewalMixCost = 5000 + overflowCalls;
  const rawSavings = paygoCost - renewalMixCost;
  const riskAdjustedSavings = rawSavings - switchingCost - riskReserve;
  const economicallyQualified = rawSavings > 0 && riskAdjustedSavings > 0;
  const authority = input.purchase_authority === true;
  let wallet;
  if (input.wallet !== undefined) {
    if (!isAddress(input.wallet)) throw new ServiceError(400, "invalid_wallet", "wallet must be an EVM address");
    wallet = getAddress(input.wallet);
    assert(wallet === getAddress(pass.owner), 403, "not_current_owner", "wallet must be the current GoldKey owner");
  }

  let recommendation = forecastCalls === 0 ? "DO_NOT_RENEW" : economicallyQualified ? (pass.active ? "RENEW_AFTER_EXPIRY" : "RENEW_NOW") : rawSavings > 0 ? "MEASURE_USAGE" : "USE_PAYGO";
  let nextAction = recommendation === "RENEW_AFTER_EXPIRY"
    ? "WAIT_UNTIL_EXPIRY"
    : recommendation === "RENEW_NOW"
    ? !wallet
      ? "PROVIDE_WALLET"
      : !authority
      ? "OBTAIN_RENEWAL_AUTHORITY"
      : "SIGN_UNSIGNED_TRANSACTIONS"
    : recommendation === "USE_PAYGO"
    ? "USE_PAYGO"
    : "MEASURE_USAGE";
  let transactions = [];
  if (recommendation === "RENEW_NOW" && wallet) {
    transactions = sequenceTransactions(chain.renewalTransactions(pass.tokenId));
  }

  const now = new Date();
  return {
    schema: "goldkey.renewal-response.v1",
    quote_id: randomUUID(),
    quote_created_at: now.toISOString(),
    quote_valid_until: new Date(now.getTime() + 5 * 60_000).toISOString(),
    token_id: pass.tokenId,
    current_owner: pass.owner,
    current_term: pass.term,
    ownership_epoch: pass.ownershipEpoch,
    current_term_active: pass.active,
    current_term_expires_at: new Date(pass.expiresAt).toISOString(),
    recommendation,
    reason_codes: [
      ...(pass.active ? ["renewal_available_only_after_expiry"] : ["term_expired"]),
      ...(rawSavings <= 0 ? ["paygo_is_cheaper_or_equal"] : ["renewal_reduces_expected_cost"]),
      ...(riskAdjustedSavings <= 0 ? ["risk_adjusted_savings_not_positive"] : []),
    ],
    forecast_calls: forecastCalls,
    paygo_cost_usdc: cents(paygoCost),
    renewal_price_usdc: "50.00",
    overflow_paygo_calls: overflowCalls,
    overflow_paygo_cost_usdc: cents(overflowCalls),
    renewal_mix_total_cost_usdc: cents(renewalMixCost),
    raw_savings_usdc: cents(rawSavings),
    risk_adjusted_savings_usdc: cents(riskAdjustedSavings),
    break_even_calls: 5000,
    authorization_status: authority ? "DECLARED_AUTHORIZED" : "INFO_ONLY",
    next_action: nextAction,
    unsigned_transactions: transactions,
    contract: config.contractAddress,
    chain_id: config.chainId,
    terms_uri: `${config.publicOrigin}/terms`,
  };
}
