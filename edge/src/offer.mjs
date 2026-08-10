import { catalog } from "./catalog.mjs";

export async function buildOffer(config, chain) {
  let onchain;
  try {
    onchain = await chain.supplyState();
  } catch {
    onchain = { status: "unavailable", error: "onchain_state_unavailable" };
  }

  return {
    schema: "goldkey.offer.v1",
    name: "GoldKey",
    version: "1.0.0",
    sku: "GOLDKEY-10K-365",
    product_type: "transferable_utility_access_pass",
    description: "One transferable credential for deterministic validation and agent-safety utilities.",
    price: {
      amount: "50.00",
      asset: "USDC",
      atomic_units: onchain.mintPriceAtomic ?? "50000000",
      decimals: onchain.paymentTokenDecimals ?? 6,
      token_address: onchain.paymentToken ?? config.usdcAddress,
      chain_id: config.chainId,
    },
    entitlement: {
      eligible_calls: config.callsPerTerm,
      term_days: config.termDays,
      mint_term_starts: "onchain_purchase",
      renewal_term_starts: "onchain_renewal_after_prior_term_expiry",
      renewal_required: true,
      renewal_price_usdc: "50.00",
      unused_calls_roll_over: false,
      transfer_moves_remaining_quota: true,
      delegated_child_credentials: true,
    },
    alternative: {
      type: "x402_paygo",
      price_per_call_usdc: "0.01",
      endpoint: `${config.publicOrigin}/v1/paygo/execute`,
      fulfillment_note: "This stateful route is served by the utility origin and may cold-start.",
    },
    economics: {
      break_even_calls_excluding_gas_and_switching_cost: 5000,
      maximum_savings_at_full_use_usdc: "50.00",
      decision_endpoint: `${config.publicOrigin}/v1/purchase/quote`,
      renewal_decision_endpoint: `${config.publicOrigin}/v1/renewal/quote`,
      gross_primary_sale_cap_usdc: "500000.00",
      gross_primary_sale_cap_basis: "10000 fixed primary units x 50.00 USDC; renewals and paygo are additional revenue",
    },
    contract: {
      address: config.contractAddress,
      max_supply: 10_000,
      terms_hash: onchain.termsHash,
      terms_uri: onchain.termsUri ?? `${config.publicOrigin}/terms`,
      state: onchain,
    },
    discovery: {
      catalog_url: `${config.publicOrigin}/v1/catalog`,
      quote_url: `${config.publicOrigin}/v1/purchase/quote`,
      renewal_quote_url: `${config.publicOrigin}/v1/renewal/quote`,
      openapi_url: `${config.publicOrigin}/openapi.json`,
      response_schema_url: `${config.publicOrigin}/schemas/commerce-response-v1.json`,
    },
    buyer_protections: {
      automatic_renewal: false,
      investment_or_appreciation_claim: false,
      explicit_purchase_authority_required: true,
      current_owner_checked_on_each_charged_call: true,
    },
    service_topology: {
      storefront: "cloudflare_worker",
      commerce_quotes: "edge_plus_base_rpc",
      utility_fulfillment: "stateful_origin_may_cold_start",
    },
    tools: catalog(),
  };
}
