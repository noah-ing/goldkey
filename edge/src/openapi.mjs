import { TOOL_NAMES } from "./catalog.mjs";

const money = {
  type: "string",
  pattern: "^[0-9]+(?:\\.[0-9]{1,2})?$",
  description: "Non-negative USDC amount with at most two fractional digits.",
};

const errorResponses = {
  400: { description: "Invalid request" },
  503: { description: "Required edge configuration or Base RPC is unavailable" },
};

function commerceRequestSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["forecast_calls"],
    properties: {
      forecast_calls: { type: "integer", minimum: 0, maximum: 10_000_000 },
      wallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      pass_purchase_budget_usdc: { ...money, description: "Maximum primary-pass spend; overflow paygo is excluded." },
      budget_usdc: { ...money, deprecated: true, description: "Compatibility alias for pass_purchase_budget_usdc." },
      switching_cost_usdc: money,
      risk_reserve_usdc: money,
      purchase_authority: { type: "boolean", default: false, description: "Caller declaration only; the service never signs or submits transactions." },
    },
  };
}

function renewalRequestSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["token_id", "forecast_calls"],
    properties: {
      token_id: { type: "string", pattern: "^[1-9][0-9]*$" },
      forecast_calls: { type: "integer", minimum: 0, maximum: 10_000_000 },
      wallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      switching_cost_usdc: money,
      risk_reserve_usdc: money,
      purchase_authority: { type: "boolean", default: false },
    },
  };
}

function proxied(description, extras = {}) {
  return {
    description: `${description} This stateful route is forwarded to ORIGIN_API and may cold-start.`,
    ...extras,
  };
}

export function buildOpenApi(config) {
  const commerceResponse = { $ref: `${config.publicOrigin}/schemas/commerce-response-v1.json` };
  const jsonObject = { type: "object" };
  return {
    openapi: "3.1.0",
    info: {
      title: "GoldKey Agent Utility API",
      version: "1.0.0",
      description: "Always-on edge discovery and Base-RPC-backed commerce for a 50-USDC transferable 10,000-call, 365-day utility pass. Stateful authentication, quota, credentials, and tool fulfillment may cold-start at the origin. The 500,000-USDC figure is only the fixed primary-mint gross cap, not a forecast or total-revenue cap.",
    },
    servers: [{ url: config.publicOrigin }],
    tags: [
      { name: "edge", description: "Served by the Worker without contacting ORIGIN_API." },
      { name: "origin", description: "Allowlisted routes forwarded to ORIGIN_API." },
    ],
    paths: {
      "/healthz": {
        get: { tags: ["edge"], operationId: "goldkey_edge_health", description: "Worker liveness only. It does not check Base RPC or ORIGIN_API.", responses: { 200: { description: "Worker is running" } } },
      },
      "/terms": {
        get: { tags: ["edge"], operationId: "goldkey_terms", responses: { 200: { description: "Exact published utility-license terms", content: { "text/markdown": {} } } } },
      },
      "/schemas/commerce-response-v1.json": {
        get: { tags: ["edge"], operationId: "goldkey_commerce_schema", responses: { 200: { description: "Commerce-response JSON Schema" } } },
      },
      "/.well-known/goldkey.json": {
        get: { tags: ["edge"], operationId: "goldkey_offer", description: "Published offer. Base RPC is consulted for live contract state; if RPC is unavailable the offer explicitly marks onchain state unavailable.", responses: { 200: { description: "GoldKey offer" }, 503: { description: "Commerce identity is not configured" } } },
      },
      "/.well-known/agent.json": {
        get: { tags: ["edge"], operationId: "goldkey_agent_card", responses: { 200: { description: "Agent discovery card" } } },
      },
      "/v1/catalog": {
        get: { tags: ["edge"], operationId: "goldkey_catalog", responses: { 200: { description: "Tool and posted-price catalog" } } },
      },
      "/v1/demo": {
        get: { tags: ["edge"], operationId: "goldkey_demo", description: "Return fixed versioned examples without payment, Base RPC, or ORIGIN_API.", responses: { 200: { description: "Free fixed examples" } } },
      },
      "/v1/purchase/quote": {
        post: {
          tags: ["edge"],
          operationId: "goldkey_quote",
          description: "Compare live primary-mint cost with paygo and return ordered unsigned transactions only when economically justified and a wallet is supplied. The service never signs or submits them.",
          requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/CommerceRequest" } } } },
          responses: { 200: { description: "Machine-readable decision", content: { "application/json": { schema: commerceResponse } } }, ...errorResponses },
        },
      },
      "/v1/commerce/respond": {
        post: {
          tags: ["edge"],
          operationId: "goldkey_commerce_respond",
          description: "Return the deterministic quote plus a sales_message. No origin call and no transaction submission.",
          requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/CommerceRequest" } } } },
          responses: { 200: { description: "Commerce decision and explanatory message", content: { "application/json": { schema: commerceResponse } } }, ...errorResponses },
        },
      },
      "/v1/renewal/quote": {
        post: {
          tags: ["edge"],
          operationId: "goldkey_renewal_quote",
          description: "Evaluate an existing token. Active terms can only receive RENEW_AFTER_EXPIRY with no transactions; expired terms may receive ordered unsigned renewal transactions.",
          requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/RenewalRequest" } } } },
          responses: { 200: { description: "Renewal decision" }, 400: { description: "Invalid request" }, 403: { description: "Wallet is not current owner" }, 404: { description: "Token does not exist" }, 503: { description: "Base RPC unavailable" } },
        },
      },
      "/metadata/{tokenId}": {
        get: {
          tags: ["edge"], operationId: "goldkey_metadata", description: "Read token metadata from Base RPC without contacting ORIGIN_API.",
          parameters: [{ name: "tokenId", in: "path", required: true, schema: { type: "string", pattern: "^[1-9][0-9]*$" } }],
          responses: { 200: { description: "Token metadata" }, 400: { description: "Invalid token ID" }, 404: { description: "Token does not exist" }, 503: { description: "Base RPC unavailable" } },
        },
      },
      "/v1/auth/challenge": {
        post: { tags: ["origin"], operationId: "goldkey_auth_challenge", ...proxied("Request an exact wallet-signature challenge.", { requestBody: { required: true, content: { "application/json": { schema: jsonObject } } }, responses: { 200: { description: "Signature challenge" }, 502: { description: "Origin unavailable" } } }) },
      },
      "/v1/auth/verify": {
        post: { tags: ["origin"], operationId: "goldkey_auth_verify", ...proxied("Verify a signed challenge and issue a short-lived session.", { requestBody: { required: true, content: { "application/json": { schema: jsonObject } } }, responses: { 200: { description: "Session issued" }, 502: { description: "Origin unavailable" } } }) },
      },
      "/v1/quota": {
        get: { tags: ["origin"], operationId: "goldkey_quota", security: [{ bearerAuth: [] }], ...proxied("Read current shared quota.", { responses: { 200: { description: "Quota state" }, 502: { description: "Origin unavailable" } } }) },
      },
      "/v1/keys": {
        get: { tags: ["origin"], operationId: "goldkey_keys_list", security: [{ bearerAuth: [] }], ...proxied("List owner-issued child credentials.", { responses: { 200: { description: "Credential list" } } }) },
        post: { tags: ["origin"], operationId: "goldkey_keys_issue", security: [{ bearerAuth: [] }], ...proxied("Issue a revocable child credential.", { requestBody: { required: true, content: { "application/json": { schema: jsonObject } } }, responses: { 201: { description: "Credential issued once" } } }) },
        delete: { tags: ["origin"], operationId: "goldkey_keys_revoke_all", security: [{ bearerAuth: [] }], ...proxied("Revoke all current owner-issued credentials.", { responses: { 200: { description: "Revocation count" } } }) },
      },
      "/v1/keys/{id}": {
        delete: { tags: ["origin"], operationId: "goldkey_key_revoke", security: [{ bearerAuth: [] }], ...proxied("Revoke one child credential.", { parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { 204: { description: "Credential revoked" } } }) },
      },
      "/v1/tools/{tool}": {
        post: {
          tags: ["origin"], operationId: "goldkey_execute", security: [{ bearerAuth: [] }],
          ...proxied("Execute one pass-gated utility call. A successful distinct request consumes one unit; an exact idempotent replay does not.", {
            parameters: [
              { name: "tool", in: "path", required: true, schema: { type: "string", enum: TOOL_NAMES } },
              { name: "Idempotency-Key", in: "header", required: true, schema: { type: "string", minLength: 8, maxLength: 128 } },
            ],
            requestBody: { required: true, content: { "application/json": { schema: jsonObject } } },
            responses: { 200: { description: "Deterministic result" }, 402: { description: "Pass quota exhausted" }, 502: { description: "Origin unavailable" } },
          }),
        },
      },
      "/v1/paygo/execute": {
        post: {
          tags: ["origin"], operationId: "goldkey_paygo_execute",
          ...proxied("Execute one independent 0.01-USDC x402 purchase. The origin validates the envelope before payment verification, buffers a fully validated tool result, settles payment, and only then releases the result; failed validation or settlement does not return a tool result. A successfully settled retry is a new purchase.", {
            requestBody: { required: true, content: { "application/json": { schema: { type: "object", additionalProperties: false, required: ["tool", "input"], properties: { tool: { type: "string", enum: TOOL_NAMES }, input: jsonObject } } } } },
            responses: { 200: { description: "Settled paid result" }, 400: { description: "Malformed request before payment" }, 402: { description: "Payment required, invalid, or unsuccessful" }, 503: { description: "Paygo disabled" }, 502: { description: "Origin unavailable" } },
          }),
        },
      },
    },
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
      schemas: { CommerceRequest: commerceRequestSchema(), RenewalRequest: renewalRequestSchema() },
    },
  };
}
