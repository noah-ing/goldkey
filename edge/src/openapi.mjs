import { ACTION_GATE_INPUT_SCHEMA, TOOL_NAMES } from "./catalog.mjs";

const money = {
  type: "string",
  pattern: "^[0-9]+(?:\\.[0-9]{1,2})?$",
  description: "Non-negative USDC amount with at most two fractional digits.",
};

const responseMoney = {
  type: "string",
  pattern: "^[0-9]+\\.[0-9]{2}$",
};

const signedResponseMoney = {
  type: "string",
  pattern: "^-?[0-9]+\\.[0-9]{2}$",
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

function commerceResponseSchema() {
  return {
    type: "object",
    additionalProperties: true,
    required: [
      "schema",
      "quote_id",
      "quote_created_at",
      "quote_valid_until",
      "recommendation",
      "reason_codes",
      "assumptions",
      "paygo_cost_usdc",
      "key_count",
      "key_purchase_cost_usdc",
      "overflow_paygo_calls",
      "overflow_paygo_cost_usdc",
      "optimized_total_cost_usdc",
      "raw_savings_usdc",
      "risk_adjusted_savings_usdc",
      "break_even_calls",
      "forecast_calls",
      "term_days",
      "included_calls_per_key",
      "contract",
      "chain_id",
      "supply_remaining",
      "supply_total_minted",
      "supply_block_number",
      "sales_paused",
      "onchain_mint_price_atomic",
      "payment_token",
      "payment_token_decimals",
      "terms_hash",
      "terms_uri",
      "response_schema_url",
      "authorization_status",
      "next_action",
      "unsigned_transactions",
    ],
    properties: {
      schema: { const: "goldkey.commerce-response.v1" },
      quote_id: { type: "string", format: "uuid" },
      quote_created_at: { type: "string", format: "date-time" },
      quote_valid_until: { type: "string", format: "date-time" },
      recommendation: {
        oneOf: [
          { enum: ["DO_NOT_BUY", "PAYGO", "TRIAL"] },
          { type: "string", pattern: "^BUY_[1-9][0-9]*_KEYS?$" },
        ],
      },
      reason_codes: { type: "array", minItems: 1, items: { type: "string" } },
      assumptions: { type: "array", items: { type: "string" } },
      paygo_cost_usdc: responseMoney,
      key_count: { type: "integer", minimum: 0, maximum: 1000 },
      key_purchase_cost_usdc: responseMoney,
      overflow_paygo_calls: { type: "integer", minimum: 0 },
      overflow_paygo_cost_usdc: responseMoney,
      optimized_total_cost_usdc: responseMoney,
      raw_savings_usdc: responseMoney,
      risk_adjusted_savings_usdc: signedResponseMoney,
      break_even_calls: { const: 5000 },
      forecast_calls: { type: "integer", minimum: 0, maximum: 10_000_000 },
      term_days: { const: 365 },
      included_calls_per_key: { const: 10_000 },
      contract: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      chain_id: { type: "integer", minimum: 1 },
      supply_remaining: { type: "integer", minimum: 0, maximum: 10_000 },
      supply_total_minted: { type: "string", pattern: "^[0-9]+$" },
      supply_block_number: { type: "string", pattern: "^[0-9]+$" },
      sales_paused: { type: "boolean" },
      onchain_mint_price_atomic: { type: "string", pattern: "^[0-9]+$" },
      payment_token: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      payment_token_decimals: { const: 6 },
      terms_hash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
      terms_uri: { type: "string" },
      response_schema_url: { type: "string", format: "uri" },
      authorization_status: { enum: ["INFO_ONLY", "DECLARED_AUTHORIZED"] },
      next_action: {
        enum: [
          "USE_PAYGO",
          "MEASURE_USAGE",
          "PROVIDE_WALLET",
          "OBTAIN_PURCHASE_AUTHORITY",
          "SIGN_UNSIGNED_TRANSACTIONS",
        ],
      },
      unsigned_transactions: { type: "array", items: { type: "object" } },
      sales_message: { type: "string" },
    },
  };
}

function paygoResponseSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["request_id", "tool", "tool_version", "input_sha256", "result", "payment", "upgrade"],
    properties: {
      request_id: { type: "string", format: "uuid" },
      tool: { type: "string", enum: TOOL_NAMES },
      tool_version: { type: "string" },
      input_sha256: { type: "string", pattern: "^[0-9a-f]{64}$" },
      result: { type: "object" },
      payment: {
        type: "object",
        additionalProperties: false,
        required: ["protocol", "charged_usdc"],
        properties: {
          protocol: { const: "x402" },
          charged_usdc: { const: "0.01" },
        },
      },
      upgrade: {
        type: "object",
        additionalProperties: false,
        required: ["quote_url", "break_even_calls"],
        properties: {
          quote_url: { type: "string", format: "uri" },
          break_even_calls: { const: 5000 },
        },
      },
    },
  };
}

function actionGateResponseSchema() {
  const sha256Schema = { type: "string", pattern: "^[0-9a-f]{64}$" };
  return {
    type: "object",
    additionalProperties: false,
    required: ["request_id", "tool", "tool_version", "input_sha256", "result", "payment", "upgrade"],
    properties: {
      request_id: { type: "string", minLength: 1, maxLength: 128 },
      tool: { const: "action.gate" },
      tool_version: { const: "1.0.0" },
      input_sha256: sha256Schema,
      result: {
        type: "object",
        additionalProperties: false,
        required: ["decision", "reason_codes", "checks", "request_sha256", "receipt_sha256", "receipt_format", "receipt_canonicalization", "receipt_hash_algorithm", "receipt_preimage_fields", "limitation"],
        properties: {
          decision: { enum: ["ALLOW", "REVIEW", "BLOCK"] },
          reason_codes: { type: "array", uniqueItems: true, items: { type: "string" } },
          checks: {
            type: "object",
            additionalProperties: false,
            required: ["action", "prompt", "url", "payload", "spend"],
            properties: {
              action: { type: "object" },
              prompt: { type: "object" },
              url: { type: "object" },
              payload: { type: "object" },
              spend: { type: "object" },
            },
          },
          request_sha256: sha256Schema,
          receipt_sha256: {
            ...sha256Schema,
            description: "SHA-256 of the UTF-8 goldkey-c14n-v1 canonical JSON object containing exactly receipt_format, request_sha256, decision, reason_codes, and checks. This reproducible digest is not a cryptographic signature.",
          },
          receipt_format: { const: "goldkey-action-gate-v1" },
          receipt_canonicalization: { const: "goldkey-c14n-v1" },
          receipt_hash_algorithm: { const: "SHA-256" },
          receipt_preimage_fields: { const: ["receipt_format", "request_sha256", "decision", "reason_codes", "checks"] },
          limitation: { type: "string" },
        },
      },
      payment: {
        type: "object",
        additionalProperties: false,
        required: ["protocol", "charged_usdc"],
        properties: { protocol: { const: "x402" }, charged_usdc: { const: "0.01" } },
      },
      upgrade: {
        type: "object",
        additionalProperties: false,
        required: ["quote_url", "break_even_calls"],
        properties: {
          quote_url: { type: "string", format: "uri" },
          break_even_calls: { const: 5000 },
        },
      },
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

function authChallengeRequestSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["wallet", "token_id"],
    properties: {
      wallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      token_id: { type: "string", pattern: "^[1-9][0-9]*$" },
    },
  };
}

function authVerifyRequestSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["challenge_id", "signature"],
    properties: {
      challenge_id: { type: "string", format: "uuid" },
      signature: { type: "string", pattern: "^0x[0-9a-fA-F]+$", maxLength: 8194 },
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
  const commerceResponse = { $ref: "#/components/schemas/CommerceResponse" };
  const jsonObject = { type: "object" };
  return {
    openapi: "3.1.0",
    info: {
      title: "GoldKey Agent Utility API",
      version: "1.0.0",
      description: "Always-on edge discovery and Base-RPC-backed commerce for a 50-USDC transferable 10,000-call, 365-day utility pass. Stateful authentication, quota, credentials, and tool fulfillment may cold-start at the origin. The 500,000-USDC figure is only the fixed primary-mint gross cap, not a forecast or total-revenue cap.",
      "x-guidance": "Use POST /v1/action-gate for one deterministic preflight decision across proposed action text, untrusted text, URL, payload schema, and spend mandate. Use POST /v1/paygo/execute for Action Gate or any of the six individual deterministic utilities. An unpaid request returns an x402 challenge for exactly 0.01 USDC on Base; pay and retry once. Use /v1/purchase/quote only to compare measured annual demand with the 50-USDC pass.",
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
        post: { tags: ["origin"], operationId: "goldkey_auth_challenge", ...proxied("Request an exact wallet-signature challenge.", { requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AuthChallengeRequest" } } } }, responses: { 200: { description: "Signature challenge" }, 400: { description: "Missing or invalid wallet or token ID" }, 502: { description: "Origin unavailable" } } }) },
      },
      "/v1/auth/verify": {
        post: { tags: ["origin"], operationId: "goldkey_auth_verify", ...proxied("Verify a signed challenge and issue a short-lived session.", { requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AuthVerifyRequest" } } } }, responses: { 200: { description: "Session issued" }, 400: { description: "Missing or invalid challenge ID or signature" }, 502: { description: "Origin unavailable" } } }) },
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
          summary: "$0.01-USDC Base x402 access to seven deterministic tools: JSON canonicalization (json.canonicalize), bounded JSON Schema validation (json.validate), prompt-injection and exfiltration signal scanning (security.prompt_scan), static unsafe-URL screening (security.url_check), atomic spend-mandate evaluation (policy.spend_check), Unicode normalization with optional control/bidi removal (text.normalize), and composite pre-action gating (action.gate).",
          "x-payment-info": {
            price: { mode: "fixed", currency: "USD", amount: "0.01" },
            protocols: [{ x402: {} }],
          },
          ...proxied("For $0.01 USDC per x402 call on Base, execute one of seven deterministic utilities: json.canonicalize creates stable JSON serialization and a SHA-256 hash before signing or comparing structured data; json.validate checks data against a bounded JSON Schema 2020-12 subset before accepting agent output; security.prompt_scan returns prompt-injection and exfiltration signals with evidence spans for untrusted text; security.url_check statically screens unsafe schemes, credentials, ports, and direct private or reserved hosts before fetch; policy.spend_check evaluates atomic-unit payment proposals against mandate caps before authorization; text.normalize normalizes Unicode and can strip control or bidirectional-formatting characters before comparison or storage; action.gate combines applicable prompt, Unicode, URL, payload-schema, and spend-mandate checks into one ALLOW, REVIEW, or BLOCK decision with stable reason codes and a reproducible receipt hash. Submit one tool and its matching input. Each call is an independent purchase: the origin validates a fixed bounded envelope before payment verification, performs the potentially expensive tool work only after verification, buffers the result, settles payment, and only then releases it; failed evaluation or settlement does not return a tool result. A successfully settled retry is a new purchase.", {
            requestBody: { required: true, content: { "application/json": { schema: { type: "object", additionalProperties: false, required: ["tool", "input"], properties: { tool: { type: "string", enum: TOOL_NAMES }, input: jsonObject } } } } },
            responses: { 200: { description: "Settled paid result", content: { "application/json": { schema: { $ref: "#/components/schemas/PaygoResponse" } } } }, 400: { description: "Malformed envelope before verification or semantic tool error after verification; no settlement occurs" }, 402: { description: "Payment Required" }, 503: { description: "Paygo disabled" }, 502: { description: "Origin unavailable" } },
          }),
        },
      },
      "/v1/action-gate": {
        post: {
          tags: ["origin"], operationId: "goldkey_action_gate_ai_agent_tool_call_preflight",
          summary: "$0.01 AI-agent tool-call preflight: return ALLOW, REVIEW, or BLOCK before an MCP/tool call, payment, fetch, message, write, or execution.",
          "x-payment-info": {
            price: { mode: "fixed", currency: "USD", amount: "0.01" },
            protocols: [{ x402: {} }],
          },
          ...proxied("For $0.01 USDC per x402 call on Base, evaluate one bounded proposed agent action across applicable prompt-injection, hidden-Unicode, static URL, payload-schema, and spend-mandate checks. The result is ALLOW, REVIEW, or BLOCK with stable reason codes, per-check evidence, and deterministic request and receipt SHA-256 hashes. Action Gate does not execute the proposed action, perform network I/O or DNS resolution, or guarantee safety. The origin validates a fixed bounded envelope before payment verification, performs full evaluation only after verification, buffers the result, settles payment, and only then releases it; failed evaluation or settlement does not return an Action Gate result. A successfully settled retry is a new purchase.", {
            requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/ActionGateInput" } } } },
            responses: { 200: { description: "Settled Action Gate result", content: { "application/json": { schema: { $ref: "#/components/schemas/ActionGateResponse" } } } }, 400: { description: "Malformed request or failed Action Gate evaluation; no settlement occurs" }, 402: { description: "Payment Required" }, 503: { description: "Paygo disabled" }, 502: { description: "Origin unavailable" } },
          }),
        },
      },
    },
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
      schemas: {
        CommerceRequest: commerceRequestSchema(),
        CommerceResponse: commerceResponseSchema(),
        RenewalRequest: renewalRequestSchema(),
        AuthChallengeRequest: authChallengeRequestSchema(),
        AuthVerifyRequest: authVerifyRequestSchema(),
        ActionGateInput: ACTION_GATE_INPUT_SCHEMA,
        ActionGateResponse: actionGateResponseSchema(),
        PaygoResponse: paygoResponseSchema(),
      },
    },
  };
}
