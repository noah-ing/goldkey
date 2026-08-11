import { TOOL_REGISTRY } from "./tools.mjs";

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

function commerceRequestSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["forecast_calls"],
    properties: {
      forecast_calls: {
        type: "integer",
        minimum: 0,
        maximum: 10_000_000,
        description: "Eligible calls forecast during the new 365-day term.",
      },
      wallet: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description: "Recipient wallet. Without it, a positive quote cannot include transactions.",
      },
      pass_purchase_budget_usdc: {
        ...money,
        description: "Maximum primary-pass acquisition spend. Overflow paygo is not counted against this field.",
      },
      budget_usdc: {
        ...money,
        deprecated: true,
        description: "Deprecated compatibility alias for pass_purchase_budget_usdc. New clients must use the canonical field.",
      },
      switching_cost_usdc: {
        ...money,
        description: "Buyer-supplied one-time integration or switching cost used in the risk-adjusted decision.",
      },
      risk_reserve_usdc: {
        ...money,
        description: "Buyer-supplied reserve subtracted from raw savings.",
      },
      purchase_authority: {
        type: "boolean",
        default: false,
        description: "Caller declaration only. The service never signs or submits the returned transactions.",
      },
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

function renewalRequestSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["token_id", "forecast_calls"],
    properties: {
      token_id: {
        type: "string",
        pattern: "^[1-9][0-9]*$",
        description: "GoldKey token whose next expired term is being evaluated.",
      },
      forecast_calls: {
        type: "integer",
        minimum: 0,
        maximum: 10_000_000,
        description: "Eligible calls forecast for the fresh post-expiry term.",
      },
      wallet: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description: "Must be the current token owner when supplied.",
      },
      switching_cost_usdc: money,
      risk_reserve_usdc: money,
      purchase_authority: {
        type: "boolean",
        default: false,
        description: "Caller declaration only. The service never signs or submits a renewal.",
      },
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

function renewalResponseSchema() {
  return {
    type: "object",
    additionalProperties: true,
    required: [
      "schema",
      "quote_id",
      "quote_created_at",
      "quote_valid_until",
      "token_id",
      "current_owner",
      "current_term",
      "ownership_epoch",
      "current_term_active",
      "current_term_expires_at",
      "recommendation",
      "reason_codes",
      "forecast_calls",
      "paygo_cost_usdc",
      "renewal_price_usdc",
      "overflow_paygo_calls",
      "overflow_paygo_cost_usdc",
      "renewal_mix_total_cost_usdc",
      "raw_savings_usdc",
      "risk_adjusted_savings_usdc",
      "break_even_calls",
      "authorization_status",
      "next_action",
      "unsigned_transactions",
      "contract",
      "chain_id",
      "terms_uri",
    ],
    properties: {
      schema: { const: "goldkey.renewal-response.v1" },
      quote_id: { type: "string", format: "uuid" },
      quote_created_at: { type: "string", format: "date-time" },
      quote_valid_until: { type: "string", format: "date-time" },
      token_id: { type: "string", pattern: "^[1-9][0-9]*$" },
      current_owner: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      current_term: { type: "string", pattern: "^[1-9][0-9]*$" },
      ownership_epoch: { type: "string", pattern: "^[0-9]+$" },
      current_term_active: { type: "boolean" },
      current_term_expires_at: { type: "string", format: "date-time" },
      recommendation: {
        enum: ["DO_NOT_RENEW", "RENEW_AFTER_EXPIRY", "RENEW_NOW", "MEASURE_USAGE", "USE_PAYGO"],
      },
      reason_codes: { type: "array", minItems: 1, items: { type: "string" } },
      forecast_calls: { type: "integer", minimum: 0, maximum: 10_000_000 },
      paygo_cost_usdc: responseMoney,
      renewal_price_usdc: { const: "50.00" },
      overflow_paygo_calls: { type: "integer", minimum: 0 },
      overflow_paygo_cost_usdc: responseMoney,
      renewal_mix_total_cost_usdc: responseMoney,
      raw_savings_usdc: signedResponseMoney,
      risk_adjusted_savings_usdc: signedResponseMoney,
      break_even_calls: { const: 5000 },
      authorization_status: { enum: ["INFO_ONLY", "DECLARED_AUTHORIZED"] },
      next_action: {
        enum: [
          "WAIT_UNTIL_EXPIRY",
          "PROVIDE_WALLET",
          "OBTAIN_RENEWAL_AUTHORITY",
          "SIGN_UNSIGNED_TRANSACTIONS",
          "USE_PAYGO",
          "MEASURE_USAGE",
        ],
      },
      unsigned_transactions: { type: "array", items: { type: "object" } },
      contract: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      chain_id: { type: "integer", minimum: 1 },
      terms_uri: { type: "string", format: "uri" },
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

export function buildOpenApi(config) {
  const toolNames = Object.keys(TOOL_REGISTRY);
  return {
    openapi: "3.1.0",
    info: {
      title: "GoldKey Agent Utility API",
      version: "1.0.0",
      description: "Seven deterministic utilities sold at 0.01 USDC per x402 call or through a transferable 10,000-call GoldKey term. The 500,000-USDC figure is the primary-mint gross cap, not a total-revenue cap or forecast.",
    },
    servers: [{ url: config.publicOrigin }],
    paths: {
      "/v1/catalog": {
        get: {
          operationId: "goldkey_catalog",
          responses: { 200: { description: "Tool and posted-price catalog" } },
        },
      },
      "/v1/purchase/quote": {
        post: {
          operationId: "goldkey_quote",
          description: "Return a live-supply-aware primary-mint versus paygo decision. Transactions are included only for a positive BUY decision with a recipient wallet; the service never submits them.",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/CommerceRequest" } } },
          },
          responses: {
            200: {
              description: "Machine-readable decision and any applicable unsigned transactions",
              content: { "application/json": { schema: { $ref: "#/components/schemas/CommerceResponse" } } },
            },
            400: { description: "Invalid forecast, money field, or wallet" },
            503: { description: "Live onchain supply could not be established" },
          },
        },
      },
      "/v1/commerce/respond": {
        post: {
          operationId: "goldkey_commerce_respond",
          description: "Return the same deterministic quote plus a network-ready explanatory sales_message.",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/CommerceRequest" } } },
          },
          responses: {
            200: {
              description: "Commerce decision, explanatory message, and any applicable unsigned transactions",
              content: { "application/json": { schema: { $ref: "#/components/schemas/CommerceResponse" } } },
            },
            400: { description: "Invalid forecast, money field, or wallet" },
            503: { description: "Live onchain supply could not be established" },
          },
        },
      },
      "/v1/renewal/quote": {
        post: {
          operationId: "goldkey_renewal_quote",
          description: "Evaluate the next 10,000-call term for an existing token. While the current term is active, a positive result is RENEW_AFTER_EXPIRY and contains no transactions. After expiry, a positive owner-matched quote may contain ordered unsigned renewal transactions.",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/RenewalRequest" } } },
          },
          responses: {
            200: {
              description: "Post-expiry renewal decision and any applicable unsigned transactions",
              content: { "application/json": { schema: { $ref: "#/components/schemas/RenewalResponse" } } },
            },
            400: { description: "Invalid token ID, forecast, money field, or wallet" },
            403: { description: "Supplied wallet is not the current token owner" },
          },
        },
      },
      "/v1/auth/challenge": {
        post: {
          operationId: "goldkey_auth_challenge",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuthChallengeRequest" } } },
          },
          responses: {
            200: { description: "Exact wallet-signature challenge for a token owner" },
            400: { description: "Missing or invalid wallet or token ID" },
          },
        },
      },
      "/v1/auth/verify": {
        post: {
          operationId: "goldkey_auth_verify",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuthVerifyRequest" } } },
          },
          responses: {
            200: { description: "Short-lived current-owner session" },
            400: { description: "Missing or invalid challenge ID or signature" },
          },
        },
      },
      "/v1/tools/{tool}": {
        post: {
          operationId: "goldkey_execute",
          description: "Execute one NFT-gated utility call. A successful distinct request consumes one quota unit; an exact idempotent replay does not consume another unit.",
          security: [{ bearerAuth: [] }],
          parameters: [
            { name: "tool", in: "path", required: true, schema: { type: "string", enum: toolNames } },
            { name: "Idempotency-Key", in: "header", required: true, schema: { type: "string", minLength: 8, maxLength: 128 } },
          ],
          requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
          responses: {
            200: { description: "Deterministic result; consumes one quota unit unless it is an exact replay" },
            402: { description: "GoldKey or delegated-key quota exhausted" },
          },
        },
      },
      "/v1/paygo/execute": {
        post: {
          operationId: "goldkey_paygo_execute",
          description: "Execute one independent 0.01-USDC x402 purchase. The route validates a fixed bounded envelope before payment verification, performs the potentially expensive deterministic tool work only after verification, buffers the result, and releases it only after successful settlement. A handler error cancels settlement. This route does not use GoldKey quota or NFT idempotency; retrying a settled request is another purchase.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  additionalProperties: false,
                  properties: {
                    tool: { type: "string", enum: toolNames },
                    input: { type: "object" },
                  },
                  required: ["tool", "input"],
                },
              },
            },
          },
          responses: {
            200: { description: "Settled paid result" },
            400: { description: "Malformed envelopes are rejected before verification; semantic tool errors after verification cancel settlement" },
            402: { description: "Payment required, invalid, or unsuccessful; tool result is not returned" },
            503: { description: "Paygo is disabled on this deployment" },
          },
        },
      },
      "/v1/action-gate": {
        post: {
          operationId: "goldkey_action_gate_ai_agent_tool_call_preflight",
          summary: "$0.01 AI-agent tool-call preflight: return ALLOW, REVIEW, or BLOCK before an MCP/tool call, payment, fetch, message, write, or execution.",
          "x-payment-info": {
            price: { mode: "fixed", currency: "USD", amount: "0.01" },
            protocols: [{ x402: {} }],
          },
          description: "Return one ALLOW, REVIEW, or BLOCK decision before an agent fetches, pays, calls a tool, sends content, or stores data. Action Gate combines prompt-injection and hidden-Unicode checks, static URL screening, payload-schema validation, and spend-mandate enforcement. It never executes the proposed action. The fixed bounded envelope is validated before payment verification; full evaluation runs only after verification, and the buffered result is released only after successful x402 settlement. One successful request is one 0.01-USDC execution. receipt_sha256 is a reproducible digest, not a cryptographic signature.",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/ActionGateRequest" } } },
          },
          responses: {
            200: {
              description: "Settled deterministic Action Gate decision and reproducible receipt hash",
              content: { "application/json": { schema: { $ref: "#/components/schemas/ActionGateResponse" } } },
            },
            400: { description: "Malformed envelopes are rejected before verification; semantic evaluation errors after verification cancel settlement" },
            402: { description: "Payment required, invalid, or unsuccessful; Action Gate result is not returned" },
            413: { description: "Bounded request, payload, schema, or evidence limit exceeded; settlement is cancelled" },
            503: { description: "Paygo is disabled on this deployment" },
          },
        },
      },
    },
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
      schemas: {
        CommerceRequest: commerceRequestSchema(),
        CommerceResponse: {
          ...commerceResponseSchema(),
          "x-json-schema-id": "urn:goldkey:schema:commerce-response:v1",
        },
        RenewalRequest: renewalRequestSchema(),
        RenewalResponse: renewalResponseSchema(),
        AuthChallengeRequest: authChallengeRequestSchema(),
        AuthVerifyRequest: authVerifyRequestSchema(),
        ActionGateRequest: TOOL_REGISTRY["action.gate"].input_schema,
        ActionGateResponse: actionGateResponseSchema(),
      },
    },
  };
}
