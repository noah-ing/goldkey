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

const guardIdentifier = { type: "string", pattern: "^[A-Za-z0-9._:-]{1,128}$" };
const guardInstallationIdentifier = { type: "string", pattern: "^gki_[A-Za-z0-9_-]{43}$" };
const guardSha256 = { type: "string", pattern: "^[0-9a-f]{64}$" };
const guardAtomic = { type: "string", pattern: "^(0|[1-9][0-9]{0,77})$" };
const guardEd25519Signature = { type: "string", pattern: "^[A-Za-z0-9_-]{86}$" };
const guardAddress = { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" };

function guardConnectorSchema() {
  const addressList = { type: "array", maxItems: 100, uniqueItems: true, items: guardAddress };
  return {
    oneOf: [
      {
        type: "object",
        additionalProperties: false,
        required: ["id", "kind", "server_id", "tools"],
        properties: {
          id: guardIdentifier,
          kind: { const: "mcp_tool" },
          server_id: guardIdentifier,
          tools: {
            type: "array",
            minItems: 1,
            maxItems: 100,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["name", "effect", "input_schema_sha256"],
              properties: {
                name: { type: "string", maxLength: 256 },
                effect: { enum: ["read", "write", "network", "payment", "execute"] },
                input_schema_sha256: guardSha256,
                arguments_schema: { type: "object", description: "Optional bounded operator-signed JSON Schema applied to the actual MCP arguments." },
              },
            },
          },
        },
      },
      {
        type: "object",
        additionalProperties: false,
        required: ["id", "kind", "origin", "operations"],
        properties: {
          id: guardIdentifier,
          kind: { const: "https" },
          origin: { type: "string", format: "uri", pattern: "^https://" },
          operations: {
            type: "array",
            minItems: 1,
            maxItems: 100,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["id", "method", "path", "effect"],
              properties: {
                id: guardIdentifier,
                method: { enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
                path: { type: "string", pattern: "^/" },
                effect: { enum: ["read", "write", "network", "payment", "execute"] },
                query_schema: { type: "object", description: "Optional bounded operator-signed JSON Schema applied to the actual query object." },
                body_schema: { type: "object", description: "Optional bounded operator-signed JSON Schema applied to the actual request body." },
              },
            },
          },
        },
      },
      {
        type: "object",
        additionalProperties: false,
        required: [
          "id", "kind", "chain_id", "from", "allowed_native_recipients", "allowed_erc20_tokens",
          "allowed_erc20_recipients", "allowed_approval_spenders", "max_native_value_atomic",
          "max_erc20_transfer_atomic", "max_erc20_approval_atomic", "max_gas_limit",
          "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic", "max_total_fee_atomic",
          "fee_period_seconds", "max_fee_period_atomic", "spend_period_seconds", "max_period_atomic",
          "require_simulation",
        ],
        properties: {
          id: guardIdentifier,
          kind: { const: "evm_transaction" },
          chain_id: { type: "integer", minimum: 1 },
          from: guardAddress,
          allowed_native_recipients: addressList,
          allowed_erc20_tokens: addressList,
          allowed_erc20_recipients: addressList,
          allowed_approval_spenders: addressList,
          max_native_value_atomic: guardAtomic,
          max_erc20_transfer_atomic: guardAtomic,
          max_erc20_approval_atomic: guardAtomic,
          max_gas_limit: guardAtomic,
          max_fee_per_gas_atomic: guardAtomic,
          max_priority_fee_per_gas_atomic: guardAtomic,
          max_total_fee_atomic: { ...guardAtomic, description: "Point-in-time screening threshold for execution maximum plus Base L1-data and operator-fee estimates; not an absolute protocol fee guarantee." },
          fee_period_seconds: { type: "integer", minimum: 60, maximum: 31_536_000 },
          max_fee_period_atomic: { ...guardAtomic, description: "Cumulative reservation threshold based on point-in-time fee estimates." },
          spend_period_seconds: { type: "integer", minimum: 60, maximum: 31_536_000 },
          max_period_atomic: guardAtomic,
          require_simulation: { const: true },
          asset_id: { type: "string" },
        },
      },
    ],
  };
}

function guardPolicySchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "policy_id", "version", "operator_wallet", "audience", "issued_at", "expires_at", "connectors", "signature"],
    properties: {
      schema: { const: "goldkey.guard-policy.v1" },
      policy_id: guardIdentifier,
      version: { type: "integer", minimum: 1 },
      operator_wallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      audience: { type: "string", format: "uri" },
      issued_at: { type: "string", format: "date-time" },
      expires_at: { type: "string", format: "date-time" },
      connectors: { type: "array", minItems: 1, maxItems: 64, items: guardConnectorSchema() },
      signature: { type: "string", pattern: "^0x[0-9a-fA-F]+$", maxLength: 8194 },
    },
  };
}

function guardInstallationSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "installation_id", "operator_wallet", "policy_sha256", "public_key_jwk", "issued_at", "expires_at", "signature", "key_proof"],
    properties: {
      schema: { const: "goldkey.guard-installation.v1" },
      installation_id: guardInstallationIdentifier,
      operator_wallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
      policy_sha256: guardSha256,
      public_key_jwk: {
        type: "object",
        additionalProperties: false,
        required: ["kty", "crv", "x"],
        properties: { kty: { const: "OKP" }, crv: { const: "Ed25519" }, x: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" } },
      },
      issued_at: { type: "string", format: "date-time" },
      expires_at: { type: "string", format: "date-time" },
      signature: { type: "string", pattern: "^0x[0-9a-fA-F]+$", maxLength: 8194 },
      key_proof: { type: "string", pattern: "^[A-Za-z0-9_-]{86}$", description: "Ed25519 proof of possession by the installation private key over the canonical binding." },
    },
  };
}

function guardCallSchema(kinds = ["mcp_tool", "https", "evm_transaction"]) {
  const variants = [];
  if (kinds.includes("mcp_tool")) variants.push({
    type: "object",
    additionalProperties: false,
    required: ["kind", "connector_id", "tool", "input_schema_sha256", "arguments"],
    properties: { kind: { const: "mcp_tool" }, connector_id: guardIdentifier, tool: { type: "string", maxLength: 256 }, input_schema_sha256: guardSha256, arguments: {} },
  });
  if (kinds.includes("https")) variants.push({
    type: "object",
    additionalProperties: false,
    required: ["kind", "connector_id", "operation_id"],
    properties: { kind: { const: "https" }, connector_id: guardIdentifier, operation_id: guardIdentifier, query: { type: "object" }, body: {} },
  });
  if (kinds.includes("evm_transaction")) variants.push({
    type: "object",
    additionalProperties: false,
    required: ["kind", "connector_id", "transaction"],
    properties: {
      kind: { const: "evm_transaction" },
      connector_id: guardIdentifier,
      transaction: {
        type: "object",
        additionalProperties: false,
        required: [
          "chain_id",
          "from",
          "value_atomic",
          "data",
          "nonce",
          "gas_limit",
          "max_fee_per_gas_atomic",
          "max_priority_fee_per_gas_atomic",
        ],
        properties: {
          chain_id: { type: "integer", minimum: 1 },
          from: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
          to: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
          value_atomic: guardAtomic,
          data: { type: "string", pattern: "^0x(?:[0-9a-fA-F]{2})*$" },
          nonce: guardAtomic,
          gas_limit: guardAtomic,
          max_fee_per_gas_atomic: guardAtomic,
          max_priority_fee_per_gas_atomic: guardAtomic,
          type: { const: "eip1559" },
          access_list: { type: "array", maxItems: 0 },
        },
      },
    },
  });
  return { oneOf: variants };
}

function guardRequestSchema(kinds) {
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "installation_id", "idempotency_key", "issued_at", "call", "signature"],
    properties: {
      schema: { const: "goldkey.guard-request.v1" },
      installation_id: guardInstallationIdentifier,
      idempotency_key: { type: "string", pattern: "^[A-Za-z0-9._:-]{8,128}$" },
      issued_at: { type: "string", format: "date-time" },
      call: guardCallSchema(kinds),
      signature: guardEd25519Signature,
    },
  };
}

function guardLifecycleSchema(completion = false) {
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "installation_id", "execution_id", "receipt_id", "receipt_sha256", "call_sha256", "issued_at", ...(completion ? ["outcome_status", "outcome_sha256"] : []), "signature"],
    properties: {
      schema: { const: completion ? "goldkey.guard-completion.v1" : "goldkey.guard-commit.v1" },
      installation_id: guardInstallationIdentifier,
      execution_id: guardIdentifier,
      receipt_id: guardIdentifier,
      receipt_sha256: guardSha256,
      call_sha256: guardSha256,
      issued_at: { type: "string", format: "date-time" },
      ...(completion ? { outcome_status: { enum: ["succeeded", "failed", "outcome_unknown"] }, outcome_sha256: guardSha256 } : {}),
      signature: guardEd25519Signature,
    },
  };
}

function guardReconciledCommitSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "commit", "payment_proof"],
    properties: {
      schema: { const: "goldkey.guard-reconciled-commit.v1" },
      commit: { $ref: "#/components/schemas/GuardCommit" },
      payment_proof: {
        type: "object",
        additionalProperties: false,
        required: ["transaction", "payment_payload"],
        properties: {
          transaction: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
          payment_payload: {
            type: "object",
            additionalProperties: false,
            required: ["x402Version", "resource", "accepted", "payload"],
            properties: {
              x402Version: { const: 2 },
              resource: {
                type: "object",
                additionalProperties: false,
                required: ["url"],
                properties: {
                  url: { type: "string", format: "uri" }, description: { type: "string" }, mimeType: { type: "string" },
                  serviceName: { type: "string" }, tags: { type: "array", items: { type: "string" } }, iconUrl: { type: "string", format: "uri" },
                },
              },
              accepted: {
                type: "object", additionalProperties: false,
                required: ["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"],
                properties: {
                  scheme: { const: "exact" }, network: { const: "eip155:8453" }, amount: guardAtomic,
                  asset: guardAddress, payTo: guardAddress, maxTimeoutSeconds: { const: 30 },
                  extra: { type: "object", additionalProperties: false, required: ["name", "version"], properties: { name: { const: "USD Coin" }, version: { const: "2" } } },
                },
              },
              payload: {
                type: "object", additionalProperties: false, required: ["authorization", "signature"],
                properties: {
                  authorization: {
                    type: "object", additionalProperties: false,
                    required: ["from", "to", "value", "validAfter", "validBefore", "nonce"],
                    properties: { from: guardAddress, to: guardAddress, value: guardAtomic, validAfter: guardAtomic, validBefore: guardAtomic, nonce: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" } },
                  },
                  signature: { type: "string", pattern: "^0x[0-9a-fA-F]{130}$" },
                },
              },
              extensions: { type: "object" },
            },
          },
        },
      },
    },
  };
}

function guardPaths(config) {
  const premium = (operationId, amount, schema, description) => ({
    post: {
      operationId,
      "x-payment-info": { price: { mode: "fixed", currency: "USD", amount }, protocols: [{ x402: {} }] },
      description,
      requestBody: { required: true, content: { "application/json": { schema } } },
      responses: {
        200: { description: "Settled signed ALLOW, REVIEW, or BLOCK authorization receipt" },
        400: { description: "Malformed request rejected before payment; post-verification evaluation failure cancels settlement" },
        401: { description: "Invalid installation signature rejected before payment" },
        402: { description: "Payment required, invalid, or unsuccessful; no authorization is issued" },
        503: { description: "Guard, chain verification, or required simulation is unavailable" },
      },
    },
  });
  return {
    "/.well-known/goldkey-guard-keys.json": {
      get: { operationId: "goldkey_guard_receipt_keyset", description: "Public Ed25519 keyset for offline verification of Guard authorization receipts.", responses: { 200: { description: "Current and retained receipt verification keys" } } },
    },
    "/v1/guard/policies": {
      post: {
        operationId: "goldkey_guard_register_policy",
        description: "Register an operator-signed, immutable, monotonically versioned Guard policy. This identity operation is not an authorization purchase.",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/GuardPolicy" } } } },
        responses: { 201: { description: "Policy registered" }, 200: { description: "Exact idempotent replay" }, 401: { description: "Invalid operator signature" }, 429: { description: "Registration rate limit exceeded" } },
      },
    },
    "/v1/guard/installations": {
      post: {
        operationId: "goldkey_guard_register_installation",
        description: "Bind one public Ed25519 installation identity to the latest active operator-signed policy. Private keys never leave the local enforcer.",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/GuardInstallation" } } } },
        responses: { 201: { description: "Installation registered" }, 200: { description: "Exact idempotent replay" }, 401: { description: "Invalid operator signature" }, 429: { description: "Registration rate limit exceeded" } },
      },
    },
    "/v1/guard/paygo/authorize/network": premium(
      "goldkey_guard_authorize_network",
      config.guardNetworkPriceUsd,
      { $ref: "#/components/schemas/GuardNetworkRequest" },
      `Authorize one exact MCP or HTTPS call for ${config.guardNetworkPriceUsd} USDC. Signature and installation checks happen before x402 verification; evaluation and receipt signing happen after verification and the response is released only after settlement. ALLOW, REVIEW, and BLOCK are billable completed decisions. An exact unexpired idempotent replay returns its stored receipt without another payment. GoldKey never forwards the call.`,
    ),
    "/v1/guard/paygo/authorize/evm": premium(
      "goldkey_guard_authorize_evm",
      config.guardEvmPriceUsd,
      { $ref: "#/components/schemas/GuardEvmRequest" },
      `Decode, policy-check, and when required simulate one exact EVM transaction for ${config.guardEvmPriceUsd} USDC. Signature and installation checks happen before x402 verification; evaluation occurs after verification and the signed response is released only after settlement. ALLOW, REVIEW, and BLOCK are billable. An exact unexpired idempotent replay is free. GoldKey never signs or broadcasts.`,
    ),
    "/v1/guard/executions/{executionId}/commit": {
      post: {
        operationId: "goldkey_guard_commit_execution",
        description: "Installation-signed transition to FORWARDING. The local enforcer must persist its own FORWARDING state, then commit here, then invoke the real upstream connector exactly once.",
        parameters: [{ name: "executionId", in: "path", required: true, schema: guardIdentifier }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/GuardCommit" } } } },
        responses: { 200: { description: "Execution committed or exact replay" }, 409: { description: "Expired, mismatched, or finalized execution" } },
      },
    },
    "/v1/guard/executions/{executionId}/reconcile-commit": {
      post: {
        operationId: "goldkey_guard_reconcile_paid_commit",
        description: "Recovery-only installation-signed commit. Use it only when a normal commit reports guard_payment_not_settled after the client received a successful PAYMENT-RESPONSE. GoldKey revalidates the exact stored x402 payload and independently verifies the Base USDC transaction and Transfer before allowing FORWARDING; no payer private key is submitted.",
        parameters: [{ name: "executionId", in: "path", required: true, schema: guardIdentifier }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/GuardReconciledCommit" } } } },
        responses: { 200: { description: "Payment reconciled and execution committed, or exact replay" }, 400: { description: "Malformed public payment proof" }, 409: { description: "Proof, claim, lifecycle, or payment identity mismatch" }, 503: { description: "Base payment proof is temporarily unavailable" } },
      },
    },
    "/v1/guard/executions/{executionId}/complete": {
      post: {
        operationId: "goldkey_guard_complete_execution",
        description: "Installation-signed outcome report after the local enforcer attempts the real call. Ambiguous outcomes are recorded as outcome_unknown and must not be retried automatically.",
        parameters: [{ name: "executionId", in: "path", required: true, schema: guardIdentifier }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/GuardCompletion" } } } },
        responses: { 200: { description: "Outcome recorded or exact replay" }, 409: { description: "Execution was not committed or lifecycle evidence conflicts" } },
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
      ...(config.guardEnabled ? guardPaths(config) : {}),
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
        ...(config.guardEnabled ? {
          GuardPolicy: guardPolicySchema(),
          GuardInstallation: guardInstallationSchema(),
          GuardNetworkRequest: guardRequestSchema(["mcp_tool", "https"]),
          GuardEvmRequest: guardRequestSchema(["evm_transaction"]),
          GuardCommit: guardLifecycleSchema(false),
          GuardReconciledCommit: guardReconciledCommitSchema(),
          GuardCompletion: guardLifecycleSchema(true),
        } : {}),
      },
    },
  };
}
