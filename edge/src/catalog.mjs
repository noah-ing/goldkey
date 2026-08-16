const VERSION = "1.0.0";
const MAX_TEXT_LENGTH = 64 * 1024;
const MAX_ACTION_NAME_LENGTH = 128;
const MAX_ACTION_DESCRIPTION_LENGTH = 4096;
const MAX_ACTION_UNTRUSTED_TEXT_LENGTH = 16 * 1024;

const atomicStringSchema = { type: "string", pattern: "^(0|[1-9]\\d*)$", minLength: 1, maxLength: 78 };
const shortStringSchema = { type: "string", minLength: 1, maxLength: 256 };

export const ACTION_GATE_INPUT_SCHEMA = {
  type: "object",
  description: "One bounded proposed agent action plus only the evidence that Action Gate should evaluate. Omitted optional evidence is not checked.",
  properties: {
    action: {
      type: "object",
      description: "Declare the proposed action and its effect class. Action Gate never performs it.",
      properties: {
        name: { type: "string", minLength: 1, maxLength: MAX_ACTION_NAME_LENGTH, description: "Stable action name, such as fetch_vendor_quote or submit_payment." },
        description: { type: "string", maxLength: MAX_ACTION_DESCRIPTION_LENGTH, description: "Optional human-readable action description; it is scanned as untrusted text." },
        effect: { enum: ["read", "write", "network", "payment", "execute"], description: "Required effect class. Network requires url; payment requires spend; write and execute require payload plus schema to avoid an evidence-free ALLOW." },
      },
      required: ["name", "effect"],
      additionalProperties: false,
    },
    untrusted_text: { type: "string", maxLength: MAX_ACTION_UNTRUSTED_TEXT_LENGTH, description: "Optional untrusted text to scan for prompt-injection, exfiltration, control-character, and bidi signals." },
    url: { type: "string", maxLength: 4096, description: "Optional absolute URL for static scheme, credential, port, hostname, and direct-IP screening. No DNS lookup or fetch occurs." },
    payload: { description: "Optional JSON payload proposed for a write or execution. When present, schema is required and both are bounded." },
    schema: { type: "object", description: "Bounded local JSON Schema used to validate payload. Remote references and regular-expression keywords are rejected." },
    spend: {
      type: "object",
      description: "Optional payment proposal and mandate evaluated in exact atomic units at the caller-supplied deterministic time.",
      properties: {
        proposal: {
          type: "object",
          properties: {
            amount_atomic: { ...atomicStringSchema, description: "Canonical non-negative integer string in the asset's atomic units; never use decimal or exponent notation." },
            asset: { ...shortStringSchema, description: "Exact asset identifier compared with mandate.allowed_assets." },
            counterparty: { ...shortStringSchema, description: "Exact counterparty identifier, compared case-insensitively when the mandate lists counterparties." },
          },
          required: ["amount_atomic", "asset", "counterparty"],
          additionalProperties: false,
        },
        mandate: {
          type: "object",
          properties: {
            max_per_tx_atomic: { ...atomicStringSchema, description: "Per-transaction cap as a canonical atomic-unit integer string." },
            max_period_atomic: { ...atomicStringSchema, description: "Period cap as a canonical atomic-unit integer string." },
            spent_period_atomic: { ...atomicStringSchema, description: "Optional already-spent amount in the same period; defaults to zero." },
            allowed_assets: {
              type: "array",
              minItems: 1,
              maxItems: 100,
              uniqueItems: true,
              items: shortStringSchema,
            },
            allowed_counterparties: {
              type: "array",
              maxItems: 100,
              uniqueItems: true,
              items: shortStringSchema,
            },
            expires_at: { type: "string", format: "date-time", description: "Mandate expiry as an ISO 8601 date-time." },
          },
          required: ["max_per_tx_atomic", "max_period_atomic", "allowed_assets", "expires_at"],
          additionalProperties: false,
        },
        now: { type: "string", format: "date-time", description: "Required caller-supplied ISO 8601 evaluation time; Action Gate never reads the server clock." },
      },
      required: ["proposal", "mandate", "now"],
      additionalProperties: false,
    },
  },
  required: ["action"],
  dependentRequired: {
    payload: ["schema"],
    schema: ["payload"],
  },
  additionalProperties: false,
};

const definitions = [
  {
    name: "json.canonicalize",
    description: "Sort and serialize JSON deterministically with goldkey-c14n-v1, then SHA-256 hash it.",
    input_schema: {
      type: "object",
      properties: { value: {} },
      required: ["value"],
      additionalProperties: false,
    },
  },
  {
    name: "json.validate",
    description: "Validate JSON against a bounded JSON Schema 2020-12 subset without coercion, defaults, mutation, remote refs, or user regex.",
    input_schema: {
      type: "object",
      properties: { value: {}, schema: { type: "object" } },
      required: ["value", "schema"],
      additionalProperties: false,
    },
  },
  {
    name: "security.prompt_scan",
    description: "Return deterministic prompt-injection and exfiltration signals with evidence spans.",
    input_schema: {
      type: "object",
      properties: { text: { type: "string", maxLength: MAX_TEXT_LENGTH } },
      required: ["text"],
      additionalProperties: false,
    },
  },
  {
    name: "security.url_check",
    description: "Statically reject unsafe URL schemes, credentials, ports, and direct private/reserved hosts.",
    input_schema: {
      type: "object",
      properties: { url: { type: "string", maxLength: 4096 } },
      required: ["url"],
      additionalProperties: false,
    },
  },
  {
    name: "policy.spend_check",
    description: "Evaluate a proposed atomic-unit payment against deterministic mandate caps using BigInt.",
    input_schema: {
      type: "object",
      properties: {
        proposal: { type: "object" },
        mandate: { type: "object" },
        now: { type: "string", format: "date-time" },
      },
      required: ["proposal", "mandate"],
      additionalProperties: false,
    },
  },
  {
    name: "text.normalize",
    description: "Normalize Unicode and optionally strip control and bidirectional-formatting characters.",
    input_schema: {
      type: "object",
      properties: {
        text: { type: "string", maxLength: MAX_TEXT_LENGTH },
        form: { enum: ["NFC", "NFKC"] },
        strip_controls: { type: "boolean" },
        strip_bidi: { type: "boolean" },
      },
      required: ["text"],
      additionalProperties: false,
    },
  },
  {
    name: "action.gate",
    description: "Deterministically evaluate a bounded proposed agent action across prompt, Unicode, URL, payload-schema, and spend-mandate checks, returning ALLOW, REVIEW, or BLOCK with a reproducible receipt hash.",
    input_schema: ACTION_GATE_INPUT_SCHEMA,
  },
];

export const TOOL_NAMES = Object.freeze(definitions.map(({ name }) => name));

export function catalog() {
  return definitions.map(({ name, description, input_schema }) => ({
    name,
    version: VERSION,
    description,
    input_schema,
    quota_units: 1,
    paygo_price_usdc: "0.01",
  }));
}

export function guardCatalog(publicOrigin) {
  return {
    product: "GoldKey Guard",
    status: "beta",
    availability: "feature_gated",
    pass_included: false,
    description: "Paid signed authorization for exact MCP, HTTPS, or supported EVM calls. The hosted authorizer evaluates operator-signed policy and never forwards; a customer-controlled local enforcer holds credentials or signing authority and forwards only an unexpired ALLOW.",
    pricing: {
      mcp_or_https_authorization_usdc: "0.05",
      evm_authorization_usdc: "0.10",
      decisions_billed: ["ALLOW", "REVIEW", "BLOCK"],
      exact_unexpired_idempotent_replay_billed: false,
    },
    topology: {
      hosted_authorizer: "Verifies signed policy, installation, exact call, and payment; returns a signed short-lived decision receipt; never receives upstream credentials and never forwards, signs, or broadcasts the action.",
      local_enforcer: "Operator-controlled execution-path component that alone holds the upstream credential or wallet signer, verifies the receipt against the exact call and pinned policy, commits FORWARDING, and then invokes the configured connector.",
      enforcement_requirement: "The guarded agent must have no direct credential, signer, or network path that bypasses the local enforcer.",
    },
    distribution: {
      package: "@goldkey/enforcer",
      version: "0.2.1",
      artifact: `${publicOrigin}/.well-known/goldkey-guard/goldkey-enforcer-0.2.1.tgz`,
      integrity_manifest: `${publicOrigin}/.well-known/goldkey-guard/goldkey-enforcer-0.2.1.tgz.integrity.json`,
      size_bytes: 120073,
      sha256: "62dbeb10684e075a9ca7d08862eaa99b30f2c2f958bba3f9cc8ecbd7c212d3e5",
      adapters: ["mcp_stdio", "agentcash", "base_wallet"],
      install_policy: "Download, verify bytes against the pinned digest, then install the local tarball with lifecycle scripts disabled. Do not install a similarly named registry package.",
    },
    routes: {
      terms: `${publicOrigin}/guard/terms`,
      policy_registration: `${publicOrigin}/v1/guard/policies`,
      installation_registration: `${publicOrigin}/v1/guard/installations`,
      revocation: `${publicOrigin}/v1/guard/revocations`,
      network_authorization: `${publicOrigin}/v1/guard/paygo/authorize/network`,
      evm_authorization: `${publicOrigin}/v1/guard/paygo/authorize/evm`,
      commit_template: `${publicOrigin}/v1/guard/executions/{executionId}/commit`,
      reconcile_commit_template: `${publicOrigin}/v1/guard/executions/{executionId}/reconcile-commit`,
      complete_template: `${publicOrigin}/v1/guard/executions/{executionId}/complete`,
      receipt_keyset: `${publicOrigin}/.well-known/goldkey-guard-keys.json`,
    },
  };
}
