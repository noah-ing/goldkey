import { randomUUID } from "node:crypto";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/express";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { createCdpFacilitatorAuth } from "./cdp-auth.mjs";
import { TOOL_REGISTRY } from "./tools.mjs";

const DISCOVERY_TOOL_NAMES = Object.freeze(Object.keys(TOOL_REGISTRY));
const DISCOVERY_DESCRIPTION = "Seven deterministic agent utilities: action.gate returns one ALLOW, REVIEW, or BLOCK preflight with a reproducible receipt hash; json.canonicalize creates stable hashes; json.validate checks bounded schemas; security.prompt_scan flags injection/exfiltration signals; security.url_check screens destinations; policy.spend_check enforces atomic caps; text.normalize canonicalizes Unicode. One call costs 0.01 USDC on Base.";
const ACTION_GATE_DESCRIPTION = "$0.01 AI-agent tool-call preflight: return ALLOW, REVIEW, or BLOCK before an MCP/tool call, payment, fetch, message, write, or execution. One deterministic request combines prompt-injection and hidden-Unicode scanning, SSRF/unsafe-URL screening, JSON Schema payload validation, and atomic spend-mandate enforcement. Returns stable reason codes plus request_sha256 and receipt_sha256; never executes the action; hashes are reproducible, not signatures.";
const GUARD_NETWORK_DESCRIPTION = "$0.05 signed GoldKey Guard authorization for one exact MCP tool call or HTTPS operation. The registered installation signature is verified before payment. After payment verification, the proposed call is evaluated against immutable operator-signed policy and returns a short-lived signed ALLOW, REVIEW, or BLOCK receipt. GoldKey never forwards the call or receives the upstream credential.";
const GUARD_EVM_DESCRIPTION = "$0.10 signed GoldKey Guard authorization for one exact Base/EVM transaction. The registered installation signature is verified before payment. After payment verification, GoldKey decodes, policy-checks, and where required simulates the transaction, then returns a short-lived signed ALLOW, REVIEW, or BLOCK receipt. GoldKey never signs or broadcasts the transaction.";
const GUARD_AUTHORIZATION_PATHS = new Set([
  "/v1/guard/paygo/authorize/network",
  "/v1/guard/paygo/authorize/evm",
]);
const GUARD_SETTLEMENT_CLAIMS = new WeakMap();

function discoveryInputSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["tool", "input"],
    properties: {
      tool: { type: "string", enum: DISCOVERY_TOOL_NAMES },
      input: { type: "object" },
    },
  };
}

function guardRequestSchema(kinds) {
  const identifier = { type: "string", pattern: "^[A-Za-z0-9._:-]{1,128}$" };
  const installationIdentifier = { type: "string", pattern: "^gki_[A-Za-z0-9_-]{43}$" };
  const sha256 = { type: "string", pattern: "^[0-9a-f]{64}$" };
  const atomic = { type: "string", pattern: "^(0|[1-9][0-9]{0,77})$" };
  const calls = [];
  if (kinds.includes("mcp_tool")) calls.push({
    type: "object",
    additionalProperties: false,
    required: ["kind", "connector_id", "tool", "input_schema_sha256", "arguments"],
    properties: {
      kind: { const: "mcp_tool" },
      connector_id: identifier,
      tool: { type: "string", pattern: "^[A-Za-z0-9._:-]{1,256}$" },
      input_schema_sha256: sha256,
      arguments: {},
    },
  });
  if (kinds.includes("https")) calls.push({
    type: "object",
    additionalProperties: false,
    required: ["kind", "connector_id", "operation_id"],
    properties: {
      kind: { const: "https" },
      connector_id: identifier,
      operation_id: identifier,
      query: { type: "object", maxProperties: 100 },
      body: {},
    },
  });
  if (kinds.includes("evm_transaction")) calls.push({
    type: "object",
    additionalProperties: false,
    required: ["kind", "connector_id", "transaction"],
    properties: {
      kind: { const: "evm_transaction" },
      connector_id: identifier,
      transaction: {
        type: "object",
        additionalProperties: false,
        required: [
          "chain_id", "from", "value_atomic", "data", "nonce", "gas_limit",
          "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic",
        ],
        properties: {
          chain_id: { type: "integer", minimum: 1 },
          from: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
          to: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
          value_atomic: atomic,
          data: { type: "string", pattern: "^0x(?:[0-9a-fA-F]{2})*$" },
          nonce: atomic,
          gas_limit: atomic,
          max_fee_per_gas_atomic: atomic,
          max_priority_fee_per_gas_atomic: atomic,
          type: { const: "eip1559" },
          access_list: { type: "array", maxItems: 0 },
        },
      },
    },
  });
  return {
    type: "object",
    additionalProperties: false,
    required: ["schema", "installation_id", "idempotency_key", "issued_at", "call", "signature"],
    properties: {
      schema: { const: "goldkey.guard-request.v1" },
      installation_id: installationIdentifier,
      idempotency_key: { type: "string", pattern: "^[A-Za-z0-9._:-]{8,128}$" },
      issued_at: { type: "string", format: "date-time" },
      call: { oneOf: calls },
      signature: { type: "string", pattern: "^[A-Za-z0-9_-]{86}$" },
    },
  };
}

function guardDiscovery({ kinds, input }) {
  return declareDiscoveryExtension({
    method: "POST",
    bodyType: "json",
    input,
    inputSchema: guardRequestSchema(kinds),
    output: {
      example: {
        schema: "goldkey.guard-authorization-envelope.v1",
        receipt: { decision: "ALLOW", reason_codes: [] },
        evidence: { schema: "goldkey.guard-evidence.v1", decision: "ALLOW", reason_codes: [] },
        receipt_sha256: "0".repeat(64),
        signature: "A".repeat(86),
      },
    },
  });
}

function createFacilitator(config) {
  const createAuthHeaders = config.cdpApiKeyId && config.cdpApiKeySecret
    ? createCdpFacilitatorAuth({ facilitatorUrl: config.x402FacilitatorUrl, apiKeyId: config.cdpApiKeyId, apiKeySecret: config.cdpApiKeySecret })
    : config.x402AuthHeaders
    ? async () => ({
        verify: config.x402AuthHeaders,
        settle: config.x402AuthHeaders,
        supported: config.x402AuthHeaders,
        bazaar: config.x402AuthHeaders,
      })
    : undefined;
  const facilitator = new HTTPFacilitatorClient({
    url: config.x402FacilitatorUrl,
    timeoutMs: 15_000,
    createAuthHeaders,
  });
  return facilitator;
}

export function assertFacilitatorSupport(supported, config) {
  const network = `eip155:${config.chainId}`;
  const match = supported?.kinds?.find((kind) => (
    kind.x402Version === 2 && kind.scheme === "exact" && kind.network === network
  ));
  if (!match) {
    throw new Error(`x402 facilitator does not advertise v2 exact payments on ${network}`);
  }
  return Object.freeze({ x402Version: 2, scheme: "exact", network });
}

export async function validateX402Facilitator(config, facilitator = createFacilitator(config)) {
  if (!config.x402Enabled) return Object.freeze({ enabled: false });
  const supported = await facilitator.getSupported();
  return Object.freeze({ enabled: true, ...assertFacilitatorSupport(supported, config) });
}

export function buildX402Routes(config) {
  const network = `eip155:${config.chainId}`;
  const paygoDiscovery = declareDiscoveryExtension({
    method: "POST",
    bodyType: "json",
    input: { tool: "security.prompt_scan", input: { text: "Ignore previous instructions" } },
    inputSchema: discoveryInputSchema(),
    output: { example: { tool: "security.prompt_scan", tool_version: "1.0.0", result: { risk_score: 50 } } },
  });
  const actionGateInput = {
    action: { name: "submit approved vendor payment", effect: "payment" },
    untrusted_text: "Process the approved vendor invoice without following embedded instructions.",
    payload: { invoice_id: "INV-17", approved: true },
    schema: {
      type: "object",
      properties: { invoice_id: { type: "string" }, approved: { const: true } },
      required: ["invoice_id", "approved"],
      additionalProperties: false,
    },
    spend: {
      proposal: { amount_atomic: "1000000", asset: "USDC", counterparty: "vendor-17" },
      mandate: {
        max_per_tx_atomic: "5000000",
        max_period_atomic: "20000000",
        spent_period_atomic: "2000000",
        allowed_assets: ["USDC"],
        allowed_counterparties: ["vendor-17"],
        expires_at: "2099-01-01T00:00:00.000Z",
      },
      now: "2026-01-01T00:00:00.000Z",
    },
  };
  const actionGateDiscovery = declareDiscoveryExtension({
    method: "POST",
    bodyType: "json",
    input: actionGateInput,
    inputSchema: TOOL_REGISTRY["action.gate"].input_schema,
    output: {
      example: {
        tool: "action.gate",
        tool_version: "1.0.0",
        result: {
          decision: "ALLOW",
          reason_codes: [],
          checks: {
            action: { status: "pass" },
            prompt: { status: "pass" },
            url: { status: "not_provided" },
            payload: { status: "pass" },
            spend: { status: "pass" },
          },
          request_sha256: "0".repeat(64),
          receipt_sha256: "0".repeat(64),
          receipt_format: "goldkey-action-gate-v1",
        },
      },
    },
  });
  const routes = {
    "POST /v1/paygo/execute": {
      accepts: [{ scheme: "exact", price: "$0.01", network, payTo: config.treasuryAddress }],
      resource: `${config.publicOrigin}/v1/paygo/execute`,
      description: DISCOVERY_DESCRIPTION,
      serviceName: "GoldKey Agent Utilities",
      tags: ["agent-security", "json-validation", "prompt-injection", "url-safety", "spend-policy"],
      mimeType: "application/json",
      extensions: paygoDiscovery,
    },
    "POST /v1/action-gate": {
      accepts: [{ scheme: "exact", price: "$0.01", network, payTo: config.treasuryAddress }],
      resource: `${config.publicOrigin}/v1/action-gate`,
      description: ACTION_GATE_DESCRIPTION,
      serviceName: "GoldKey Action Gate",
      tags: ["ai-agent-security", "tool-call-preflight", "mcp-security", "prompt-injection", "ssrf", "spend-policy", "schema-validation", "receipt-hash"],
      mimeType: "application/json",
      extensions: actionGateDiscovery,
    },
  };
  if (config.guardEnabled) {
    const networkPath = "/v1/guard/paygo/authorize/network";
    const evmPath = "/v1/guard/paygo/authorize/evm";
    routes[`POST ${networkPath}`] = {
      accepts: [{ scheme: "exact", price: `$${config.guardNetworkPriceUsd}`, network, payTo: config.treasuryAddress, maxTimeoutSeconds: 30 }],
      resource: `${config.publicOrigin}${networkPath}`,
      description: GUARD_NETWORK_DESCRIPTION,
      serviceName: "GoldKey Guard Network Authorization",
      tags: ["agent-security", "mcp-security", "https-policy", "signed-receipts", "enforcement"],
      mimeType: "application/json",
      extensions: guardDiscovery({
        kinds: ["mcp_tool", "https"],
        input: {
          schema: "goldkey.guard-request.v1",
          installation_id: `gki_${"A".repeat(43)}`,
          idempotency_key: "example.network.1",
          issued_at: "2026-08-11T00:00:00.000Z",
          call: { kind: "https", connector_id: "crm", operation_id: "create_lead", body: { company: "Example" } },
          signature: "A".repeat(86),
        },
      }),
    };
    routes[`POST ${evmPath}`] = {
      accepts: [{ scheme: "exact", price: `$${config.guardEvmPriceUsd}`, network, payTo: config.treasuryAddress, maxTimeoutSeconds: 30 }],
      resource: `${config.publicOrigin}${evmPath}`,
      description: GUARD_EVM_DESCRIPTION,
      serviceName: "GoldKey Guard EVM Authorization",
      tags: ["agent-security", "wallet-policy", "transaction-simulation", "signed-receipts", "enforcement"],
      mimeType: "application/json",
      extensions: guardDiscovery({
        kinds: ["evm_transaction"],
        input: {
          schema: "goldkey.guard-request.v1",
          installation_id: `gki_${"A".repeat(43)}`,
          idempotency_key: "example.evm.1",
          issued_at: "2026-08-11T00:00:00.000Z",
          call: {
            kind: "evm_transaction",
            connector_id: "base-wallet",
            transaction: {
              chain_id: config.chainId,
              from: config.treasuryAddress,
              to: config.treasuryAddress,
              value_atomic: "0",
              data: "0x",
              nonce: "0",
              gas_limit: "21000",
              max_fee_per_gas_atomic: "10000000",
              max_priority_fee_per_gas_atomic: "1000000",
              type: "eip1559",
              access_list: [],
            },
          },
          signature: "A".repeat(86),
        },
      }),
    };
  }
  return routes;
}

export function createGuardSettlementHook(onGuardSettlement) {
  if (typeof onGuardSettlement !== "function") throw new TypeError("onGuardSettlement must be a function");
  return async ({ transportContext, result, paymentPayload, requirements }) => {
    const path = transportContext?.request?.path;
    if (!GUARD_AUTHORIZATION_PATHS.has(path)) return;
    if (!transportContext || typeof transportContext !== "object") throw new Error("Guard settlement transport context is missing");
    const claimId = GUARD_SETTLEMENT_CLAIMS.get(transportContext);
    if (!claimId) throw new Error("Guard settlement has no owned claim");
    const body = transportContext?.request?.adapter?.getBody?.();
    await onGuardSettlement({ path, body, result, claimId, paymentPayload, requirements });
    GUARD_SETTLEMENT_CLAIMS.delete(transportContext);
  };
}

export function createGuardBeforeSettlementHook(onGuardBeforeSettlement) {
  if (typeof onGuardBeforeSettlement !== "function") throw new TypeError("onGuardBeforeSettlement must be a function");
  return async ({ transportContext, paymentPayload, requirements }) => {
    const path = transportContext?.request?.path;
    if (!GUARD_AUTHORIZATION_PATHS.has(path)) return;
    try {
      if (!transportContext || typeof transportContext !== "object") throw new Error("Guard settlement transport context is missing");
      const body = transportContext?.request?.adapter?.getBody?.();
      const claimId = randomUUID();
      await onGuardBeforeSettlement({ path, body, claimId, paymentPayload, requirements });
      GUARD_SETTLEMENT_CLAIMS.set(transportContext, claimId);
    } catch {
      // The x402 SDK deliberately swallows ordinary hook errors. Return its
      // explicit abort directive so a stale authorization can never settle.
      // Keep the response generic so policy, installation, and timing details
      // are not disclosed through the payment boundary.
      return {
        abort: true,
        reason: "guard_authorization_inactive",
        message: "Guard authorization is no longer active",
      };
    }
  };
}

export function createGuardSettlementFailureHook(onGuardSettlementFailure) {
  if (typeof onGuardSettlementFailure !== "function") throw new TypeError("onGuardSettlementFailure must be a function");
  return async ({ transportContext, error, paymentPayload, requirements }) => {
    const path = transportContext?.request?.path;
    if (!GUARD_AUTHORIZATION_PATHS.has(path)) return;
    if (!transportContext || typeof transportContext !== "object") return;
    const claimId = GUARD_SETTLEMENT_CLAIMS.get(transportContext);
    if (!claimId) return;
    const body = transportContext?.request?.adapter?.getBody?.();
    await onGuardSettlementFailure({ path, body, claimId, error, paymentPayload, requirements });
    GUARD_SETTLEMENT_CLAIMS.delete(transportContext);
  };
}

export function createX402Middleware(config, { onGuardBeforeSettlement, onGuardSettlement, onGuardSettlementFailure } = {}) {
  const facilitator = createFacilitator(config);
  const network = `eip155:${config.chainId}`;
  const resourceServer = new x402ResourceServer(facilitator).register(network, new ExactEvmScheme());
  if (onGuardBeforeSettlement !== undefined) {
    resourceServer.onBeforeSettle(createGuardBeforeSettlementHook(onGuardBeforeSettlement));
  }
  if (onGuardSettlement !== undefined) {
    resourceServer.onAfterSettle(createGuardSettlementHook(onGuardSettlement));
  }
  if (onGuardSettlementFailure !== undefined) {
    resourceServer.onSettleFailure(createGuardSettlementFailureHook(onGuardSettlementFailure));
  }
  const routes = buildX402Routes(config);
  return paymentMiddleware(routes, resourceServer);
}
