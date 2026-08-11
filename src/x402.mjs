import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/express";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { createCdpFacilitatorAuth } from "./cdp-auth.mjs";
import { TOOL_REGISTRY } from "./tools.mjs";

const DISCOVERY_TOOL_NAMES = Object.freeze(Object.keys(TOOL_REGISTRY));
const DISCOVERY_DESCRIPTION = "Seven deterministic agent utilities: action.gate returns one ALLOW, REVIEW, or BLOCK preflight with a reproducible receipt hash; json.canonicalize creates stable hashes; json.validate checks bounded schemas; security.prompt_scan flags injection/exfiltration signals; security.url_check screens destinations; policy.spend_check enforces atomic caps; text.normalize canonicalizes Unicode. One call costs 0.01 USDC on Base.";
const ACTION_GATE_DESCRIPTION = "$0.01 AI-agent tool-call preflight: return ALLOW, REVIEW, or BLOCK before an MCP/tool call, payment, fetch, message, write, or execution. One deterministic request combines prompt-injection and hidden-Unicode scanning, SSRF/unsafe-URL screening, JSON Schema payload validation, and atomic spend-mandate enforcement. Returns stable reason codes plus request_sha256 and receipt_sha256; never executes the action; hashes are reproducible, not signatures.";

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
  return routes;
}

export function createX402Middleware(config) {
  const facilitator = createFacilitator(config);
  const network = `eip155:${config.chainId}`;
  const resourceServer = new x402ResourceServer(facilitator).register(network, new ExactEvmScheme());
  const routes = buildX402Routes(config);
  return paymentMiddleware(routes, resourceServer);
}
