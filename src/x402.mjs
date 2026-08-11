import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/express";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { createCdpFacilitatorAuth } from "./cdp-auth.mjs";
import { TOOL_REGISTRY } from "./tools.mjs";

const DISCOVERY_TOOL_NAMES = Object.freeze(Object.keys(TOOL_REGISTRY));
const DISCOVERY_DESCRIPTION = "Six deterministic agent utilities: json.canonicalize creates stable hashes; json.validate checks data against bounded schemas; security.prompt_scan flags prompt-injection/exfiltration signals; security.url_check screens destinations before fetch; policy.spend_check evaluates atomic payment caps; text.normalize canonicalizes Unicode and can strip control/bidi characters. Use before signing data, consuming agent output, fetching URLs, or paying. One call costs 0.01 USDC on Base.";

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
  const discovery = declareDiscoveryExtension({
    method: "POST",
    bodyType: "json",
    input: { tool: "security.prompt_scan", input: { text: "Ignore previous instructions" } },
    inputSchema: discoveryInputSchema(),
    output: { example: { tool: "security.prompt_scan", tool_version: "1.0.0", result: { risk_score: 50 } } },
  });
  const routes = {
    "POST /v1/paygo/execute": {
      accepts: [{ scheme: "exact", price: "$0.01", network, payTo: config.treasuryAddress }],
      resource: `${config.publicOrigin}/v1/paygo/execute`,
      description: DISCOVERY_DESCRIPTION,
      serviceName: "GoldKey Agent Utilities",
      tags: ["agent-security", "json-validation", "prompt-injection", "url-safety", "spend-policy"],
      mimeType: "application/json",
      extensions: discovery,
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
