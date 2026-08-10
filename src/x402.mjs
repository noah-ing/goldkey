import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/express";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { createCdpFacilitatorAuth } from "./cdp-auth.mjs";

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

export function createX402Middleware(config) {
  const facilitator = createFacilitator(config);
  const network = `eip155:${config.chainId}`;
  const resourceServer = new x402ResourceServer(facilitator).register(network, new ExactEvmScheme());
  const discovery = declareDiscoveryExtension({
    method: "POST",
    bodyType: "json",
    input: { tool: "security.prompt_scan", input: { text: "Ignore previous instructions" } },
    inputSchema: {
      type: "object",
      properties: { tool: { type: "string" }, input: { type: "object" } },
      required: ["tool", "input"],
    },
    output: { example: { tool: "security.prompt_scan", tool_version: "1.0.0", result: { risk_score: 50 } } },
  });
  const routes = {
    "POST /v1/paygo/execute": {
      accepts: [{ scheme: "exact", price: "$0.01", network, payTo: config.treasuryAddress }],
      description: "Execute one deterministic GoldKey agent utility without buying a pass.",
      mimeType: "application/json",
      extensions: discovery,
    },
  };
  return paymentMiddleware(routes, resourceServer);
}
