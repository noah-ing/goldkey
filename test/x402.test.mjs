import assert from "node:assert/strict";
import test from "node:test";
import { TOOL_REGISTRY } from "../src/tools.mjs";
import { assertFacilitatorSupport, buildX402Routes, validateX402Facilitator } from "../src/x402.mjs";

const config = Object.freeze({ chainId: 8453, x402Enabled: true });

test("x402 startup accepts only v2 exact support on the configured chain", async () => {
  const facilitator = {
    async getSupported() {
      return {
        kinds: [
          { x402Version: 1, scheme: "exact", network: "eip155:8453" },
          { x402Version: 2, scheme: "exact", network: "eip155:8453" },
        ],
      };
    },
  };
  assert.deepEqual(await validateX402Facilitator(config, facilitator), {
    enabled: true,
    x402Version: 2,
    scheme: "exact",
    network: "eip155:8453",
  });
});

test("x402 startup fails closed for the wrong network or protocol", () => {
  assert.throws(
    () => assertFacilitatorSupport({ kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:84532" }] }, config),
    /does not advertise v2 exact payments on eip155:8453/,
  );
  assert.throws(
    () => assertFacilitatorSupport({ kinds: [{ x402Version: 1, scheme: "exact", network: "eip155:8453" }] }, config),
    /does not advertise v2 exact payments on eip155:8453/,
  );
});

test("x402 startup skips facilitator calls when paygo is disabled", async () => {
  const result = await validateX402Facilitator({ ...config, x402Enabled: false }, {
    async getSupported() {
      throw new Error("must not be called");
    },
  });
  assert.deepEqual(result, { enabled: false });
});

test("x402 binds payment and Bazaar discovery to the permanent public origin", () => {
  const routes = buildX402Routes({
    chainId: 8453,
    publicOrigin: "https://goldkey-edge-storefront.noah-ing.workers.dev",
    treasuryAddress: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
  });
  const route = routes["POST /v1/paygo/execute"];
  const actionGateRoute = routes["POST /v1/action-gate"];

  assert.equal(route.resource, "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/paygo/execute");
  assert.deepEqual(route.accepts, [{
    scheme: "exact",
    price: "$0.01",
    network: "eip155:8453",
    payTo: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
  }]);
  assert.equal(route.serviceName, "GoldKey Agent Utilities");
  assert.deepEqual(route.tags, ["agent-security", "json-validation", "prompt-injection", "url-safety", "spend-policy"]);
  assert.ok(route.description.length <= 500);
  const toolNames = [
    "json.canonicalize",
    "json.validate",
    "security.prompt_scan",
    "security.url_check",
    "policy.spend_check",
    "text.normalize",
    "action.gate",
  ];
  for (const toolName of toolNames) {
    assert.ok(route.description.includes(toolName), `${toolName} must be described for Bazaar discovery`);
  }
  assert.match(route.description, /0\.01 USDC on Base/);
  assert.ok(route.extensions?.bazaar);

  const bodySchema = route.extensions.bazaar.schema.properties.input.properties.body;
  assert.deepEqual(Object.keys(TOOL_REGISTRY), toolNames);
  assert.deepEqual(bodySchema.properties.tool, { type: "string", enum: toolNames });
  assert.deepEqual(bodySchema.properties.input, { type: "object" });
  assert.equal(bodySchema.additionalProperties, false);
  assert.deepEqual(bodySchema.required, ["tool", "input"]);

  assert.equal(actionGateRoute.resource, "https://goldkey-edge-storefront.noah-ing.workers.dev/v1/action-gate");
  assert.deepEqual(actionGateRoute.accepts, route.accepts);
  assert.equal(actionGateRoute.serviceName, "GoldKey Action Gate");
  assert.deepEqual(actionGateRoute.tags, ["ai-agent-security", "tool-call-preflight", "mcp-security", "prompt-injection", "ssrf", "spend-policy", "schema-validation", "receipt-hash"]);
  assert.ok(actionGateRoute.description.length <= 500);
  assert.match(actionGateRoute.description, /ALLOW, REVIEW, or BLOCK/);
  assert.match(actionGateRoute.description, /request_sha256 and receipt_sha256/);
  assert.match(actionGateRoute.description, /hashes are reproducible, not signatures/);
  assert.match(actionGateRoute.description, /never executes the action/);
  assert.match(actionGateRoute.description, /AI-agent tool-call preflight/);
  assert.ok(actionGateRoute.extensions?.bazaar);
  const actionGateBodySchema = actionGateRoute.extensions.bazaar.schema.properties.input.properties.body;
  assert.deepEqual(actionGateBodySchema, TOOL_REGISTRY["action.gate"].input_schema);
  assert.deepEqual(Object.keys(routes), ["POST /v1/paygo/execute", "POST /v1/action-gate"]);
});
