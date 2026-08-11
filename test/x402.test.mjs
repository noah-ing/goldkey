import assert from "node:assert/strict";
import test from "node:test";
import { TOOL_REGISTRY } from "../src/tools.mjs";
import {
  assertFacilitatorSupport,
  buildX402Routes,
  createGuardBeforeSettlementHook,
  createGuardSettlementFailureHook,
  createGuardSettlementHook,
  validateX402Facilitator,
} from "../src/x402.mjs";

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

test("Guard uses separate fixed x402 prices for network and EVM authorization", () => {
  const routes = buildX402Routes({
    chainId: 8453,
    publicOrigin: "https://guard.example",
    treasuryAddress: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
    guardEnabled: true,
    guardNetworkPriceUsd: "0.05",
    guardEvmPriceUsd: "0.10",
  });
  const network = routes["POST /v1/guard/paygo/authorize/network"];
  const evm = routes["POST /v1/guard/paygo/authorize/evm"];

  assert.deepEqual(network.accepts, [{
    scheme: "exact",
    price: "$0.05",
    network: "eip155:8453",
    payTo: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
    maxTimeoutSeconds: 30,
  }]);
  assert.deepEqual(evm.accepts, [{
    scheme: "exact",
    price: "$0.10",
    network: "eip155:8453",
    payTo: "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b",
    maxTimeoutSeconds: 30,
  }]);
  assert.equal(network.resource, "https://guard.example/v1/guard/paygo/authorize/network");
  assert.equal(evm.resource, "https://guard.example/v1/guard/paygo/authorize/evm");
  assert.match(network.description, /never forwards/i);
  assert.match(evm.description, /never signs or broadcasts/i);
  const networkCalls = network.extensions.bazaar.schema.properties.input.properties.body.properties.call.oneOf;
  assert.equal(network.extensions.bazaar.schema.properties.input.properties.body.properties.installation_id.pattern, "^gki_[A-Za-z0-9_-]{43}$");
  assert.match(network.extensions.bazaar.info.input.body.installation_id, /^gki_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(networkCalls.map(({ properties }) => properties.kind.const), ["mcp_tool", "https"]);
  assert.deepEqual(networkCalls[0].required, ["kind", "connector_id", "tool", "input_schema_sha256", "arguments"]);
  const evmCall = evm.extensions.bazaar.schema.properties.input.properties.body.properties.call.oneOf[0];
  assert.equal(evmCall.properties.kind.const, "evm_transaction");
  assert.deepEqual(evmCall.properties.transaction.required, [
    "chain_id", "from", "value_atomic", "data", "nonce", "gas_limit",
    "max_fee_per_gas_atomic", "max_priority_fee_per_gas_atomic",
  ]);
  assert.equal(evmCall.properties.transaction.properties.type.const, "eip1559");
  assert.equal(evmCall.properties.transaction.properties.access_list.maxItems, 0);
  assert.deepEqual(Object.keys(routes), [
    "POST /v1/paygo/execute",
    "POST /v1/action-gate",
    "POST /v1/guard/paygo/authorize/network",
    "POST /v1/guard/paygo/authorize/evm",
  ]);
});

test("Guard settlement hook marks only successful protected authorization routes using the exact parsed request", async () => {
  const calls = [];
  const before = createGuardBeforeSettlementHook(async (value) => calls.push({ phase: "before", ...value }));
  const hook = createGuardSettlementHook(async (value) => calls.push(value));
  const body = { schema: "goldkey.guard-request.v1", installation_id: "install-1" };
  const result = { success: true, transaction: `0x${"a".repeat(64)}` };
  const paymentPayload = { x402Version: 2, payload: { authorization: { nonce: `0x${"b".repeat(64)}` } } };
  const requirements = { scheme: "exact", network: "eip155:8453" };
  const transportContext = {
      request: {
        path: "/v1/guard/paygo/authorize/network",
        adapter: { getBody: () => body },
      },
  };
  await before({ transportContext, paymentPayload, requirements });
  await hook({
    transportContext,
    result,
    paymentPayload,
    requirements,
  });
  await hook({
    transportContext: {
      request: {
        path: "/v1/action-gate",
        adapter: { getBody: () => ({}) },
      },
    },
    result,
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].phase, "before");
  assert.equal(calls[0].path, "/v1/guard/paygo/authorize/network");
  assert.equal(calls[0].body, body);
  assert.match(calls[0].claimId, /^[0-9a-f-]{36}$/);
  assert.deepEqual(calls[1], {
    path: "/v1/guard/paygo/authorize/network",
    body,
    result,
    claimId: calls[0].claimId,
    paymentPayload,
    requirements,
  });
});

test("Guard settlement failure cancels only the claim owned by that exact request", async () => {
  const calls = [];
  const before = createGuardBeforeSettlementHook(async (value) => calls.push({ phase: "before", ...value }));
  const failure = createGuardSettlementFailureHook(async (value) => calls.push({ phase: "failure", ...value }));
  const body = { schema: "goldkey.guard-request.v1", installation_id: "install-1" };
  const transportContext = {
    request: {
      path: "/v1/guard/paygo/authorize/evm",
      adapter: { getBody: () => body },
    },
  };
  await before({ transportContext });
  const error = new Error("facilitator failed");
  await failure({ transportContext, error });
  await failure({ transportContext, error: new Error("duplicate callback") });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].phase, "failure");
  assert.equal(calls[1].body, body);
  assert.equal(calls[1].claimId, calls[0].claimId);
  assert.equal(calls[1].error, error);
});

test("Guard before-settlement hook passes the exact parsed request only for protected authorization routes", async () => {
  const calls = [];
  const hook = createGuardBeforeSettlementHook(async (value) => calls.push(value));
  const body = { schema: "goldkey.guard-request.v1", installation_id: "install-1" };

  const active = await hook({
    transportContext: {
      request: {
        path: "/v1/guard/paygo/authorize/evm",
        adapter: { getBody: () => body },
      },
    },
  });
  const ignored = await hook({
    transportContext: {
      request: {
        path: "/v1/action-gate",
        adapter: { getBody: () => ({ should_not_be_read: true }) },
      },
    },
  });

  assert.equal(active, undefined);
  assert.equal(ignored, undefined);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].body, body);
  assert.equal(calls[0].path, "/v1/guard/paygo/authorize/evm");
  assert.match(calls[0].claimId, /^[0-9a-f-]{36}$/);
});

test("Guard before-settlement hook converts every active-state failure into a generic SDK abort", async () => {
  for (const state of ["revoked", "expired", "inactive"]) {
    const hook = createGuardBeforeSettlementHook(async () => {
      throw new Error(`sensitive ${state} policy details`);
    });
    const result = await hook({
      transportContext: {
        request: {
          path: "/v1/guard/paygo/authorize/network",
          adapter: { getBody: () => ({ state }) },
        },
      },
    });

    assert.deepEqual(result, {
      abort: true,
      reason: "guard_authorization_inactive",
      message: "Guard authorization is no longer active",
    });
    if (state !== "inactive") assert.doesNotMatch(JSON.stringify(result), new RegExp(state));
    assert.doesNotMatch(JSON.stringify(result), /sensitive|policy details/);
  }
});

test("Guard before-settlement hook fails closed when the parsed request cannot be read", async () => {
  const hook = createGuardBeforeSettlementHook(async () => {
    throw new Error("must not be reached");
  });
  const result = await hook({
    transportContext: {
      request: {
        path: "/v1/guard/paygo/authorize/network",
        adapter: { getBody: () => { throw new Error("parser internals"); } },
      },
    },
  });
  assert.deepEqual(result, {
    abort: true,
    reason: "guard_authorization_inactive",
    message: "Guard authorization is no longer active",
  });
});
