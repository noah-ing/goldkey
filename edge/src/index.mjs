import { catalog } from "./catalog.mjs";
import { createChainClient } from "./chain.mjs";
import { calculateQuote, calculateRenewalQuote, renderCommerceResponse } from "./commerce.mjs";
import { commerceConfig, isCommerceConfigured, originUrl, publicOrigin } from "./config.mjs";
import { EdgeError, assert } from "./errors.mjs";
import { buildMetadata } from "./metadata.mjs";
import { buildOffer } from "./offer.mjs";
import { buildOpenApi } from "./openapi.mjs";

const VERSION = "1.0.0";
const MAX_JSON_BYTES = 64 * 1024;
const MAX_PROXY_BYTES = 1024 * 1024;
const SUPPLY_CACHE_MS = 5_000;
const DOMAIN_SKILL_ASSETS = new Map([
  ["/.well-known/agent-skills/index.json", "application/json; charset=utf-8"],
  ["/.well-known/agent-skills/goldkey-agent-utilities.tar.gz", "application/gzip"],
]);

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

function withPublicHeaders(response, requestId) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-expose-headers", "payment-required,payment-response,x-request-id");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-request-id", requestId);
  headers.delete("server");
  headers.delete("x-powered-by");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function parseJson(request, limit = MAX_JSON_BYTES) {
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  assert(Number.isFinite(contentLength) && contentLength <= limit, 413, "request_too_large", `Request body must not exceed ${limit} bytes`);
  const bytes = new Uint8Array(await request.arrayBuffer());
  assert(bytes.byteLength <= limit, 413, "request_too_large", `Request body must not exceed ${limit} bytes`);
  assert(bytes.byteLength > 0, 400, "invalid_json", "Request body must contain JSON");
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new EdgeError(400, "invalid_json", "Request body must contain valid JSON");
  }
}

function proxyRoute(pathname, method) {
  const allowed = new Map([
    ["/v1/auth/challenge", ["POST"]],
    ["/v1/auth/verify", ["POST"]],
    ["/v1/quota", ["GET"]],
    ["/v1/keys", ["GET", "POST", "DELETE"]],
    ["/v1/paygo/execute", ["POST"]],
  ]);
  const exact = allowed.get(pathname);
  if (exact) return { known: true, allowed: exact.includes(method) };
  if (/^\/v1\/keys\/[^/]+$/.test(pathname)) return { known: true, allowed: method === "DELETE" };
  if (/^\/v1\/tools\/[^/]+$/.test(pathname)) return { known: true, allowed: method === "POST" };
  return { known: false, allowed: false };
}

async function proxyToOrigin(request, env, fetchImpl) {
  const base = originUrl(env);
  const source = new URL(request.url);
  const target = new URL(base);
  target.pathname = source.pathname;
  target.search = source.search;

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  assert(Number.isFinite(contentLength) && contentLength <= MAX_PROXY_BYTES, 413, "request_too_large", `Proxied request body must not exceed ${MAX_PROXY_BYTES} bytes`);
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");
  headers.set("x-forwarded-host", source.host);
  headers.set("x-forwarded-proto", source.protocol.slice(0, -1));
  headers.set("x-goldkey-edge", "1");

  let body;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const bytes = await request.arrayBuffer();
    assert(bytes.byteLength <= MAX_PROXY_BYTES, 413, "request_too_large", `Proxied request body must not exceed ${MAX_PROXY_BYTES} bytes`);
    body = bytes;
  }

  let response;
  try {
    response = await fetchImpl(target.toString(), { method: request.method, headers, body, redirect: "manual" });
  } catch {
    throw new EdgeError(502, "origin_unavailable", "The stateful utility origin is unavailable");
  }

  const responseHeaders = new Headers(response.headers);
  responseHeaders.set("cache-control", "no-store");
  const location = responseHeaders.get("location");
  if (location) {
    try {
      const redirect = new URL(location, target);
      if (redirect.origin === target.origin) {
        redirect.protocol = source.protocol;
        redirect.host = source.host;
        responseHeaders.set("location", redirect.toString());
      }
    } catch {
      responseHeaders.delete("location");
    }
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
}

async function asset(env, request, assetPath, contentType) {
  assert(env.ASSETS && typeof env.ASSETS.fetch === "function", 503, "assets_unavailable", "Static edge assets are unavailable");
  const url = new URL(request.url);
  url.pathname = assetPath;
  url.search = "";
  const response = await env.ASSETS.fetch(new Request(url, { method: "GET" }));
  assert(response.ok, 503, "assets_unavailable", "A required static edge asset is unavailable");
  const headers = new Headers(response.headers);
  headers.set("content-type", contentType);
  headers.set("cache-control", "public, max-age=300");
  return new Response(response.body, { status: 200, headers });
}

function configCacheKey(config) {
  return [config.chainId, config.rpcUrl, config.contractAddress, config.usdcAddress, config.treasuryAddress, config.expectedTermsHash].join("|");
}

export function createWorker({ fetchImpl = fetch, clock = () => Date.now() } = {}) {
  const supplyCache = new Map();

  async function liveSupply(config, chain) {
    const key = configCacheKey(config);
    const cached = supplyCache.get(key);
    if (cached && cached.expiresAt > clock()) return cached.promise;
    const promise = chain.supplyState();
    supplyCache.set(key, { expiresAt: clock() + SUPPLY_CACHE_MS, promise });
    try {
      return await promise;
    } catch (error) {
      supplyCache.delete(key);
      throw error;
    }
  }

  async function route(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const pathname = url.pathname;

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
          "access-control-allow-headers": "authorization,content-type,idempotency-key,payment-signature,x-payment",
          "access-control-max-age": "86400",
        },
      });
    }

    if (pathname === "/healthz" && method === "GET") {
      return json({
        ok: true,
        service: "goldkey-edge",
        version: VERSION,
        storefront: "ready",
        commerce_configured: isCommerceConfigured(request, env),
        origin_checked: false,
      }, 200, { "cache-control": "no-store" });
    }

    const domainSkillContentType = DOMAIN_SKILL_ASSETS.get(pathname);
    if (domainSkillContentType && method === "GET") {
      return asset(env, request, pathname, domainSkillContentType);
    }

    if (pathname === "/terms" && method === "GET") return asset(env, request, "/TERMS.md", "text/markdown; charset=utf-8");
    if (pathname === "/v1/demo" && method === "GET") return asset(env, request, "/demo.json", "application/json; charset=utf-8");
    if (pathname === "/schemas/commerce-response-v1.json" && method === "GET") {
      return asset(env, request, "/schemas/commerce-response-v1.json", "application/schema+json; charset=utf-8");
    }

    const origin = publicOrigin(request, env);
    if (pathname === "/openapi.json" && method === "GET") {
      return json(buildOpenApi({ publicOrigin: origin }), 200, { "cache-control": "public, max-age=300" });
    }
    if (pathname === "/.well-known/agent.json" && method === "GET") {
      return json({
        name: "GoldKey Commerce Agent",
        version: VERSION,
        description: "Always-on discovery and Base-RPC-backed commerce for GoldKey; stateful authentication and utility fulfillment may cold-start.",
        offer: `${origin}/.well-known/goldkey.json`,
        openapi: `${origin}/openapi.json`,
        free_demo: `${origin}/v1/demo`,
        response_schema: `${origin}/schemas/commerce-response-v1.json`,
        decision_rule: "Buy only when risk-adjusted expected paygo cost exceeds pass cost.",
        commerce_configured: isCommerceConfigured(request, env),
        fulfillment: { topology: "stateful_origin", may_cold_start: true },
      }, 200, { "cache-control": "public, max-age=300" });
    }
    if (pathname === "/v1/catalog" && method === "GET") {
      return json({
        tools: catalog(),
        pricing: { paygo_per_call_usdc: "0.01", pass_price_usdc: "50.00", calls_per_pass: 10_000, pass_term_days: 365 },
        fulfillment: { topology: "stateful_origin", may_cold_start: true },
      }, 200, { "cache-control": "public, max-age=300" });
    }

    if (pathname === "/.well-known/goldkey.json" && method === "GET") {
      const config = commerceConfig(request, env);
      const chain = createChainClient(config, fetchImpl);
      const offer = await buildOffer(config, { supplyState: () => liveSupply(config, chain) });
      return json(offer, 200, { "cache-control": "public, max-age=5" });
    }

    if ((pathname === "/v1/purchase/quote" || pathname === "/v1/commerce/respond") && method === "POST") {
      const input = await parseJson(request);
      const config = commerceConfig(request, env);
      const chain = createChainClient(config, fetchImpl);
      const quote = calculateQuote(input, config, chain, await liveSupply(config, chain));
      return json(pathname.endsWith("/respond") ? { ...quote, sales_message: renderCommerceResponse(quote) } : quote, 200, { "cache-control": "no-store" });
    }

    if (pathname === "/v1/renewal/quote" && method === "POST") {
      const input = await parseJson(request);
      assert(typeof input?.token_id === "string" && /^[1-9]\d*$/.test(input.token_id), 400, "invalid_token_id", "token_id must be a canonical positive integer string");
      const config = commerceConfig(request, env);
      const chain = createChainClient(config, fetchImpl);
      await liveSupply(config, chain);
      const pass = await chain.passState(input.token_id);
      assert(pass.term !== "0" && pass.owner.toLowerCase() !== "0x0000000000000000000000000000000000000000", 404, "goldkey_not_found", "GoldKey token does not exist");
      return json(calculateRenewalQuote(input, config, chain, pass), 200, { "cache-control": "no-store" });
    }

    const metadataMatch = pathname.match(/^\/metadata\/([^/]+)$/);
    if (metadataMatch && method === "GET") {
      let tokenId;
      try {
        tokenId = decodeURIComponent(metadataMatch[1]);
      } catch {
        throw new EdgeError(400, "invalid_token_id", "tokenId must be a canonical positive integer string");
      }
      assert(/^[1-9]\d*$/.test(tokenId), 400, "invalid_token_id", "tokenId must be a canonical positive integer string");
      const config = commerceConfig(request, env);
      const chain = createChainClient(config, fetchImpl);
      await liveSupply(config, chain);
      const metadata = await buildMetadata(tokenId, config, chain);
      return json(metadata, 200, { "cache-control": "public, max-age=60" });
    }

    const proxy = proxyRoute(pathname, method);
    if (proxy.known && !proxy.allowed) {
      return json({ error: { code: "method_not_allowed", message: "Method not allowed" } }, 405, { allow: pathname.includes("/keys/") ? "DELETE" : "GET, POST, DELETE" });
    }
    if (proxy.allowed) return proxyToOrigin(request, env, fetchImpl);

    return json({ error: { code: "not_found", message: "Route not found" } }, 404, { "cache-control": "no-store" });
  }

  return {
    async fetch(request, env = {}) {
      const requestId = crypto.randomUUID();
      try {
        return withPublicHeaders(await route(request, env), requestId);
      } catch (error) {
        if (error instanceof EdgeError) {
          return withPublicHeaders(json({
            error: {
              code: error.code,
              message: error.message,
              ...(error.details === undefined ? {} : { details: error.details }),
            },
            request_id: requestId,
          }, error.status, { "cache-control": "no-store" }), requestId);
        }
        return withPublicHeaders(json({ error: { code: "internal_error", message: "Internal edge error" }, request_id: requestId }, 500, { "cache-control": "no-store" }), requestId);
      }
    },
  };
}

export default createWorker();
