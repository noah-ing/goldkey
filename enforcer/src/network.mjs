import { resolve4 as defaultResolve4, resolve6 as defaultResolve6 } from "node:dns/promises";
import { request as defaultHttpsRequest } from "node:https";
import { isIP } from "node:net";
import { canonicalBytes } from "./canonical.mjs";
import {
  DeadlineExceededError,
  InvalidInputError,
  NetworkPolicyError,
  ResponseLimitError,
} from "./errors.mjs";

export const MAX_REQUEST_BYTES = 64 * 1024;
export const MAX_RESPONSE_BYTES = 1024 * 1024;
export const MAX_DEADLINE_MS = 15_000;

const SAFE_RESPONSE_HEADERS = new Set([
  "cache-control", "content-language", "content-length", "content-type", "date", "etag",
  "expires", "last-modified", "retry-after", "x-request-id",
]);
const FORBIDDEN_HOSTNAMES = /(^|\.)(localhost|local|internal|home\.arpa|onion|test|invalid|example)$/i;

function ipv4Integer(address) {
  const parts = address.split(".");
  if (parts.length !== 4) return undefined;
  let value = 0n;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function inV4Cidr(value, base, bits) {
  const shift = 32n - BigInt(bits);
  return (value >> shift) === (ipv4Integer(base) >> shift);
}

const BLOCKED_V4 = Object.freeze([
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
]);

function ipv6Integer(rawAddress) {
  if (typeof rawAddress !== "string" || rawAddress.includes("%")) return undefined;
  let address = rawAddress.toLowerCase();
  const dottedIndex = address.lastIndexOf(":");
  if (address.includes(".")) {
    if (dottedIndex < 0) return undefined;
    const v4 = ipv4Integer(address.slice(dottedIndex + 1));
    if (v4 === undefined) return undefined;
    address = address.slice(0, dottedIndex) + ":" + Number((v4 >> 16n) & 0xffffn).toString(16) + ":" + Number(v4 & 0xffffn).toString(16);
  }
  if ((address.match(/::/g) ?? []).length > 1) return undefined;
  const halves = address.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && left.length !== 8) return undefined;
  const missing = 8 - left.length - right.length;
  if (missing < (halves.length === 2 ? 1 : 0)) return undefined;
  const words = [...left, ...Array(missing).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return undefined;
  return words.reduce((value, word) => (value << 16n) | BigInt("0x" + word), 0n);
}

function inV6Cidr(value, base, bits) {
  const shift = 128n - BigInt(bits);
  return (value >> shift) === (ipv6Integer(base) >> shift);
}

export function isPublicIpAddress(address) {
  const family = isIP(address);
  if (family === 4) {
    const value = ipv4Integer(address);
    return value !== undefined && !BLOCKED_V4.some(([base, bits]) => inV4Cidr(value, base, bits));
  }
  if (family !== 6) return false;
  const value = ipv6Integer(address);
  if (value === undefined) return false;
  if (inV6Cidr(value, "::ffff:0:0", 96)) {
    return isPublicIpAddress([
      Number((value >> 24n) & 255n),
      Number((value >> 16n) & 255n),
      Number((value >> 8n) & 255n),
      Number(value & 255n),
    ].join("."));
  }
  if (!inV6Cidr(value, "2000::", 3)) return false;
  return ![
    ["2001::", 23],
    ["2001:db8::", 32],
    ["2002::", 16],
    ["3fff::", 20],
  ].some(([base, bits]) => inV6Cidr(value, base, bits));
}

function dnsValues(result) {
  return result.map((entry) => typeof entry === "string" ? entry : entry?.address);
}

function ignorableDnsError(error) {
  return ["ENODATA", "ENOTFOUND", "ENONAME"].includes(error?.code);
}

export async function resolvePublicAddresses(hostname, {
  resolve4 = defaultResolve4,
  resolve6 = defaultResolve6,
} = {}) {
  if (typeof hostname !== "string" || hostname.length < 1 || hostname.length > 253 || hostname.includes("\0")) {
    throw new NetworkPolicyError("HTTPS destination has an invalid hostname");
  }
  if (isIP(hostname) !== 0) throw new NetworkPolicyError("Literal-IP HTTPS origins are forbidden; use a verified DNS name");
  const lower = hostname.toLowerCase().replace(/\.$/, "");
  if (FORBIDDEN_HOSTNAMES.test(lower) || lower === "instance-data" || lower === "metadata") {
    throw new NetworkPolicyError("Local, special-use, and metadata hostnames are forbidden");
  }
  const settled = await Promise.allSettled([
    resolve4(lower, { ttl: true }),
    resolve6(lower, { ttl: true }),
  ]);
  for (const result of settled) {
    if (result.status === "rejected" && !ignorableDnsError(result.reason)) {
      throw new NetworkPolicyError("Destination DNS resolution failed closed", { code: result.reason?.code });
    }
  }
  const addresses = settled.flatMap((result) => result.status === "fulfilled" ? dnsValues(result.value) : []);
  const distinct = [...new Set(addresses)];
  if (distinct.length < 1) throw new NetworkPolicyError("Destination DNS name has no A or AAAA addresses");
  if (distinct.length > 64) throw new NetworkPolicyError("Destination DNS answer set is unreasonably large");
  const denied = distinct.filter((address) => !isPublicIpAddress(address));
  if (denied.length > 0) {
    throw new NetworkPolicyError("Destination DNS answer contains a private, reserved, or invalid address", { denied });
  }
  return Object.freeze(distinct.map((address) => Object.freeze({ address, family: isIP(address) })));
}

function safeResponseHeaders(rawHeaders) {
  const result = {};
  for (const [name, value] of Object.entries(rawHeaders ?? {})) {
    const lower = name.toLowerCase();
    if (!SAFE_RESPONSE_HEADERS.has(lower) || value === undefined) continue;
    const text = Array.isArray(value) ? value.join(", ") : String(value);
    if (!/[\r\n\0]/.test(text)) result[lower] = text;
  }
  return Object.freeze(result);
}

export function buildHttpsRequest({ connector, operation, call }) {
  const url = new URL(operation.path, connector.origin);
  if (url.origin !== connector.origin || url.pathname !== operation.path) throw new NetworkPolicyError("HTTPS operation path changed its operator-controlled destination");
  if (call.query !== undefined) {
    for (const key of Object.keys(call.query).sort()) {
      const values = Array.isArray(call.query[key]) ? call.query[key] : [call.query[key]];
      for (const value of values) url.searchParams.append(key, value);
    }
  }
  const body = call.body === undefined ? Buffer.alloc(0) : canonicalBytes(call.body);
  const headers = {
    ...connector.trusted_headers,
    "accept-encoding": "identity",
    ...(body.byteLength === 0 ? {} : { "content-type": "application/json", "content-length": String(body.byteLength) }),
  };
  const headerBytes = Object.entries(headers).reduce((total, [name, value]) => total + Buffer.byteLength(name) + Buffer.byteLength(value) + 4, 0);
  const requestBytes = Buffer.byteLength(operation.method) + Buffer.byteLength(url.pathname + url.search) + 12 + headerBytes + body.byteLength;
  if (requestBytes > MAX_REQUEST_BYTES) throw new ResponseLimitError("Guarded HTTPS request exceeds 64 KiB", { request_bytes: requestBytes });
  return Object.freeze({ url, method: operation.method, headers: Object.freeze(headers), body });
}

export function performPinnedHttpsRequest({
  request,
  pinnedAddress,
  requestImpl = defaultHttpsRequest,
  signal,
  maxResponseBytes = MAX_RESPONSE_BYTES,
}) {
  if (!request?.url || !pinnedAddress?.address || ![4, 6].includes(pinnedAddress.family)) throw new InvalidInputError("Pinned HTTPS request inputs are invalid");
  if (signal?.aborted) throw new DeadlineExceededError("Guarded HTTPS deadline already expired");
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abort);
      if (error) reject(error);
      else resolve(value);
    };
    const abort = () => {
      const error = new DeadlineExceededError("Guarded HTTPS request exceeded its deadline");
      outgoing?.destroy?.(error);
      finish(error);
    };
    let outgoing;
    try {
      outgoing = requestImpl({
        protocol: "https:",
        hostname: request.url.hostname,
        port: request.url.port || 443,
        servername: request.url.hostname,
        family: pinnedAddress.family,
        lookup(_hostname, _options, callback) {
          callback(null, pinnedAddress.address, pinnedAddress.family);
        },
        method: request.method,
        path: request.url.pathname + request.url.search,
        headers: request.headers,
        agent: false,
        maxHeaderSize: 16 * 1024,
        rejectUnauthorized: true,
        signal,
      }, (response) => {
        const contentLength = response.headers?.["content-length"];
        if (contentLength !== undefined && (!/^\d+$/.test(String(contentLength)) || Number(contentLength) > maxResponseBytes)) {
          response.destroy?.();
          finish(new ResponseLimitError("Guarded HTTPS response exceeds 1 MiB"));
          return;
        }
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          if (settled) return;
          const bytes = Buffer.from(chunk);
          length += bytes.byteLength;
          if (length > maxResponseBytes) {
            response.destroy?.();
            outgoing.destroy?.();
            finish(new ResponseLimitError("Guarded HTTPS response exceeds 1 MiB"));
            return;
          }
          chunks.push(bytes);
        });
        response.on("end", () => {
          finish(undefined, Object.freeze({
            status: response.statusCode ?? 0,
            headers: safeResponseHeaders(response.headers),
            body: Buffer.concat(chunks, length),
          }));
        });
        response.on("error", (error) => finish(error));
      });
    } catch (error) {
      finish(error);
      return;
    }
    signal?.addEventListener("abort", abort, { once: true });
    outgoing.on("error", (error) => {
      if (signal?.aborted) finish(new DeadlineExceededError("Guarded HTTPS request exceeded its deadline", { cause: error }));
      else finish(error);
    });
    if (request.body.byteLength > 0) outgoing.write(request.body);
    outgoing.end();
  });
}
