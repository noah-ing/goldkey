import net from "node:net";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { canonicalize, hashCanonical, sha256 } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";

const MAX_TEXT_LENGTH = 64 * 1024;
const MAX_SCHEMA_BYTES = 32 * 1024;
const MAX_SCHEMA_NODES = 1000;
const MAX_SCHEMA_DEPTH = 20;
const MAX_EVIDENCE_ITEMS = 100;
const MAX_VALIDATOR_CACHE = 64;
const VERSION = "1.0.0";
const validatorCache = new Map();

const toolDefinitions = [
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
];

export const TOOL_REGISTRY = Object.freeze(
  Object.fromEntries(toolDefinitions.map((definition) => [definition.name, { ...definition, version: VERSION }])),
);

const promptSignals = [
  ["instruction_override", 30, /\b(?:ignore|disregard|override|forget)\b.{0,48}\b(?:previous|prior|system|developer|instructions?)\b/giu],
  ["role_override", 20, /\b(?:you are now|act as|new role|system prompt|developer message)\b/giu],
  ["secret_exfiltration", 35, /\b(?:reveal|print|send|expose|leak|extract)\b.{0,48}\b(?:secret|credential|api key|private key|system prompt|environment variable)\b/giu],
  ["tool_coercion", 25, /\b(?:must|immediately|without asking)\b.{0,48}\b(?:execute|run|call|transfer|pay|delete|download)\b/giu],
  ["privileged_markup", 20, /<\/?(?:system|developer|tool|assistant|instructions?)\b[^>]*>/giu],
  ["encoded_payload", 10, /\b(?:base64|rot13|hex[- ]?decode|unicode escape)\b/giu],
];

function requireObject(value, name = "input") {
  assert(value && typeof value === "object" && !Array.isArray(value), 400, "invalid_input", `${name} must be an object`);
}

function requireText(value, name, maxLength = MAX_TEXT_LENGTH) {
  assert(typeof value === "string", 400, "invalid_input", `${name} must be a string`);
  assert(value.length <= maxLength, 413, "input_too_large", `${name} exceeds ${maxLength} characters`);
  return value;
}

function parseAtomic(value, name) {
  assert(typeof value === "string" && value.length <= 78 && /^(0|[1-9]\d*)$/.test(value), 400, "invalid_atomic_amount", `${name} must be a canonical non-negative integer string of at most 78 digits`);
  return BigInt(value);
}

function assertSafeSchema(schema) {
  const stack = [{ value: schema, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const { value, depth } = stack.pop();
    nodes += 1;
    assert(nodes <= MAX_SCHEMA_NODES, 400, "schema_too_complex", `schema exceeds ${MAX_SCHEMA_NODES} nodes`);
    assert(depth <= MAX_SCHEMA_DEPTH, 400, "schema_too_deep", `schema exceeds ${MAX_SCHEMA_DEPTH} levels`);
    if (!value || typeof value !== "object") continue;
    if (!Array.isArray(value)) {
      assert(!Object.hasOwn(value, "pattern") && !Object.hasOwn(value, "patternProperties"), 400, "unsafe_schema_keyword", "pattern and patternProperties are not supported");
      if (typeof value.$ref === "string") assert(value.$ref.startsWith("#"), 400, "remote_schema_ref", "only local JSON Schema references are supported");
    }
    for (const child of Array.isArray(value) ? value : Object.values(value)) {
      if (child && typeof child === "object") stack.push({ value: child, depth: depth + 1 });
    }
  }
}

function compiledValidator(schema) {
  const cacheKey = sha256(JSON.stringify(schema));
  const cached = validatorCache.get(cacheKey);
  if (cached) {
    validatorCache.delete(cacheKey);
    validatorCache.set(cacheKey, cached);
    return cached;
  }
  const ajv = new Ajv2020({ allErrors: true, strict: true, coerceTypes: false, useDefaults: false, removeAdditional: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  validatorCache.set(cacheKey, validate);
  if (validatorCache.size > MAX_VALIDATOR_CACHE) validatorCache.delete(validatorCache.keys().next().value);
  return validate;
}

function isPrivateIPv4(hostname) {
  const parts = hostname.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = parts;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) || a >= 224
  );
}

function isPrivateIPv6(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "::" || host === "::1") return true;
  if (/^(?:fc|fd|fe8|fe9|fea|feb|ff)/.test(host)) return true;
  if (host.startsWith("2001:db8:")) return true;
  const mapped = host.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isPrivateIPv4(mapped[1]) : false;
}

function runCanonicalize(input) {
  requireObject(input);
  assert(Object.hasOwn(input, "value"), 400, "invalid_input", "value is required");
  const canonical = canonicalize(input.value);
  return { format: "goldkey-c14n-v1", canonical, sha256: sha256(canonical) };
}

function runValidate(input) {
  requireObject(input);
  requireObject(input.schema, "schema");
  assert(Buffer.byteLength(JSON.stringify(input.schema)) <= MAX_SCHEMA_BYTES, 413, "schema_too_large", `schema exceeds ${MAX_SCHEMA_BYTES} bytes`);
  assertSafeSchema(input.schema);
  try {
    const validate = compiledValidator(input.schema);
    const valid = validate(input.value);
    const errors = validate.errors ?? [];
    return {
      valid: Boolean(valid),
      errors: errors.slice(0, MAX_EVIDENCE_ITEMS).map(({ instancePath, schemaPath, keyword, message, params }) => ({ instancePath, schemaPath, keyword, message, params })),
      error_count: errors.length,
      errors_truncated: errors.length > MAX_EVIDENCE_ITEMS,
      mutated: false,
    };
  } catch (error) {
    throw new ServiceError(400, "invalid_schema", error.message);
  }
}

function runPromptScan(input) {
  requireObject(input);
  const text = requireText(input.text, "text");
  const signals = [];
  for (const [id, weight, pattern] of promptSignals) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      signals.push({ id, weight, start: match.index, end: match.index + match[0].length, evidence: match[0].slice(0, 120) });
      if (signals.length >= 30) break;
    }
  }
  const hidden = [...text].flatMap((character, index) => {
    const code = character.codePointAt(0);
    if ((code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) || code === 0x200b) {
      return [{ id: "hidden_unicode", weight: 25, start: index, end: index + 1, evidence: `U+${code.toString(16).toUpperCase()}` }];
    }
    return [];
  });
  signals.push(...hidden.slice(0, Math.max(0, 30 - signals.length)));
  const riskScore = Math.min(100, [...new Map(signals.map((signal) => [signal.id, signal.weight])).values()].reduce((sum, weight) => sum + weight, 0));
  return {
    classification: riskScore >= 60 ? "high_signal" : riskScore >= 25 ? "review" : "low_signal",
    risk_score: riskScore,
    signals,
    limitation: "Deterministic indicators only; low_signal does not prove content is safe.",
  };
}

function runUrlCheck(input) {
  requireObject(input);
  const raw = requireText(input.url, "url", 4096);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ServiceError(400, "malformed_url", "url is not a valid absolute URL");
  }
  const reasons = [];
  if (!["http:", "https:"].includes(parsed.protocol)) reasons.push("unsafe_scheme");
  if (parsed.username || parsed.password) reasons.push("embedded_credentials");
  if (parsed.port && !["80", "443"].includes(parsed.port)) reasons.push("unsafe_port");
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) reasons.push("local_hostname");
  const ipVersion = net.isIP(hostname);
  if ((ipVersion === 4 && isPrivateIPv4(hostname)) || (ipVersion === 6 && isPrivateIPv6(hostname))) reasons.push("private_or_reserved_ip");
  return {
    normalized_url: parsed.href,
    hostname,
    verdict: reasons.length ? "reject" : ipVersion ? "allow_static" : "requires_dns_resolution",
    reasons,
    dns_rebinding_warning: ipVersion === 0,
  };
}

function runSpendCheck(input) {
  requireObject(input);
  requireObject(input.proposal, "proposal");
  requireObject(input.mandate, "mandate");
  const proposal = input.proposal;
  const mandate = input.mandate;
  const amount = parseAtomic(proposal.amount_atomic, "proposal.amount_atomic");
  const maxPerTx = parseAtomic(mandate.max_per_tx_atomic, "mandate.max_per_tx_atomic");
  const maxPeriod = parseAtomic(mandate.max_period_atomic, "mandate.max_period_atomic");
  const spentPeriod = parseAtomic(mandate.spent_period_atomic ?? "0", "mandate.spent_period_atomic");
  const now = input.now ? Date.parse(input.now) : Date.now();
  assert(Number.isFinite(now), 400, "invalid_time", "now must be an ISO date-time");
  const expires = Date.parse(mandate.expires_at);
  assert(Number.isFinite(expires), 400, "invalid_expiry", "mandate.expires_at must be an ISO date-time");
  const reasons = [];
  if (now >= expires) reasons.push("mandate_expired");
  if (amount > maxPerTx) reasons.push("per_transaction_cap_exceeded");
  if (spentPeriod + amount > maxPeriod) reasons.push("period_cap_exceeded");
  if (!Array.isArray(mandate.allowed_assets) || !mandate.allowed_assets.includes(proposal.asset)) reasons.push("asset_not_allowed");
  if (Array.isArray(mandate.allowed_counterparties) && !mandate.allowed_counterparties.map((value) => value.toLowerCase()).includes(String(proposal.counterparty).toLowerCase())) reasons.push("counterparty_not_allowed");
  const remaining = maxPeriod > spentPeriod ? maxPeriod - spentPeriod : 0n;
  return {
    allowed: reasons.length === 0,
    reason_codes: reasons,
    amount_atomic: amount.toString(),
    remaining_before_atomic: remaining.toString(),
    remaining_after_atomic: reasons.length === 0 ? (remaining - amount).toString() : remaining.toString(),
  };
}

function runNormalize(input) {
  requireObject(input);
  const text = requireText(input.text, "text");
  const form = input.form ?? "NFC";
  assert(["NFC", "NFKC"].includes(form), 400, "invalid_normalization_form", "form must be NFC or NFKC");
  let normalized = text.normalize(form);
  const removed = [];
  let removedCount = 0;
  if (input.strip_controls) {
    normalized = normalized.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/gu, (character, offset) => {
      removedCount += 1;
      if (removed.length < MAX_EVIDENCE_ITEMS) removed.push({ offset, codepoint: `U+${character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`, reason: "control" });
      return "";
    });
  }
  if (input.strip_bidi) {
    normalized = normalized.replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/gu, (character, offset) => {
      removedCount += 1;
      if (removed.length < MAX_EVIDENCE_ITEMS) removed.push({ offset, codepoint: `U+${character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`, reason: "bidi" });
      return "";
    });
  }
  return {
    form,
    normalized,
    changed: normalized !== text,
    before_sha256: sha256(text),
    after_sha256: sha256(normalized),
    removed,
    removed_count: removedCount,
    removed_truncated: removedCount > removed.length,
  };
}

const implementations = {
  "json.canonicalize": runCanonicalize,
  "json.validate": runValidate,
  "security.prompt_scan": runPromptScan,
  "security.url_check": runUrlCheck,
  "policy.spend_check": runSpendCheck,
  "text.normalize": runNormalize,
};

export function executeTool(name, input) {
  const implementation = implementations[name];
  if (!implementation) throw new ServiceError(404, "unknown_tool", `Unknown GoldKey tool: ${name}`);
  const result = implementation(input);
  const inputHash = toolInputHash(name, input);
  return { tool: name, tool_version: VERSION, input_sha256: inputHash, result };
}

export function toolInputHash(name, input) {
  if (!Object.hasOwn(implementations, name)) throw new ServiceError(404, "unknown_tool", `Unknown GoldKey tool: ${name}`);
  return hashCanonical({ tool: name, version: VERSION, input }).sha256;
}

export function catalog() {
  return Object.values(TOOL_REGISTRY).map(({ name, version, description, input_schema }) => ({
    name,
    version,
    description,
    input_schema,
    quota_units: 1,
    paygo_price_usdc: "0.01",
  }));
}
