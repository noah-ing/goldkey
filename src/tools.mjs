import net from "node:net";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { canonicalize, hashCanonical, sha256 } from "./canonical.mjs";
import { ServiceError, assert } from "./errors.mjs";

const MAX_TEXT_LENGTH = 64 * 1024;
const MAX_SCHEMA_BYTES = 32 * 1024;
const MAX_SCHEMA_NODES = 256;
const MAX_SCHEMA_DEPTH = 20;
const MAX_EVIDENCE_ITEMS = 100;
const MAX_VALIDATION_ERROR_PARAMS_BYTES = 1024;
const MAX_VALIDATION_EVIDENCE_BYTES = 32 * 1024;
const MAX_VALIDATOR_CACHE = 64;
const MAX_ACTION_NAME_LENGTH = 128;
const MAX_ACTION_DESCRIPTION_LENGTH = 4096;
const MAX_ACTION_UNTRUSTED_TEXT_LENGTH = 16 * 1024;
const MAX_ACTION_PAYLOAD_BYTES = 32 * 1024;
const MAX_ACTION_PAYLOAD_NODES = 2000;
const MAX_ACTION_PAYLOAD_DEPTH = 16;
const MAX_ACTION_GATE_REQUEST_BYTES = 256 * 1024;
const VERSION = "1.0.0";
const validatorCache = new Map();

const atomicStringSchema = { type: "string", pattern: "^(0|[1-9]\\d*)$", minLength: 1, maxLength: 78 };
const shortStringSchema = { type: "string", minLength: 1, maxLength: 256 };

const ACTION_GATE_INPUT_SCHEMA = {
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
  {
    name: "action.gate",
    description: "Deterministically evaluate a bounded proposed agent action across prompt, Unicode, URL, payload-schema, and spend-mandate checks, returning ALLOW, REVIEW, or BLOCK with a reproducible receipt hash.",
    input_schema: ACTION_GATE_INPUT_SCHEMA,
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

function compiledValidator(schema, { cache = true } = {}) {
  const canonicalSchema = canonicalize(schema);
  const cacheKey = sha256(canonicalSchema);
  const cached = cache ? validatorCache.get(cacheKey) : undefined;
  if (cache && cached) {
    validatorCache.delete(cacheKey);
    validatorCache.set(cacheKey, cached);
    return cached;
  }
  // Stop at the first validation failure. Materializing every failure lets a
  // small allOf/array input amplify into hundreds of thousands of Ajv errors.
  // Compile canonicalized schema bytes so the first failure is stable across
  // equivalent object-key insertion orders.
  const ajv = new Ajv2020({ allErrors: false, strict: true, coerceTypes: false, useDefaults: false, removeAdditional: false });
  addFormats(ajv);
  const validate = ajv.compile(JSON.parse(canonicalSchema));
  if (cache) {
    validatorCache.set(cacheKey, validate);
    if (validatorCache.size > MAX_VALIDATOR_CACHE) validatorCache.delete(validatorCache.keys().next().value);
  }
  return validate;
}

function boundedValidationErrors(rawErrors) {
  const normalized = rawErrors
    .map(({ instancePath, schemaPath, keyword, message, params }) => {
      const rawParams = params ?? {};
      const canonicalParams = canonicalize(rawParams);
      const paramsBytes = Buffer.byteLength(canonicalParams);
      return {
        instancePath,
        schemaPath,
        keyword,
        message,
        params: paramsBytes <= MAX_VALIDATION_ERROR_PARAMS_BYTES
          ? rawParams
          : { truncated: true, byte_length: paramsBytes, sha256: sha256(canonicalParams) },
      };
    })
    .map((error) => ({ error, sortKey: canonicalize(error) }))
    .sort((left, right) => left.sortKey < right.sortKey ? -1 : left.sortKey > right.sortKey ? 1 : 0)
    .map(({ error }) => error);
  const errors = [];
  let evidenceBytes = 2;
  for (const error of normalized) {
    if (errors.length >= MAX_EVIDENCE_ITEMS) break;
    const encoded = canonicalize(error);
    const nextBytes = Buffer.byteLength(encoded) + (errors.length === 0 ? 0 : 1);
    if (evidenceBytes + nextBytes > MAX_VALIDATION_EVIDENCE_BYTES) break;
    errors.push(error);
    evidenceBytes += nextBytes;
  }
  return { errors, errorCount: normalized.length, evidenceBytes };
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
  const mappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const high = Number.parseInt(mappedHex[1], 16);
    const low = Number.parseInt(mappedHex[2], 16);
    const mappedIpv4 = `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`;
    return isPrivateIPv4(mappedIpv4);
  }
  const mapped = host.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isPrivateIPv4(mapped[1]) : false;
}

function runCanonicalize(input) {
  requireObject(input);
  assert(Object.hasOwn(input, "value"), 400, "invalid_input", "value is required");
  const canonical = canonicalize(input.value);
  return { format: "goldkey-c14n-v1", canonical, sha256: sha256(canonical) };
}

function validateValueAgainstSchema(value, schema, { cache = false } = {}) {
  try {
    const validate = compiledValidator(schema, { cache });
    // Ajv's first reported error follows object insertion order. Validate a
    // canonical deep clone so canonically identical JSON always yields the
    // same evidence and receipt without mutating the caller's value.
    const canonicalValue = JSON.parse(canonicalize(value));
    const valid = validate(canonicalValue);
    const bounded = boundedValidationErrors(validate.errors ?? []);
    return {
      valid: Boolean(valid),
      errors: bounded.errors,
      error_count: bounded.errorCount,
      errors_truncated: bounded.errors.length < bounded.errorCount,
      evidence_bytes: bounded.evidenceBytes,
      mutated: false,
    };
  } catch (error) {
    throw new ServiceError(400, "invalid_schema", error.message);
  }
}

export function normalizeBoundedJsonSchema(schema, { cache = false } = {}) {
  requireObject(schema, "schema");
  let serialized;
  try {
    serialized = JSON.stringify(schema);
  } catch (error) {
    throw new ServiceError(400, "invalid_schema", `schema must be JSON: ${error.message}`);
  }
  assert(Buffer.byteLength(serialized) <= MAX_SCHEMA_BYTES, 413, "schema_too_large", `schema exceeds ${MAX_SCHEMA_BYTES} bytes`);
  assertSafeSchema(schema);
  try {
    const canonicalSchema = canonicalize(schema);
    assert(Buffer.byteLength(canonicalSchema) <= MAX_SCHEMA_BYTES, 413, "schema_too_large", `schema exceeds ${MAX_SCHEMA_BYTES} bytes`);
    const normalized = JSON.parse(canonicalSchema);
    // Compile during normalization so unsafe or unsupported schemas fail when
    // an operator registers policy, never later in an authorization path.
    compiledValidator(normalized, { cache });
    return Object.freeze(normalized);
  } catch (error) {
    if (error instanceof ServiceError) throw error;
    throw new ServiceError(400, "invalid_schema", error.message);
  }
}

export function validateBoundedJsonSchemaValue(value, schema, { cache = true } = {}) {
  const normalizedSchema = normalizeBoundedJsonSchema(schema, { cache });
  return validateValueAgainstSchema(value, normalizedSchema, { cache });
}

function runValidate(input) {
  requireObject(input);
  const schema = normalizeBoundedJsonSchema(input.schema);
  return validateValueAgainstSchema(input.value, schema);
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

function assertBoundedPayload(value) {
  const { canonical, sha256: payloadSha256 } = hashCanonical(value);
  assert(Buffer.byteLength(canonical) <= MAX_ACTION_PAYLOAD_BYTES, 413, "action_payload_too_large", `payload exceeds ${MAX_ACTION_PAYLOAD_BYTES} canonical JSON bytes`);
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    assert(nodes <= MAX_ACTION_PAYLOAD_NODES, 413, "action_payload_too_complex", `payload exceeds ${MAX_ACTION_PAYLOAD_NODES} nodes`);
    assert(current.depth <= MAX_ACTION_PAYLOAD_DEPTH, 413, "action_payload_too_deep", `payload exceeds ${MAX_ACTION_PAYLOAD_DEPTH} levels`);
    if (current.value && typeof current.value === "object") {
      for (const child of Array.isArray(current.value) ? current.value : Object.values(current.value)) {
        stack.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
  return { bytes: Buffer.byteLength(canonical), nodes, sha256: payloadSha256 };
}

function summarizedNormalization(result) {
  return {
    form: result.form,
    changed: result.changed,
    before_sha256: result.before_sha256,
    after_sha256: result.after_sha256,
    removed: result.removed,
    removed_count: result.removed_count,
    removed_truncated: result.removed_truncated,
  };
}

function runActionGate(input) {
  requireObject(input);
  const request = hashCanonical({ tool: "action.gate", version: VERSION, input });
  assert(Buffer.byteLength(request.canonical) <= MAX_ACTION_GATE_REQUEST_BYTES, 413, "action_gate_request_too_large", `action.gate request exceeds ${MAX_ACTION_GATE_REQUEST_BYTES} canonical JSON bytes`);

  const envelope = validateToolInput("action.gate", input);
  assert(envelope.valid, 400, "invalid_action_gate_input", "action.gate input does not match its strict schema", { errors: envelope.errors, error_count: envelope.error_count });

  const reasonCodes = [];
  const statuses = [];
  const record = (status, ...codes) => {
    statuses.push(status);
    reasonCodes.push(...codes);
  };

  const actionText = `${input.action.name}${input.action.description ? `\n${input.action.description}` : ""}`;
  const actionNormalization = runNormalize({ text: actionText, form: "NFC", strip_controls: true, strip_bidi: true });
  const actionPrompt = runPromptScan({ text: actionText });
  let actionStatus = "pass";
  const actionReasons = [];
  if (actionNormalization.removed_count > 0) {
    actionStatus = "block";
    actionReasons.push("action_hidden_unicode");
  }
  if (actionPrompt.classification === "high_signal") {
    actionStatus = "block";
    actionReasons.push("action_prompt_high_signal");
  } else if (actionPrompt.classification === "review" && actionStatus !== "block") {
    actionStatus = "review";
    actionReasons.push("action_prompt_review_signal");
  }
  const missingEvidenceReason = (
    input.action.effect === "payment" && !Object.hasOwn(input, "spend") ? "payment_spend_not_provided" :
    input.action.effect === "network" && !Object.hasOwn(input, "url") ? "network_url_not_provided" :
    input.action.effect === "write" && !Object.hasOwn(input, "payload") ? "write_payload_not_provided" :
    input.action.effect === "execute" && !Object.hasOwn(input, "payload") ? "execute_payload_not_provided" :
    undefined
  );
  if (missingEvidenceReason) {
    if (actionStatus !== "block") actionStatus = "review";
    actionReasons.push(missingEvidenceReason);
  }
  record(actionStatus, ...actionReasons);

  let promptCheck = { status: "not_provided" };
  if (Object.hasOwn(input, "untrusted_text")) {
    const normalization = runNormalize({ text: input.untrusted_text, form: "NFC", strip_controls: true, strip_bidi: true });
    const scan = runPromptScan({ text: input.untrusted_text });
    let status = "pass";
    const reasons = [];
    if (normalization.removed_count > 0) {
      status = "block";
      reasons.push("untrusted_text_hidden_unicode");
    }
    if (scan.classification === "high_signal") {
      status = "block";
      reasons.push("prompt_high_signal");
    } else if (scan.classification === "review" && status !== "block") {
      status = "review";
      reasons.push("prompt_review_signal");
    }
    record(status, ...reasons);
    promptCheck = { status, reason_codes: reasons, normalization: summarizedNormalization(normalization), scan };
  }

  let urlCheck = { status: "not_provided" };
  if (Object.hasOwn(input, "url")) {
    const result = runUrlCheck({ url: input.url });
    const status = result.verdict === "reject" ? "block" : result.verdict === "requires_dns_resolution" ? "review" : "pass";
    const reasons = result.verdict === "reject"
      ? result.reasons.map((reason) => `url_${reason}`)
      : result.verdict === "requires_dns_resolution" ? ["url_requires_dns_resolution"] : [];
    record(status, ...reasons);
    urlCheck = { status, reason_codes: reasons, ...result };
  }

  let payloadCheck = { status: "not_provided" };
  if (Object.hasOwn(input, "payload")) {
    const bounds = assertBoundedPayload(input.payload);
    const validation = runValidate({ value: input.payload, schema: input.schema });
    const status = validation.valid ? "pass" : "block";
    const reasons = validation.valid ? [] : ["payload_schema_invalid"];
    record(status, ...reasons);
    payloadCheck = { status, reason_codes: reasons, bounds, validation };
  }

  let spendCheck = { status: "not_provided" };
  if (Object.hasOwn(input, "spend")) {
    const result = runSpendCheck(input.spend);
    const status = result.allowed ? "pass" : "block";
    const reasons = result.reason_codes.map((reason) => `spend_${reason}`);
    record(status, ...reasons);
    spendCheck = { ...result, status, policy_reason_codes: result.reason_codes, reason_codes: reasons };
  }

  const checks = {
    action: {
      status: actionStatus,
      reason_codes: actionReasons,
      normalization: summarizedNormalization(actionNormalization),
      prompt_scan: actionPrompt,
    },
    prompt: promptCheck,
    url: urlCheck,
    payload: payloadCheck,
    spend: spendCheck,
  };
  const decision = statuses.includes("block") ? "BLOCK" : statuses.includes("review") ? "REVIEW" : "ALLOW";
  const stableReasonCodes = [...new Set(reasonCodes)].sort();
  const receiptPayload = {
    receipt_format: "goldkey-action-gate-v1",
    request_sha256: request.sha256,
    decision,
    reason_codes: stableReasonCodes,
    checks,
  };
  return {
    decision,
    reason_codes: stableReasonCodes,
    checks,
    request_sha256: request.sha256,
    receipt_sha256: hashCanonical(receiptPayload).sha256,
    receipt_format: receiptPayload.receipt_format,
    receipt_canonicalization: "goldkey-c14n-v1",
    receipt_hash_algorithm: "SHA-256",
    receipt_preimage_fields: ["receipt_format", "request_sha256", "decision", "reason_codes", "checks"],
    limitation: "Deterministic static checks only; ALLOW does not guarantee safety, authorization, successful execution, or future endpoint behavior.",
  };
}

const implementations = {
  "json.canonicalize": runCanonicalize,
  "json.validate": runValidate,
  "security.prompt_scan": runPromptScan,
  "security.url_check": runUrlCheck,
  "policy.spend_check": runSpendCheck,
  "text.normalize": runNormalize,
  "action.gate": runActionGate,
};

export function executeTool(name, input) {
  const implementation = implementations[name];
  if (!implementation) throw new ServiceError(404, "unknown_tool", `Unknown GoldKey tool: ${name}`);
  const result = implementation(input);
  const inputHash = toolInputHash(name, input);
  return { tool: name, tool_version: VERSION, input_sha256: inputHash, result };
}

export function validateToolInput(name, input) {
  const definition = TOOL_REGISTRY[name];
  if (!definition) throw new ServiceError(404, "unknown_tool", `Unknown GoldKey tool: ${name}`);
  return validateValueAgainstSchema(input, definition.input_schema, { cache: true });
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
