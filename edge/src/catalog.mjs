const VERSION = "1.0.0";
const MAX_TEXT_LENGTH = 64 * 1024;

const definitions = [
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

export const TOOL_NAMES = Object.freeze(definitions.map(({ name }) => name));

export function catalog() {
  return definitions.map(({ name, description, input_schema }) => ({
    name,
    version: VERSION,
    description,
    input_schema,
    quota_units: 1,
    paygo_price_usdc: "0.01",
  }));
}
