import { createHash } from "node:crypto";
import { ServiceError } from "./errors.mjs";

const MAX_DEPTH = 32;
const MAX_NODES = 20_000;

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalize(value) {
  let nodes = 0;

  function encode(node, depth) {
    nodes += 1;
    if (nodes > MAX_NODES) {
      throw new ServiceError(413, "input_too_complex", `Input exceeds ${MAX_NODES} nodes`);
    }
    if (depth > MAX_DEPTH) {
      throw new ServiceError(413, "input_too_deep", `Input exceeds depth ${MAX_DEPTH}`);
    }

    if (node === null) return "null";
    if (typeof node === "boolean" || typeof node === "string") return JSON.stringify(node);
    if (typeof node === "number") {
      if (!Number.isFinite(node)) {
        throw new ServiceError(400, "non_finite_number", "NaN and Infinity are not valid JSON values");
      }
      return JSON.stringify(Object.is(node, -0) ? 0 : node);
    }
    if (Array.isArray(node)) return `[${node.map((item) => encode(item, depth + 1)).join(",")}]`;
    if (typeof node === "object") {
      const prototype = Object.getPrototypeOf(node);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new ServiceError(400, "non_json_value", "Only plain JSON objects are accepted");
      }
      return `{${Object.keys(node)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${encode(node[key], depth + 1)}`)
        .join(",")}}`;
    }
    throw new ServiceError(400, "non_json_value", `Unsupported JSON value type: ${typeof node}`);
  }

  return encode(value, 0);
}

export function hashCanonical(value) {
  const canonical = canonicalize(value);
  return { canonical, sha256: sha256(canonical) };
}
