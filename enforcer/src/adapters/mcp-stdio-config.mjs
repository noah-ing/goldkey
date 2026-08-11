import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { parseDocument as parseYamlDocument } from "yaml";
import {
  assertSafeIdentifier,
  deepFreeze,
  isCanonicalSha256,
} from "../canonical.mjs";
import { InvalidInputError, LocalStateError } from "../errors.mjs";

export const MCP_STDIO_CONFIG_SCHEMA = "goldkey.mcp-stdio-launcher.v1";
export const MCP_IDEMPOTENCY_META_KEY = "com.goldkey/idempotency-key";

const EFFECTS = new Set(["read", "write", "network", "payment", "execute"]);
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_ENV_VALUE_BYTES = 128 * 1024;
const DEFAULT_STARTUP_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024;
const NORMALIZED_CONFIGS = new WeakSet();
const NORMALIZED_INSPECTION_CONFIGS = new WeakSet();

function plainObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidInputError(`${name} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new InvalidInputError(`${name} must be a plain object`);
  }
  return value;
}

function exactKeys(value, allowed, required, name) {
  plainObject(value, name);
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  const missing = [...required].filter((key) => !Object.hasOwn(value, key));
  if (extras.length > 0 || missing.length > 0) {
    throw new InvalidInputError(`${name} must have the exact operator-controlled shape`, {
      extras: extras.sort(),
      missing: missing.sort(),
    });
  }
  return value;
}

function boundedString(value, name, maximum) {
  if (
    typeof value !== "string"
    || value.length < 1
    || Buffer.byteLength(value, "utf8") > maximum
    || /[\0\r\n]/.test(value)
  ) {
    throw new InvalidInputError(`${name} must be one bounded single-line string`);
  }
  return value;
}

function absolutePath(value, name) {
  boundedString(value, name, 4096);
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new InvalidInputError(`${name} must be one normalized absolute path`);
  }
  return value;
}

function boundedInteger(value, name, minimum, maximum, fallback) {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw new InvalidInputError(`${name} must be ${minimum}-${maximum}`);
  }
  return normalized;
}

function normalizeArguments(value) {
  if (!Array.isArray(value) || value.length > 256) {
    throw new InvalidInputError("mcp_stdio.upstream.args must contain at most 256 fixed arguments");
  }
  let totalBytes = 0;
  const args = value.map((argument, index) => {
    if (typeof argument !== "string" || /\0/.test(argument) || Buffer.byteLength(argument, "utf8") > 8192) {
      throw new InvalidInputError(`mcp_stdio.upstream.args[${index}] must be a bounded string without NUL bytes`);
    }
    totalBytes += Buffer.byteLength(argument, "utf8");
    return argument;
  });
  if (totalBytes > 64 * 1024) throw new InvalidInputError("mcp_stdio.upstream.args exceeds 64 KiB");
  return Object.freeze(args);
}

function normalizeEnvironment(value, sourceEnvironment) {
  plainObject(value, "mcp_stdio.upstream.env");
  if (Object.keys(value).length > 128) throw new InvalidInputError("mcp_stdio.upstream.env may contain at most 128 variables");
  const normalized = Object.create(null);
  const caseFolded = new Set();
  for (const [name, source] of Object.entries(value)) {
    if (!ENV_NAME.test(name)) throw new InvalidInputError(`mcp_stdio.upstream.env contains invalid variable name ${name}`);
    const folded = process.platform === "win32" ? name.toUpperCase() : name;
    if (caseFolded.has(folded)) throw new InvalidInputError(`mcp_stdio.upstream.env contains duplicate variable ${name}`);
    caseFolded.add(folded);
    exactKeys(source, new Set(["value", "from_env"]), new Set(), `mcp_stdio.upstream.env.${name}`);
    const keys = Object.keys(source);
    if (keys.length !== 1) {
      throw new InvalidInputError(`mcp_stdio.upstream.env.${name} must contain exactly one of value or from_env`);
    }
    let resolved;
    if (keys[0] === "from_env") {
      if (typeof source.from_env !== "string" || !ENV_NAME.test(source.from_env)) {
        throw new InvalidInputError(`mcp_stdio.upstream.env.${name}.from_env must name one launcher environment variable`);
      }
      resolved = sourceEnvironment[source.from_env];
      if (typeof resolved !== "string") {
        throw new InvalidInputError(`Required launcher environment variable ${source.from_env} is not set`);
      }
    } else {
      resolved = source.value;
    }
    if (typeof resolved !== "string" || /\0/.test(resolved) || Buffer.byteLength(resolved, "utf8") > MAX_ENV_VALUE_BYTES) {
      throw new InvalidInputError(`mcp_stdio.upstream.env.${name} resolves to an invalid or oversized value`);
    }
    normalized[name] = resolved;
  }
  return Object.freeze(normalized);
}

function normalizeTools(value, { allowEmpty = false } = {}) {
  if (!Array.isArray(value) || value.length < (allowEmpty ? 0 : 1) || value.length > 100) {
    throw new InvalidInputError(`mcp_stdio.connector.tools must contain ${allowEmpty ? "0-100" : "1-100"} explicitly guarded tools`);
  }
  const names = new Set();
  const tools = value.map((tool, index) => {
    exactKeys(
      tool,
      new Set(["name", "effect", "input_schema_sha256"]),
      new Set(["name", "effect", "input_schema_sha256"]),
      `mcp_stdio.connector.tools[${index}]`,
    );
    if (typeof tool.name !== "string" || !TOOL_NAME.test(tool.name)) {
      throw new InvalidInputError(`mcp_stdio.connector.tools[${index}].name is not a safe MCP tool name`);
    }
    if (names.has(tool.name)) throw new InvalidInputError(`Duplicate configured MCP tool ${tool.name}`);
    names.add(tool.name);
    if (!EFFECTS.has(tool.effect)) {
      throw new InvalidInputError(`mcp_stdio.connector.tools[${index}].effect is unsupported`);
    }
    if (!isCanonicalSha256(tool.input_schema_sha256)) {
      throw new InvalidInputError(`mcp_stdio.connector.tools[${index}].input_schema_sha256 must be lowercase SHA-256`);
    }
    return Object.freeze({
      name: tool.name,
      effect: tool.effect,
      input_schema_sha256: tool.input_schema_sha256,
    });
  });
  return Object.freeze(tools);
}

function normalizeUpstream(raw, env) {
  exactKeys(
    raw,
    new Set(["command", "args", "cwd", "env", "startup_timeout_ms", "max_message_bytes"]),
    new Set(["command", "args", "cwd", "env"]),
    "mcp_stdio.upstream",
  );
  return {
    command: absolutePath(raw.command, "mcp_stdio.upstream.command"),
    args: normalizeArguments(raw.args),
    cwd: absolutePath(raw.cwd, "mcp_stdio.upstream.cwd"),
    env: normalizeEnvironment(raw.env, env),
    startup_timeout_ms: boundedInteger(
      raw.startup_timeout_ms,
      "mcp_stdio.upstream.startup_timeout_ms",
      100,
      30_000,
      DEFAULT_STARTUP_TIMEOUT_MS,
    ),
    max_message_bytes: boundedInteger(
      raw.max_message_bytes,
      "mcp_stdio.upstream.max_message_bytes",
      64 * 1024,
      10 * 1024 * 1024,
      DEFAULT_MAX_MESSAGE_BYTES,
    ),
  };
}

/**
 * Validates and resolves the operator-owned MCP section. Environment references
 * are resolved once during startup and the resulting object is deeply frozen.
 */
export function normalizeMcpStdioConfig(raw, { env = process.env } = {}) {
  exactKeys(
    raw,
    new Set(["schema", "connector", "upstream"]),
    new Set(["schema", "connector", "upstream"]),
    "mcp_stdio",
  );
  if (raw.schema !== MCP_STDIO_CONFIG_SCHEMA) {
    throw new InvalidInputError(`mcp_stdio.schema must be ${MCP_STDIO_CONFIG_SCHEMA}`);
  }
  exactKeys(
    raw.connector,
    new Set(["id", "server_id", "tools"]),
    new Set(["id", "server_id", "tools"]),
    "mcp_stdio.connector",
  );
  const connectorId = assertSafeIdentifier(raw.connector.id, "mcp_stdio.connector.id");
  const serverId = assertSafeIdentifier(raw.connector.server_id, "mcp_stdio.connector.server_id");
  const normalized = {
    schema: MCP_STDIO_CONFIG_SCHEMA,
    connector: {
      id: connectorId,
      server_id: serverId,
      tools: normalizeTools(raw.connector.tools),
    },
    upstream: normalizeUpstream(raw.upstream, env),
  };
  const frozen = deepFreeze(normalized);
  NORMALIZED_CONFIGS.add(frozen);
  return frozen;
}

export function assertNormalizedMcpStdioConfig(value) {
  if (!NORMALIZED_CONFIGS.has(value)) {
    throw new InvalidInputError("MCP stdio config must be produced by normalizeMcpStdioConfig");
  }
  return value;
}

/**
 * Inspection accepts an empty tool list so an operator can discover hashes
 * before enabling the launcher. It never relaxes normal launch validation.
 */
export function normalizeMcpStdioInspectionConfig(raw, { env = process.env } = {}) {
  exactKeys(
    raw,
    new Set(["schema", "connector", "upstream"]),
    new Set(["schema", "connector", "upstream"]),
    "mcp_stdio",
  );
  if (raw.schema !== MCP_STDIO_CONFIG_SCHEMA) {
    throw new InvalidInputError(`mcp_stdio.schema must be ${MCP_STDIO_CONFIG_SCHEMA}`);
  }
  exactKeys(
    raw.connector,
    new Set(["id", "server_id", "tools"]),
    new Set(["id", "server_id", "tools"]),
    "mcp_stdio.connector",
  );
  const normalized = deepFreeze({
    schema: MCP_STDIO_CONFIG_SCHEMA,
    connector: {
      id: assertSafeIdentifier(raw.connector.id, "mcp_stdio.connector.id"),
      server_id: assertSafeIdentifier(raw.connector.server_id, "mcp_stdio.connector.server_id"),
      tools: normalizeTools(raw.connector.tools, { allowEmpty: true }),
    },
    upstream: normalizeUpstream(raw.upstream, env),
  });
  NORMALIZED_INSPECTION_CONFIGS.add(normalized);
  return normalized;
}

export function assertNormalizedMcpStdioInspectionConfig(value) {
  if (!NORMALIZED_INSPECTION_CONFIGS.has(value) && !NORMALIZED_CONFIGS.has(value)) {
    throw new InvalidInputError("MCP inspection config must be produced by an MCP stdio config normalizer");
  }
  return value;
}

async function readOperatorConfig(filename) {
  const resolved = path.resolve(filename);
  let pathMetadata;
  let handle;
  try {
    pathMetadata = await lstat(resolved);
    handle = await open(resolved, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch (cause) {
    await handle?.close().catch(() => {});
    throw new LocalStateError(`Unable to inspect MCP launcher config ${resolved}`, { cause });
  }
  try {
    const metadata = await handle.stat();
    if (
      !pathMetadata.isFile()
      || pathMetadata.isSymbolicLink()
      || !metadata.isFile()
      || pathMetadata.dev !== metadata.dev
      || pathMetadata.ino !== metadata.ino
    ) {
      throw new LocalStateError(`MCP launcher config ${resolved} must be one stable regular file, not a symlink`);
    }
    if (metadata.size < 1 || metadata.size > MAX_CONFIG_BYTES) {
      throw new LocalStateError(`MCP launcher config ${resolved} must be 1-${MAX_CONFIG_BYTES} bytes`);
    }
    if (process.platform !== "win32") {
      if ((metadata.mode & 0o022) !== 0) {
        throw new LocalStateError(`MCP launcher config ${resolved} must not be writable by group or other users`);
      }
      const effectiveUid = process.geteuid?.();
      if (effectiveUid !== undefined && metadata.uid !== 0 && metadata.uid !== effectiveUid) {
        throw new LocalStateError(`MCP launcher config ${resolved} must be owned by root or the launcher user`);
      }
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (
      bytes.byteLength !== metadata.size
      || after.size !== metadata.size
      || after.mtimeMs !== metadata.mtimeMs
      || after.ctimeMs !== metadata.ctimeMs
    ) {
      throw new LocalStateError(`MCP launcher config ${resolved} changed while it was being read`);
    }
    return { resolved, text: bytes.toString("utf8") };
  } catch (cause) {
    if (cause instanceof LocalStateError) throw cause;
    throw new LocalStateError(`Unable to read MCP launcher config ${resolved}`, { cause });
  } finally {
    await handle.close().catch(() => {});
  }
}

function parseDocument(filename, text) {
  const extension = path.extname(filename).toLowerCase();
  try {
    if (extension === ".json") {
      JSON.parse(text);
      const parsed = parseYamlDocument(text, {
        maxAliasCount: 0,
        merge: false,
        schema: "json",
        uniqueKeys: true,
      });
      if (parsed.errors.length > 0 || parsed.warnings.length > 0) {
        throw parsed.errors[0] ?? parsed.warnings[0];
      }
      return parsed.toJS({ maxAliasCount: 0 });
    }
    if (extension === ".yaml" || extension === ".yml") {
      const parsed = parseYamlDocument(text, {
        maxAliasCount: 0,
        merge: false,
        schema: "core",
        uniqueKeys: true,
      });
      if (parsed.errors.length > 0 || parsed.warnings.length > 0) {
        throw parsed.errors[0] ?? parsed.warnings[0];
      }
      return parsed.toJS({ maxAliasCount: 0 });
    }
  } catch (cause) {
    throw new InvalidInputError(`MCP launcher config ${filename} is not valid ${extension.slice(1).toUpperCase()}: ${cause.message}`);
  }
  throw new InvalidInputError("MCP launcher config filename must end in .json, .yaml, or .yml");
}

/**
 * Loads one YAML/JSON document. A shared launcher may place this section at
 * `mcp_stdio`; a standalone document may consist solely of the MCP section.
 */
export async function loadMcpStdioConfigFile(filename, { env = process.env } = {}) {
  if (typeof filename !== "string" || filename.length < 1) {
    throw new InvalidInputError("An MCP launcher config filename is required");
  }
  const { resolved, text } = await readOperatorConfig(filename);
  const document = parseDocument(resolved, text);
  plainObject(document, "MCP launcher config document");
  const section = Object.hasOwn(document, "mcp_stdio") ? document.mcp_stdio : document;
  const mcpStdioConfig = normalizeMcpStdioConfig(section, { env });
  return Object.freeze({
    filename: resolved,
    document: deepFreeze(document),
    mcpStdioConfig,
  });
}

export async function loadMcpStdioInspectionConfigFile(filename, { env = process.env } = {}) {
  if (typeof filename !== "string" || filename.length < 1) {
    throw new InvalidInputError("An MCP launcher config filename is required");
  }
  const { resolved, text } = await readOperatorConfig(filename);
  const document = parseDocument(resolved, text);
  plainObject(document, "MCP launcher config document");
  const section = Object.hasOwn(document, "mcp_stdio") ? document.mcp_stdio : document;
  const mcpStdioConfig = normalizeMcpStdioInspectionConfig(section, { env });
  return Object.freeze({
    filename: resolved,
    document: deepFreeze(document),
    mcpStdioConfig,
  });
}
