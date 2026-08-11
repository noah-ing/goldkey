import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  loadMcpStdioConfigFile,
  loadMcpStdioInspectionConfigFile,
  normalizeMcpStdioConfig,
  normalizeMcpStdioInspectionConfig,
} from "../src/adapters/mcp-stdio-config.mjs";
import { InvalidInputError, LocalStateError } from "../src/errors.mjs";

const HASH = "a".repeat(64);

function rawConfig({ tools, env = {} } = {}) {
  return {
    schema: "goldkey.mcp-stdio-launcher.v1",
    connector: {
      id: "fixture-connector",
      server_id: "fixture-server",
      tools: tools ?? [{ name: "echo", effect: "read", input_schema_sha256: HASH }],
    },
    upstream: {
      command: process.execPath,
      args: [path.resolve("examples/mcp/fixture-upstream.mjs")],
      cwd: process.cwd(),
      env,
      startup_timeout_ms: 5000,
      max_message_bytes: 1024 * 1024,
    },
  };
}

test("normalizer resolves only explicitly allowlisted environment values and freezes the result", () => {
  const config = normalizeMcpStdioConfig(rawConfig({
    env: {
      API_TOKEN: { from_env: "OPERATOR_SECRET" },
      NODE_ENV: { value: "production" },
    },
  }), {
    env: {
      OPERATOR_SECRET: "secret-value",
      AGENT_CONTROLLED_SECRET: "must-not-pass",
      PATH: "/agent/path",
    },
  });
  assert.deepEqual({ ...config.upstream.env }, { API_TOKEN: "secret-value", NODE_ENV: "production" });
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.connector.tools), true);
  assert.throws(() => { config.upstream.env.EXTRA = "no"; }, TypeError);
});

test("normal launch rejects empty tools while inspection accepts the bootstrap shape", () => {
  assert.throws(
    () => normalizeMcpStdioConfig(rawConfig({ tools: [] })),
    (error) => error instanceof InvalidInputError && /1-100/.test(error.message),
  );
  const inspection = normalizeMcpStdioInspectionConfig(rawConfig({ tools: [] }));
  assert.deepEqual(inspection.connector.tools, []);
});

test("normalizer rejects mutable launch surfaces, extras, and missing env references", () => {
  const relative = rawConfig();
  relative.upstream.command = "node";
  assert.throws(() => normalizeMcpStdioConfig(relative), /normalized absolute path/);

  const extra = rawConfig();
  extra.upstream.shell = true;
  assert.throws(() => normalizeMcpStdioConfig(extra), /exact operator-controlled shape/);

  const missing = rawConfig({ env: { TOKEN: { from_env: "MISSING_SECRET" } } });
  assert.throws(() => normalizeMcpStdioConfig(missing, { env: {} }), /is not set/);

  const injection = rawConfig();
  injection.upstream.args = ["ok\0--evil"];
  assert.throws(() => normalizeMcpStdioConfig(injection), /without NUL/);
});

test("JSON and YAML loaders accept one operator-owned document and reject duplicate YAML keys", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-mcp-config-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const jsonFile = path.join(directory, "config.json");
  await writeFile(jsonFile, JSON.stringify({ mcp_stdio: rawConfig() }), { mode: 0o600 });
  const loadedJson = await loadMcpStdioConfigFile(jsonFile);
  assert.equal(loadedJson.mcpStdioConfig.connector.id, "fixture-connector");

  const yamlFile = path.join(directory, "inspect.yaml");
  const yaml = [
    "schema: goldkey.mcp-stdio-launcher.v1",
    "connector:",
    "  id: fixture-connector",
    "  server_id: fixture-server",
    "  tools: []",
    "upstream:",
    `  command: ${JSON.stringify(process.execPath)}`,
    "  args: []",
    `  cwd: ${JSON.stringify(process.cwd())}`,
    "  env: {}",
    "  startup_timeout_ms: 5000",
    "  max_message_bytes: 1048576",
    "",
  ].join("\n");
  await writeFile(yamlFile, yaml, { mode: 0o600 });
  const loadedYaml = await loadMcpStdioInspectionConfigFile(yamlFile);
  assert.deepEqual(loadedYaml.mcpStdioConfig.connector.tools, []);

  const duplicateFile = path.join(directory, "duplicate.yaml");
  await writeFile(duplicateFile, `${yaml}schema: goldkey.mcp-stdio-launcher.v1\n`, { mode: 0o600 });
  await assert.rejects(() => loadMcpStdioInspectionConfigFile(duplicateFile), /Map keys must be unique|unique/);

  const aliasFile = path.join(directory, "alias.yaml");
  await writeFile(aliasFile, `${yaml}\ncopy: &config {}\ncopy_again: *config\n`, { mode: 0o600 });
  await assert.rejects(() => loadMcpStdioInspectionConfigFile(aliasFile), /Alias resolution is disabled/);

  const duplicateJson = path.join(directory, "duplicate.json");
  await writeFile(duplicateJson, '{"schema":"goldkey.mcp-stdio-launcher.v1","schema":"goldkey.mcp-stdio-launcher.v1"}', { mode: 0o600 });
  await assert.rejects(() => loadMcpStdioInspectionConfigFile(duplicateJson), /Map keys must be unique|unique/);
});

test("loader rejects symlink and group/other-writable config files", { skip: process.platform === "win32" }, async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "goldkey-mcp-config-mode-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, "target.json");
  const link = path.join(directory, "link.json");
  await writeFile(target, JSON.stringify(rawConfig()), { mode: 0o600 });
  await symlink(target, link);
  await assert.rejects(() => loadMcpStdioConfigFile(link), LocalStateError);
  await chmod(target, 0o622);
  await assert.rejects(() => loadMcpStdioConfigFile(target), /must not be writable by group or other/);
});
