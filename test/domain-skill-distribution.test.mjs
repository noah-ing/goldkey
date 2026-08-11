import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

import { buildDomainSkill } from "../scripts/build-domain-skill.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceDirectory = resolve(root, "distribution/goldkey-agent-utilities");
const outputDirectory = resolve(root, "edge/public/.well-known/agent-skills");
const expectedFiles = [
  "SKILL.md",
  "agents/openai.yaml",
  "scripts/goldkey-client.mjs",
];

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function readTarString(bytes, offset, length) {
  const field = bytes.subarray(offset, offset + length);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.length : end).toString("utf8");
}

function readTar(archive) {
  const bytes = gunzipSync(archive);
  const entries = new Map();
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const path = readTarString(header, 0, 100);
    const size = Number.parseInt(readTarString(header, 124, 12).trim() || "0", 8);
    assert.equal(readTarString(header, 257, 6), "ustar");
    assert.equal(header[156], 0x30);
    offset += 512;
    entries.set(path, bytes.subarray(offset, offset + size));
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}

test("domain skill index pins a deterministic archive with only audited files", async () => {
  const first = await buildDomainSkill();
  assert.equal(first.archiveChanged, false, "generated skill archive is stale; run scripts/build-domain-skill.mjs and commit it");
  assert.equal(first.indexChanged, false, "generated skill index is stale; run scripts/build-domain-skill.mjs and commit it");
  const firstArchive = await readFile(resolve(outputDirectory, "goldkey-agent-utilities.tar.gz"));
  const firstIndex = await readFile(resolve(outputDirectory, "index.json"), "utf8");
  const second = await buildDomainSkill();
  const secondArchive = await readFile(resolve(outputDirectory, "goldkey-agent-utilities.tar.gz"));

  assert.equal(second.archiveChanged, false);
  assert.equal(second.indexChanged, false);
  assert.deepEqual(secondArchive, firstArchive);
  assert.equal(first.digest, `sha256:${sha256(firstArchive)}`);

  const index = JSON.parse(firstIndex);
  assert.deepEqual(index, {
    $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
    skills: [{
      name: "goldkey-agent-utilities",
      type: "archive",
      description: "Run GoldKey Action Gate before proposed agent actions to obtain ALLOW, REVIEW, or BLOCK with a deterministic, reproducible receipt hash, or use its component JSON, prompt, URL, spend, and Unicode checks. When live discovery explicitly advertises it, integrate the feature-gated GoldKey Guard beta as a paid hosted authorizer plus operator-controlled local enforcer for real MCP, HTTPS, or supported EVM calls. Use for exact 0.01-USDC pre-action decisions, zero-spend x402 probes, pass-versus-paygo evaluation, Guard enforcement, or GoldKey pass, renewal, authentication, quota, and scoped child-key operations.",
      url: "./goldkey-agent-utilities.tar.gz",
      digest: `sha256:${sha256(firstArchive)}`,
    }],
  });

  const entries = readTar(firstArchive);
  assert.deepEqual([...entries.keys()], expectedFiles);
  for (const path of expectedFiles) {
    assert.deepEqual(entries.get(path), await readFile(resolve(sourceDirectory, path)));
  }

  const publicBytes = Buffer.concat([Buffer.from(firstIndex), firstArchive]);
  assert.doesNotMatch(publicBytes.toString("latin1"), /github\.com\/noah-ing\/goldkey|\/Users\/noah-ing/);
});
