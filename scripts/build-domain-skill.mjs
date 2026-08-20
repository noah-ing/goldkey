#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceDirectory = resolve(root, "distribution/goldkey-agent-utilities");
const outputDirectory = resolve(root, "edge/public/.well-known/agent-skills");
const archiveName = "goldkey-agent-utilities.tar.gz";
const archivePath = resolve(outputDirectory, archiveName);
const indexPath = resolve(outputDirectory, "index.json");
const schema = "https://schemas.agentskills.io/discovery/0.2.0/schema.json";
const files = Object.freeze([
  "SKILL.md",
  "agents/openai.yaml",
  "references/guard-beta.md",
  "references/pass-and-keys.md",
  "scripts/goldkey-client.mjs",
]);

function fail(message) {
  throw new Error(message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function writeString(header, value, offset, length) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) fail(`Tar field is too long: ${value}`);
  bytes.copy(header, offset);
}

function writeOctal(header, value, offset, length) {
  const encoded = value.toString(8).padStart(length - 1, "0");
  if (encoded.length >= length) fail(`Tar numeric field is too large: ${value}`);
  writeString(header, `${encoded}\0`, offset, length);
}

function tarHeader(path, size, mode = 0o644) {
  const header = Buffer.alloc(512);
  writeString(header, path, 0, 100);
  writeOctal(header, mode, 100, 8);
  writeOctal(header, 0, 108, 8);
  writeOctal(header, 0, 116, 8);
  writeOctal(header, size, 124, 12);
  writeOctal(header, 0, 136, 12);
  header.fill(0x20, 148, 156);
  writeString(header, "0", 156, 1);
  writeString(header, "ustar\0", 257, 6);
  writeString(header, "00", 263, 2);
  writeOctal(header, 0, 329, 8);
  writeOctal(header, 0, 337, 8);

  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeString(header, `${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8);
  return header;
}

function buildTar(entries) {
  const chunks = [];
  for (const [path, content] of entries) {
    chunks.push(tarHeader(path, content.length), content);
    const remainder = content.length % 512;
    if (remainder !== 0) chunks.push(Buffer.alloc(512 - remainder));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function reverseBits(value, width) {
  let reversed = 0;
  for (let bit = 0; bit < width; bit += 1) {
    reversed = (reversed << 1) | ((value >>> bit) & 1);
  }
  return reversed;
}

function fixedLiteralCode(symbol) {
  if (symbol <= 143) return [0x30 + symbol, 8];
  if (symbol <= 255) return [0x190 + symbol - 144, 9];
  if (symbol <= 279) return [symbol - 256, 7];
  return [0xc0 + symbol - 280, 8];
}

function deterministicDeflate(bytes) {
  const output = [];
  let pending = 0;
  let pendingBits = 0;

  const writeBits = (value, width) => {
    pending |= value << pendingBits;
    pendingBits += width;
    while (pendingBits >= 8) {
      output.push(pending & 0xff);
      pending >>>= 8;
      pendingBits -= 8;
    }
  };

  writeBits(0b011, 3); // final block using the fixed Huffman table
  for (const byte of bytes) {
    const [code, width] = fixedLiteralCode(byte);
    writeBits(reverseBits(code, width), width);
  }
  const [endCode, endWidth] = fixedLiteralCode(256);
  writeBits(reverseBits(endCode, endWidth), endWidth);
  if (pendingBits > 0) output.push(pending & 0xff);
  return Buffer.from(output);
}

function deterministicGzip(bytes) {
  const header = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
  const compressed = deterministicDeflate(bytes);
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(bytes), 0);
  trailer.writeUInt32LE(bytes.length >>> 0, 4);
  return Buffer.concat([header, compressed, trailer]);
}

function frontmatterField(source, field) {
  const opening = source.startsWith("---\n");
  const closing = source.indexOf("\n---\n", 4);
  if (!opening || closing === -1) fail("SKILL.md must contain YAML frontmatter");
  const frontmatter = source.slice(4, closing);
  const match = frontmatter.match(new RegExp(`^${field}:\\s*(.+?)\\s*$`, "m"));
  if (!match) fail(`SKILL.md frontmatter is missing ${field}`);
  return match[1];
}

async function writeIfChanged(path, content) {
  let current;
  try {
    current = await readFile(path);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (current?.equals(content)) return false;
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, { mode: 0o644 });
  return true;
}

export async function buildDomainSkill() {
  const entries = await Promise.all(files.map(async (path) => [
    path,
    await readFile(resolve(sourceDirectory, path)),
  ]));
  const skillSource = entries[0][1].toString("utf8");
  const name = frontmatterField(skillSource, "name");
  const description = frontmatterField(skillSource, "description");
  if (name !== "goldkey-agent-utilities") fail(`Unexpected skill name: ${name}`);
  if (description.length > 1024) fail("Skill description exceeds the discovery schema limit");

  const archive = deterministicGzip(buildTar(entries));
  const digest = `sha256:${sha256(archive)}`;
  const index = Buffer.from(`${JSON.stringify({
    $schema: schema,
    skills: [{
      name,
      type: "archive",
      description,
      url: `./${archiveName}`,
      digest,
    }],
  }, null, 2)}\n`, "utf8");

  const archiveChanged = await writeIfChanged(archivePath, archive);
  const indexChanged = await writeIfChanged(indexPath, index);
  return Object.freeze({ archivePath, indexPath, digest, archiveChanged, indexChanged });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await buildDomainSkill();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
