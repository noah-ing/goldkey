import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const destination = path.join(packageRoot, "dist");
const publicDestination = path.resolve(packageRoot, "../edge/public/.well-known/goldkey-guard");
await mkdir(destination, { recursive: true });
await mkdir(publicDestination, { recursive: true });

const packed = spawnSync("npm", ["pack", "--json", "--pack-destination", destination], {
  cwd: packageRoot,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
});
if (packed.status !== 0) throw new Error(`npm pack failed: ${packed.stderr.trim()}`);

let result;
try {
  [result] = JSON.parse(packed.stdout);
} catch (cause) {
  throw new Error("npm pack returned invalid JSON", { cause });
}
if (!result?.filename || result.name !== "@goldkey/enforcer" || typeof result.version !== "string") {
  throw new Error("npm pack did not report the expected @goldkey/enforcer artifact identity");
}

const artifact = path.join(destination, result.filename);
const bytes = await readFile(artifact);
const manifest = {
  schema: "goldkey-enforcer-package-integrity.v1",
  package: result.name,
  version: result.version,
  filename: result.filename,
  download_url: `https://goldkey-edge-storefront.noah-ing.workers.dev/.well-known/goldkey-guard/${result.filename}`,
  node_engine: ">=22",
  size: bytes.byteLength,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
};
const manifestPath = `${artifact}.integrity.json`;
const publicArtifact = path.join(publicDestination, result.filename);
const publicManifest = `${publicArtifact}.integrity.json`;
const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
await Promise.all([
  writeFile(manifestPath, manifestBytes, { mode: 0o644 }),
  writeFile(publicArtifact, bytes, { mode: 0o644 }),
  writeFile(publicManifest, manifestBytes, { mode: 0o644 }),
]);
process.stdout.write(`${JSON.stringify({ artifact, manifest: manifestPath, publicArtifact, publicManifest, ...manifest }, null, 2)}\n`);
