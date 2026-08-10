#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { keccak256, stringToHex, toHex } from "viem";
import { buildGoldKeyCreate2Deployment } from "./create2-deployment.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));

function usage() {
  return `Usage:
  node scripts/build-create2-deployment.mjs [--out PATH]
  node scripts/build-create2-deployment.mjs --sample-sepolia [--out PATH]

This command only reads a local Foundry artifact and writes JSON. It never reads a
private key, contacts an RPC endpoint, asks a paymaster to sponsor gas, or sends a
transaction.

Real-build environment variables:
  GOLDKEY_NETWORK             base-sepolia or base
  GOLDKEY_OWNER               nonzero owner/Safe address
  GOLDKEY_TREASURY            nonzero treasury/Safe address
  GOLDKEY_METADATA_BASE_URI   HTTPS URL ending in /
  GOLDKEY_TERMS_URI           HTTPS terms URL
  GOLDKEY_TERMS_HASH          32-byte keccak256 hash
  GOLDKEY_CREATE2_SALT        nonzero bytes32 salt

Optional:
  GOLDKEY_USDC                must equal canonical Circle USDC for the network
  GOLDKEY_ARTIFACT            artifact path relative to this project (or absolute)
`;
}

function parseArgs(argv) {
  const options = { sampleSepolia: false, outputPath: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--sample-sepolia") {
      options.sampleSepolia = true;
    } else if (argument === "--out") {
      options.outputPath = argv[index + 1];
      if (!options.outputPath) throw new Error("--out requires a path");
      index += 1;
    } else if (argument === "--help" || argument === "-h") {
      options.help = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return options;
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function readArtifact(pathFromEnvironment) {
  const relativeOrAbsolute =
    pathFromEnvironment ?? "contracts/out/GoldKey.sol/GoldKey.json";
  const artifactPath = isAbsolute(relativeOrAbsolute)
    ? relativeOrAbsolute
    : resolve(projectRoot, relativeOrAbsolute);
  let artifact;
  try {
    artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  } catch (error) {
    throw new Error(
      `cannot read GoldKey artifact at ${artifactPath}; run npm run test:contract first (${error.message})`,
    );
  }
  return { artifact, artifactPath, artifactLabel: relativeOrAbsolute };
}

function sampleInputs() {
  const termsBytes = readFileSync(resolve(projectRoot, "TERMS.md"));
  return {
    network: "base-sepolia",
    initialOwner: "0x1111111111111111111111111111111111111111",
    initialTreasury: "0x2222222222222222222222222222222222222222",
    metadataBaseUri: "https://testnet-api.example.invalid/metadata/",
    termsUri: "https://testnet-api.example.invalid/terms",
    termsHash: keccak256(toHex(termsBytes)),
    salt: keccak256(stringToHex("goldkey-offline-base-sepolia-sample-v1")),
    sample: true,
  };
}

function environmentInputs() {
  return {
    network: requiredEnvironment("GOLDKEY_NETWORK"),
    initialOwner: requiredEnvironment("GOLDKEY_OWNER"),
    initialTreasury: requiredEnvironment("GOLDKEY_TREASURY"),
    metadataBaseUri: requiredEnvironment("GOLDKEY_METADATA_BASE_URI"),
    termsUri: requiredEnvironment("GOLDKEY_TERMS_URI"),
    termsHash: requiredEnvironment("GOLDKEY_TERMS_HASH"),
    salt: requiredEnvironment("GOLDKEY_CREATE2_SALT"),
    usdc: process.env.GOLDKEY_USDC,
    sample: false,
  };
}

export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(usage());
    return;
  }

  const { artifact, artifactLabel } = readArtifact(process.env.GOLDKEY_ARTIFACT);
  const inputs = options.sampleSepolia ? sampleInputs() : environmentInputs();
  const manifest = buildGoldKeyCreate2Deployment({
    artifact,
    artifactPath: artifactLabel,
    ...inputs,
  });
  const output = `${JSON.stringify(manifest, null, 2)}\n`;

  if (options.outputPath) {
    const outputPath = isAbsolute(options.outputPath)
      ? options.outputPath
      : resolve(process.cwd(), options.outputPath);
    writeFileSync(outputPath, output, { encoding: "utf8", flag: "wx" });
    process.stdout.write(`Wrote offline deployment manifest to ${outputPath}\n`);
    return;
  }

  process.stdout.write(output);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`Error: ${error.message}\n\n${usage()}`);
    process.exitCode = 1;
  }
}
