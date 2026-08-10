import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  concatHex,
  decodeFunctionData,
  encodeAbiParameters,
  getAddress,
  keccak256,
  sliceHex,
} from "viem";
import {
  BASE_CREATE2_DEPLOYER,
  CREATE2_DEPLOYER_ABI,
  buildGoldKeyCreate2Deployment,
} from "../scripts/create2-deployment.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const artifact = JSON.parse(
  readFileSync(resolve(projectRoot, "contracts/out/GoldKey.sol/GoldKey.json"), "utf8"),
);

const fixture = {
  artifact,
  network: "base-sepolia",
  initialOwner: "0x1111111111111111111111111111111111111111",
  initialTreasury: "0x2222222222222222222222222222222222222222",
  metadataBaseUri: "https://testnet-api.example.invalid/metadata/",
  termsUri: "https://testnet-api.example.invalid/terms",
  termsHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  salt: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
};

test("builds deterministic GoldKey init code, CREATE2 address, and sponsored call data", () => {
  const first = buildGoldKeyCreate2Deployment(fixture);
  const second = buildGoldKeyCreate2Deployment(fixture);
  assert.deepEqual(first, second);

  assert.equal(first.broadcastsTransactions, false);
  assert.equal(first.network, "base-sepolia");
  assert.equal(first.chainId, 84532);
  assert.equal(first.factory.address, BASE_CREATE2_DEPLOYER);
  assert.equal(first.factory.function, "deploy(uint256,bytes32,bytes)");
  assert.equal(first.factory.selector, "0x66cfa057");
  assert.equal(first.cdpUserOperation.calls[0].to, BASE_CREATE2_DEPLOYER);
  assert.equal(first.cdpUserOperation.calls[0].value, "0");

  const decoded = decodeFunctionData({
    abi: CREATE2_DEPLOYER_ABI,
    data: first.cdpUserOperation.calls[0].data,
  });
  assert.equal(decoded.functionName, "deploy");
  assert.equal(decoded.args[0], 0n);
  assert.equal(decoded.args[1], fixture.salt);
  assert.equal(decoded.args[2], first.deployment.initCode);

  const expectedConstructorArgs = encodeAbiParameters(
    [
      { type: "address" },
      { type: "address" },
      { type: "address" },
      { type: "string" },
      { type: "string" },
      { type: "bytes32" },
    ],
    [
      getAddress(fixture.initialOwner),
      first.constructor.usdc,
      getAddress(fixture.initialTreasury),
      fixture.metadataBaseUri,
      fixture.termsUri,
      fixture.termsHash,
    ],
  );
  assert.equal(first.constructor.encodedArguments, expectedConstructorArgs);
  assert.equal(
    first.deployment.initCode,
    concatHex([artifact.bytecode.object, expectedConstructorArgs]),
  );

  const create2Digest = keccak256(
    concatHex([
      "0xff",
      BASE_CREATE2_DEPLOYER,
      fixture.salt,
      first.deployment.initCodeHash,
    ]),
  );
  assert.equal(
    first.deployment.predictedAddress,
    getAddress(sliceHex(create2Digest, 12)),
  );
});

test("pins canonical Circle USDC and refuses unsafe deployment inputs", () => {
  assert.equal(
    buildGoldKeyCreate2Deployment(fixture).constructor.usdc,
    "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  );

  assert.throws(
    () =>
      buildGoldKeyCreate2Deployment({
        ...fixture,
        usdc: "0x3333333333333333333333333333333333333333",
      }),
    /canonical base-sepolia USDC/,
  );
  assert.throws(
    () =>
      buildGoldKeyCreate2Deployment({
        ...fixture,
        initialOwner: "0x0000000000000000000000000000000000000000",
      }),
    /must not be the zero address/,
  );
  assert.throws(
    () => buildGoldKeyCreate2Deployment({ ...fixture, metadataBaseUri: "https://example.invalid/metadata" }),
    /must end in \/$/,
  );
  assert.throws(
    () => buildGoldKeyCreate2Deployment({ ...fixture, termsHash: `0x${"00".repeat(32)}` }),
    /must not be zero/,
  );
});

test("Sepolia sample CLI is networkless, deterministic, and contains no signer fields", () => {
  const command = spawnSync(
    process.execPath,
    [resolve(projectRoot, "scripts/build-create2-deployment.mjs"), "--sample-sepolia"],
    {
      cwd: projectRoot,
      encoding: "utf8",
      env: { PATH: process.env.PATH },
      maxBuffer: 2 * 1024 * 1024,
    },
  );

  assert.equal(command.status, 0, command.stderr);
  const manifest = JSON.parse(command.stdout);
  assert.equal(manifest.mode, "offline-sepolia-sample");
  assert.equal(manifest.broadcastsTransactions, false);
  assert.equal(manifest.network, "base-sepolia");
  assert.equal(manifest.cdpUserOperation.calls.length, 1);
  assert.equal("privateKey" in manifest, false);
  assert.equal("rpcUrl" in manifest, false);
  assert.equal("paymasterUrl" in manifest, false);
});
