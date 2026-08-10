import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  MAINNET_RELEASE,
  buildMainnetDeploymentInput,
  calculateFundingBudget,
  deploymentSizing,
} from "../scripts/mainnet-preflight-data.mjs";

const scriptPath = new URL("../scripts/mainnet-preflight.zsh", import.meta.url);
const confirmationScriptPath = new URL("../scripts/mainnet-confirm-and-verify.zsh", import.meta.url);
const artifactPath = new URL("../contracts/out/GoldKey.sol/GoldKey.json", import.meta.url);

test("mainnet release input freezes the intended constructor and compiler settings", () => {
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  const deployment = buildMainnetDeploymentInput(artifact);

  assert.equal(MAINNET_RELEASE.chainId, 8453);
  assert.equal(MAINNET_RELEASE.deployer, "0xd6b7E00FcD46966676F554fE0455BfF739e85b1b");
  assert.equal(MAINNET_RELEASE.owner, MAINNET_RELEASE.deployer);
  assert.equal(MAINNET_RELEASE.treasury, MAINNET_RELEASE.deployer);
  assert.equal(MAINNET_RELEASE.usdc, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
  assert.equal(
    MAINNET_RELEASE.publicOrigin,
    "https://goldkey-edge-storefront.noah-ing.workers.dev",
  );
  assert.equal(
    MAINNET_RELEASE.metadataBaseUri,
    "https://goldkey-edge-storefront.noah-ing.workers.dev/metadata/",
  );
  assert.equal(
    MAINNET_RELEASE.termsUri,
    "https://goldkey-edge-storefront.noah-ing.workers.dev/terms",
  );
  assert.equal(
    MAINNET_RELEASE.termsHash,
    "0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750",
  );
  assert.equal(
    deployment.creationBytecodeHash,
    "0x0f72ba5fbc99a627f014dc2d3323cd41907807ccde19ed143c9c5c5c26438cdc",
  );
  assert.equal(
    deployment.initCodeHash,
    "0x1ac4675966261ebcbc30b6be393f97142756a15c48c303f82e9af27149ea1d0c",
  );
  assert.equal(deployment.creationBytecodeBytes, 12_003);
  assert.equal(deployment.initCodeBytes, 12_387);
  assert.deepEqual(deployment.constructorArgs, [
    MAINNET_RELEASE.owner,
    MAINNET_RELEASE.usdc,
    MAINNET_RELEASE.treasury,
    MAINNET_RELEASE.metadataBaseUri,
    MAINNET_RELEASE.termsUri,
    MAINNET_RELEASE.termsHash,
  ]);
  assert.ok(deployment.initCode.startsWith(artifact.bytecode.object));
  assert.ok(deployment.initCodeBytes > deployment.creationBytecodeBytes);
  assert.match(deployment.initCodeHash, /^0x[0-9a-f]{64}$/);
});

test("funding budget applies independent gas, fee-cap, L1, and final margins", () => {
  const sizing = deploymentSizing("2500000", "5000000");
  assert.equal(sizing.gasLimit, 3_000_000n);
  assert.equal(sizing.feeCapWei, 10_000_000n);

  const short = calculateFundingBudget({
    gasEstimate: "2500000",
    gasPriceWei: "5000000",
    l1FeeEstimateWei: "1000000000000",
    l1FeeUpperBoundWei: "1500000000000",
    balanceWei: "100",
  });
  assert.equal(short.currentExecutionEstimateWei, 12_500_000_000_000n);
  assert.equal(short.currentTotalEstimateWei, 13_500_000_000_000n);
  assert.equal(short.preMarginBudgetWei, 31_500_000_000_000n);
  assert.equal(short.requiredWei, 39_375_000_000_000n);
  assert.equal(short.shortfallWei, short.requiredWei - 100n);
  assert.equal(short.funded, false);

  const funded = calculateFundingBudget({
    gasEstimate: "2500000",
    gasPriceWei: "5000000",
    l1FeeEstimateWei: "1000000000000",
    l1FeeUpperBoundWei: "1500000000000",
    balanceWei: short.requiredWei,
  });
  assert.equal(funded.shortfallWei, 0n);
  assert.equal(funded.funded, true);
});

test("operator command is syntactically valid and has no signing or publishing path", () => {
  execFileSync("/bin/zsh", ["-n", scriptPath.pathname]);
  const source = readFileSync(scriptPath, "utf8");

  assert.match(source, /read -rs "RPC_URL\?/);
  assert.match(source, /chain_id.*8453|CHAIN_ID="8453"/s);
  assert.match(source, /cmp -s .*TERMS\.md.*LIVE_TERMS/);
  assert.match(source, /forge"? build|FORGE_BIN.* build/s);
  assert.match(source, /cast"? estimate|CAST_BIN.* estimate/s);
  assert.match(source, /getL1Fee\(bytes\)\(uint256\)/);
  assert.match(source, /getL1FeeUpperBound\(uint256\)\(uint256\)/);
  assert.match(source, /mktx --raw-unsigned/);
  assert.doesNotMatch(
    source,
    /--broadcast|--private-key|--keystore|--account|--mnemonic|--interactive|cast\s+send|cast\s+publish|eth_sendTransaction|eth_sendRawTransaction/,
  );
});

test("mainnet confirmation is read-only except for source publication", () => {
  execFileSync("/bin/zsh", ["-n", confirmationScriptPath.pathname]);
  const source = readFileSync(confirmationScriptPath, "utf8");

  assert.match(source, /0x94b0dd9f5bbb93216aea85e1384c5592372e3dcf1ab5da04e51c5f48c6e022c6/);
  assert.match(source, /0x220FE98C77CE79baa00d47C5896BE05C2A7D3db0/);
  assert.match(source, /0x1ac4675966261ebcbc30b6be393f97142756a15c48c303f82e9af27149ea1d0c/);
  assert.match(source, /verify-contract/);
  assert.match(source, /base\.blockscout\.com\/api\//);
  assert.doesNotMatch(
    source,
    /--broadcast|--private-key|--keystore|--account|--mnemonic|cast\s+send|cast\s+publish|forge\s+create|eth_sendTransaction|eth_sendRawTransaction/,
  );
});
