import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  concatHex,
  encodeAbiParameters,
  encodeDeployData,
  getAddress,
  isHex,
  keccak256,
  size,
} from "viem";

export const MAINNET_RELEASE = Object.freeze({
  chainId: 8453,
  deployer: getAddress("0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"),
  owner: getAddress("0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"),
  treasury: getAddress("0xd6b7E00FcD46966676F554fE0455BfF739e85b1b"),
  usdc: getAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
  publicOrigin: "https://goldkey-edge-storefront.noah-ing.workers.dev",
  metadataBaseUri: "https://goldkey-edge-storefront.noah-ing.workers.dev/metadata/",
  termsUri: "https://goldkey-edge-storefront.noah-ing.workers.dev/terms",
  termsHash: "0xd1fb20b0e28b63e18b660a2710f1b69b356bc87829a01cf5d75e572ae7de3750",
  gasPriceOracle: getAddress("0x420000000000000000000000000000000000000F"),
  creationBytecodeHash: "0x0f72ba5fbc99a627f014dc2d3323cd41907807ccde19ed143c9c5c5c26438cdc",
  initCodeHash: "0x1ac4675966261ebcbc30b6be393f97142756a15c48c303f82e9af27149ea1d0c",
});

const CONSTRUCTOR_TYPES = ["address", "address", "address", "string", "string", "bytes32"];
const CONSTRUCTOR_PARAMETERS = [
  { name: "initialOwner", type: "address" },
  { name: "usdc", type: "address" },
  { name: "initialTreasury", type: "address" },
  { name: "baseTokenURI", type: "string" },
  { name: "termsURI", type: "string" },
  { name: "termsHash", type: "bytes32" },
];

function assertReleaseArtifact(artifact) {
  if (!artifact || !Array.isArray(artifact.abi)) {
    throw new Error("GoldKey artifact must contain an ABI");
  }

  const constructor = artifact.abi.find((entry) => entry.type === "constructor");
  const actualTypes = constructor?.inputs?.map((input) => input.type);
  if (
    !actualTypes ||
    actualTypes.length !== CONSTRUCTOR_TYPES.length ||
    actualTypes.some((type, index) => type !== CONSTRUCTOR_TYPES[index])
  ) {
    throw new Error(`GoldKey constructor must be (${CONSTRUCTOR_TYPES.join(",")})`);
  }

  const bytecode = artifact.bytecode?.object;
  if (!isHex(bytecode) || bytecode === "0x" || bytecode.includes("__")) {
    throw new Error("GoldKey creation bytecode is missing or unlinked");
  }
  const hasLinks = Object.values(artifact.bytecode?.linkReferences ?? {}).some(
    (references) => Object.keys(references).length > 0,
  );
  if (hasLinks) throw new Error("GoldKey creation bytecode contains library links");

  const compiler = artifact.metadata?.compiler?.version;
  const optimizer = artifact.metadata?.settings?.optimizer;
  const evmVersion = artifact.metadata?.settings?.evmVersion;
  if (compiler !== "0.8.24+commit.e11b9ed9") {
    throw new Error(`Unexpected Solidity compiler: ${compiler ?? "missing"}`);
  }
  if (optimizer?.enabled !== true || optimizer?.runs !== 10_000) {
    throw new Error("GoldKey artifact must use the frozen 10,000-run optimizer settings");
  }
  if (evmVersion !== "cancun") {
    throw new Error(`Unexpected EVM version: ${evmVersion ?? "missing"}`);
  }
  return bytecode;
}

export function buildMainnetDeploymentInput(artifact) {
  const bytecode = assertReleaseArtifact(artifact);
  const constructorArgs = [
    MAINNET_RELEASE.owner,
    MAINNET_RELEASE.usdc,
    MAINNET_RELEASE.treasury,
    MAINNET_RELEASE.metadataBaseUri,
    MAINNET_RELEASE.termsUri,
    MAINNET_RELEASE.termsHash,
  ];
  const encodedConstructorArgs = encodeAbiParameters(CONSTRUCTOR_PARAMETERS, constructorArgs);
  const initCode = encodeDeployData({ abi: artifact.abi, bytecode, args: constructorArgs });
  if (initCode !== concatHex([bytecode, encodedConstructorArgs])) {
    throw new Error("Encoded init code does not equal bytecode plus constructor arguments");
  }

  const creationBytecodeHash = keccak256(bytecode);
  const initCodeHash = keccak256(initCode);
  if (creationBytecodeHash !== MAINNET_RELEASE.creationBytecodeHash) {
    throw new Error(`Creation bytecode hash changed: ${creationBytecodeHash}`);
  }
  if (initCodeHash !== MAINNET_RELEASE.initCodeHash) {
    throw new Error(`Mainnet init code hash changed: ${initCodeHash}`);
  }

  return Object.freeze({
    constructorArgs: Object.freeze(constructorArgs),
    encodedConstructorArgs,
    creationBytecodeHash,
    creationBytecodeBytes: size(bytecode),
    initCode,
    initCodeHash,
    initCodeBytes: size(initCode),
  });
}

function positiveBigInt(value, name) {
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error(`${name} must be positive`);
  return parsed;
}

function nonnegativeBigInt(value, name) {
  const parsed = BigInt(value);
  if (parsed < 0n) throw new Error(`${name} must not be negative`);
  return parsed;
}

function ceilDiv(numerator, denominator) {
  return (numerator + denominator - 1n) / denominator;
}

export function deploymentSizing(gasEstimateValue, gasPriceValue) {
  const gasEstimate = positiveBigInt(gasEstimateValue, "gasEstimate");
  const gasPriceWei = positiveBigInt(gasPriceValue, "gasPriceWei");
  return Object.freeze({
    gasEstimate,
    gasPriceWei,
    gasLimit: ceilDiv(gasEstimate * 120n, 100n),
    feeCapWei: gasPriceWei * 2n,
  });
}

export function calculateFundingBudget({
  gasEstimate: gasEstimateValue,
  gasPriceWei: gasPriceValue,
  l1FeeEstimateWei: l1FeeEstimateValue,
  l1FeeUpperBoundWei: l1FeeUpperBoundValue,
  balanceWei: balanceValue,
}) {
  const sizing = deploymentSizing(gasEstimateValue, gasPriceValue);
  const l1FeeEstimateWei = nonnegativeBigInt(l1FeeEstimateValue, "l1FeeEstimateWei");
  const l1FeeUpperBoundWei = nonnegativeBigInt(l1FeeUpperBoundValue, "l1FeeUpperBoundWei");
  const balanceWei = nonnegativeBigInt(balanceValue, "balanceWei");
  const l1BudgetWei = l1FeeUpperBoundWei > l1FeeEstimateWei
    ? l1FeeUpperBoundWei
    : l1FeeEstimateWei;
  const currentExecutionEstimateWei = sizing.gasEstimate * sizing.gasPriceWei;
  const currentTotalEstimateWei = currentExecutionEstimateWei + l1FeeEstimateWei;
  const preMarginBudgetWei = sizing.gasLimit * sizing.feeCapWei + l1BudgetWei;
  const requiredWei = ceilDiv(preMarginBudgetWei * 125n, 100n);
  const shortfallWei = balanceWei >= requiredWei ? 0n : requiredWei - balanceWei;

  return Object.freeze({
    ...sizing,
    l1FeeEstimateWei,
    l1FeeUpperBoundWei,
    l1BudgetWei,
    balanceWei,
    currentExecutionEstimateWei,
    currentTotalEstimateWei,
    preMarginBudgetWei,
    requiredWei,
    shortfallWei,
    funded: shortfallWei === 0n,
  });
}

function printLines(values) {
  process.stdout.write(`${values.map(String).join("\n")}\n`);
}

function runCli(argv) {
  const [mode, ...args] = argv;
  if (mode === "input" && args.length === 1) {
    const artifact = JSON.parse(readFileSync(resolve(args[0]), "utf8"));
    const input = buildMainnetDeploymentInput(artifact);
    printLines([
      input.initCode,
      input.initCodeHash,
      input.creationBytecodeHash,
      input.initCodeBytes,
      input.creationBytecodeBytes,
    ]);
    return;
  }
  if (mode === "sizing" && args.length === 2) {
    const sizing = deploymentSizing(args[0], args[1]);
    printLines([sizing.gasLimit, sizing.feeCapWei]);
    return;
  }
  if (mode === "budget" && args.length === 5) {
    const budget = calculateFundingBudget({
      gasEstimate: args[0],
      gasPriceWei: args[1],
      l1FeeEstimateWei: args[2],
      l1FeeUpperBoundWei: args[3],
      balanceWei: args[4],
    });
    printLines([
      budget.gasLimit,
      budget.feeCapWei,
      budget.currentExecutionEstimateWei,
      budget.currentTotalEstimateWei,
      budget.l1BudgetWei,
      budget.preMarginBudgetWei,
      budget.requiredWei,
      budget.shortfallWei,
      budget.funded ? "FUNDED" : "SHORT",
    ]);
    return;
  }
  throw new Error(
    "Usage: mainnet-preflight-data.mjs input <artifact> | sizing <gas> <gas-price> | budget <gas> <gas-price> <l1-estimate> <l1-upper> <balance>",
  );
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`MAINNET PREFLIGHT DATA FAILED: ${error.message}\n`);
    process.exitCode = 1;
  }
}
