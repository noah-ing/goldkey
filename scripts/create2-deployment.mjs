import {
  concatHex,
  encodeAbiParameters,
  encodeDeployData,
  encodeFunctionData,
  getAddress,
  getCreate2Address,
  isAddress,
  isHex,
  keccak256,
  numberToHex,
  size,
} from "viem";

export const BASE_CREATE2_DEPLOYER = getAddress(
  "0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2",
);

export const CREATE2_DEPLOY_FUNCTION = "deploy(uint256,bytes32,bytes)";

export const CREATE2_DEPLOYER_ABI = [
  {
    type: "function",
    name: "deploy",
    stateMutability: "nonpayable",
    inputs: [
      { name: "value", type: "uint256" },
      { name: "salt", type: "bytes32" },
      { name: "code", type: "bytes" },
    ],
    outputs: [],
  },
];

export const GOLDKEY_NETWORKS = Object.freeze({
  "base-sepolia": Object.freeze({
    chainId: 84532,
    usdc: getAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
  }),
  base: Object.freeze({
    chainId: 8453,
    usdc: getAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
  }),
});

const EXPECTED_CONSTRUCTOR_TYPES = ["address", "address", "address", "string", "string", "bytes32"];
const CONSTRUCTOR_ABI_PARAMETERS = [
  { name: "initialOwner", type: "address" },
  { name: "usdc", type: "address" },
  { name: "initialTreasury", type: "address" },
  { name: "baseTokenURI", type: "string" },
  { name: "termsURI", type: "string" },
  { name: "termsHash", type: "bytes32" },
];

function requireAddress(value, name) {
  if (!isAddress(value, { strict: false })) {
    throw new Error(`${name} must be a valid EVM address`);
  }

  const address = getAddress(value);
  if (address === "0x0000000000000000000000000000000000000000") {
    throw new Error(`${name} must not be the zero address`);
  }
  return address;
}

function requireBytes32(value, name, { allowZero = false } = {}) {
  if (!isHex(value) || size(value) !== 32) {
    throw new Error(`${name} must be exactly 32 bytes (0x plus 64 hex characters)`);
  }
  if (!allowZero && /^0x0{64}$/i.test(value)) {
    throw new Error(`${name} must not be zero`);
  }
  return value.toLowerCase();
}

function requireHttpsUrl(value, name, { trailingSlash = false } = {}) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid URL`);
  }

  if (parsed.protocol !== "https:") {
    throw new Error(`${name} must use https`);
  }
  if (trailingSlash && !value.endsWith("/")) {
    throw new Error(`${name} must end in /`);
  }
  return value;
}

function validateArtifact(artifact) {
  if (!artifact || !Array.isArray(artifact.abi)) {
    throw new Error("GoldKey artifact must contain an ABI");
  }

  const constructor = artifact.abi.find((entry) => entry.type === "constructor");
  const constructorTypes = constructor?.inputs?.map((input) => input.type);
  if (
    !constructorTypes ||
    constructorTypes.length !== EXPECTED_CONSTRUCTOR_TYPES.length ||
    constructorTypes.some((type, index) => type !== EXPECTED_CONSTRUCTOR_TYPES[index])
  ) {
    throw new Error(
      `GoldKey constructor must be (${EXPECTED_CONSTRUCTOR_TYPES.join(",")})`,
    );
  }

  const bytecode = artifact.bytecode?.object;
  if (!isHex(bytecode) || bytecode === "0x") {
    throw new Error("GoldKey artifact must contain non-empty creation bytecode");
  }

  const unresolvedLinks = Object.values(artifact.bytecode?.linkReferences ?? {}).some(
    (referencesByLibrary) => Object.keys(referencesByLibrary).length > 0,
  );
  if (unresolvedLinks || bytecode.includes("__")) {
    throw new Error("GoldKey creation bytecode contains unresolved library links");
  }

  return bytecode;
}

function computeCreate2Address({ factory, salt, initCodeHash }) {
  return getCreate2Address({ from: factory, salt, bytecodeHash: initCodeHash });
}

export function buildGoldKeyCreate2Deployment({
  artifact,
  network,
  initialOwner,
  initialTreasury,
  metadataBaseUri,
  termsUri,
  termsHash,
  salt,
  usdc,
  artifactPath = "contracts/out/GoldKey.sol/GoldKey.json",
  sample = false,
}) {
  const networkConfig = GOLDKEY_NETWORKS[network];
  if (!networkConfig) {
    throw new Error(`network must be one of: ${Object.keys(GOLDKEY_NETWORKS).join(", ")}`);
  }

  const bytecode = validateArtifact(artifact);
  const owner = requireAddress(initialOwner, "initialOwner");
  const treasury = requireAddress(initialTreasury, "initialTreasury");
  const canonicalUsdc = networkConfig.usdc;
  const paymentToken = usdc ? requireAddress(usdc, "usdc") : canonicalUsdc;
  if (paymentToken !== canonicalUsdc) {
    throw new Error(`usdc must equal Circle's canonical ${network} USDC ${canonicalUsdc}`);
  }

  const baseTokenURI = requireHttpsUrl(metadataBaseUri, "metadataBaseUri", {
    trailingSlash: true,
  });
  const licenseTermsURI = requireHttpsUrl(termsUri, "termsUri");
  const licenseTermsHash = requireBytes32(termsHash, "termsHash");
  const create2Salt = requireBytes32(salt, "salt");

  const constructorArgs = [
    owner,
    paymentToken,
    treasury,
    baseTokenURI,
    licenseTermsURI,
    licenseTermsHash,
  ];
  const encodedConstructorArgs = encodeAbiParameters(
    CONSTRUCTOR_ABI_PARAMETERS,
    constructorArgs,
  );
  const initCode = encodeDeployData({ abi: artifact.abi, bytecode, args: constructorArgs });

  // Guard against an ABI or encoder change silently producing a different payload shape.
  if (initCode !== concatHex([bytecode, encodedConstructorArgs])) {
    throw new Error("encoded GoldKey init code does not match bytecode plus constructor arguments");
  }

  const initCodeHash = keccak256(initCode);
  const predictedAddress = computeCreate2Address({
    factory: BASE_CREATE2_DEPLOYER,
    salt: create2Salt,
    initCodeHash,
  });
  const calldata = encodeFunctionData({
    abi: CREATE2_DEPLOYER_ABI,
    functionName: "deploy",
    args: [0n, create2Salt, initCode],
  });

  const cdpCall = {
    to: BASE_CREATE2_DEPLOYER,
    value: "0",
    data: calldata,
  };
  const eip5792Call = {
    to: BASE_CREATE2_DEPLOYER,
    value: "0x0",
    data: calldata,
  };

  return {
    schema: "goldkey-create2-deployment/v1",
    mode: sample ? "offline-sepolia-sample" : "offline-build",
    broadcastsTransactions: false,
    network,
    chainId: networkConfig.chainId,
    chainIdHex: numberToHex(networkConfig.chainId),
    constructor: {
      initialOwner: owner,
      usdc: paymentToken,
      initialTreasury: treasury,
      baseTokenURI,
      termsURI: licenseTermsURI,
      termsHash: licenseTermsHash,
      encodedArguments: encodedConstructorArgs,
    },
    artifact: {
      path: artifactPath,
      compilerVersion: artifact.metadata?.compiler?.version ?? null,
      optimizer: artifact.metadata?.settings?.optimizer ?? null,
      creationBytecodeBytes: size(bytecode),
      creationBytecodeHash: keccak256(bytecode),
    },
    factory: {
      address: BASE_CREATE2_DEPLOYER,
      function: CREATE2_DEPLOY_FUNCTION,
      selector: calldata.slice(0, 10),
      value: "0",
    },
    deployment: {
      salt: create2Salt,
      initCode,
      initCodeBytes: size(initCode),
      initCodeHash,
      predictedAddress,
    },
    cdpUserOperation: {
      network,
      calls: [cdpCall],
    },
    walletSendCalls: {
      version: "2.0.0",
      chainId: numberToHex(networkConfig.chainId),
      atomicRequired: true,
      calls: [eip5792Call],
      requiredRuntimeField: "from",
    },
    paymasterPolicy: {
      allowlistedContract: BASE_CREATE2_DEPLOYER,
      allowlistedFunction: CREATE2_DEPLOY_FUNCTION,
      recommendedMaxUserOperations: 1,
      disableAfterDeployment: true,
    },
  };
}
