import { readFileSync } from "node:fs";
import { keccak256, toHex } from "viem";
import { createApp } from "./app.mjs";
import { createAuthService } from "./auth.mjs";
import { createChainService } from "./chain.mjs";
import { loadConfig } from "./config.mjs";
import { createGoldKeyDatabase } from "./database.mjs";
import { createGuardService } from "./guard-service.mjs";
import { createPilotApplicationsService } from "./pilot-applications.mjs";
import { validateX402Facilitator } from "./x402.mjs";

const config = loadConfig();
const chain = createChainService(config);
const termsBytes = readFileSync(new URL("../TERMS.md", import.meta.url));
const expectedTermsHash = keccak256(toHex(termsBytes));
const deployment = await chain.validateDeployment({ expectedTermsHash });
const x402 = await validateX402Facilitator(config);
const db = await createGoldKeyDatabase(config);
const auth = createAuthService({ config, db, chain });
const guard = config.guardEnabled ? createGuardService({ config, db, chain, previousPublicKeys: config.guardReceiptPreviousPublicKeys }) : undefined;
const pilotApplications = config.pilotApplicationsEnabled
  ? createPilotApplicationsService({
      database: db,
      adminTokenSha256: config.pilotAdminTokenSha256,
      abuseSecret: config.pilotAbuseSecret,
      retentionDays: config.pilotRetentionDays,
    })
  : undefined;
const app = createApp({ config, db, chain, auth, guard, pilotApplications });

const server = app.listen(config.port, () => {
  console.log(JSON.stringify({
    event: "goldkey_started",
    origin: config.publicOrigin,
    port: config.port,
    chain_id: config.chainId,
    contract: deployment.contractAddress,
    usdc: deployment.usdcAddress,
    treasury: deployment.treasuryAddress,
    terms_hash: deployment.termsHash,
    x402_enabled: config.x402Enabled,
    x402_network: x402.network,
    x402_scheme: x402.scheme,
    x402_version: x402.x402Version,
    guard_enabled: config.guardEnabled,
    guard_network_price_usdc: config.guardEnabled ? config.guardNetworkPriceUsd : undefined,
    guard_evm_price_usdc: config.guardEnabled ? config.guardEvmPriceUsd : undefined,
    pilot_applications_enabled: config.pilotApplicationsEnabled,
  }));
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  server.close(async () => {
    await db.close();
    console.log(JSON.stringify({ event: "goldkey_stopped", signal }));
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
