# GoldKey: shortest path to first revenue

The first target is one legitimate outside 0.01-USDC x402 call. That call proves
settlement and causes CDP Bazaar to index the advertised route. The next target
is one outside 50-USDC GoldKey mint from an agent whose live quote forecasts more
than 5,000 eligible calls and remains positive after its own risk costs.

## 1. User-only setup

Do these first. Never paste a seed phrase, private key, keystore password,
database URL, RPC URL, or CDP secret into chat or source control.

1. Create one dedicated encrypted deployment wallet:

   ```sh
   /Users/noah-ing/.foundry/bin/cast wallet new /Users/noah-ing/.foundry/keystores goldkey-deployer
   ```

   Enter a strong password only in the hidden local prompt. Back up the encrypted
   keystore and password separately. Share only the printed public `0x...`
   address. Use this address as deployer, owner, and treasury during the
   zero-cash bootstrap; migrate owner and treasury to separate Safes after revenue.

2. Create or sign into GitHub, then create an empty repository named `goldkey`.
   Make it public before launch so agent buyers can inspect the source. Do not add
   a README, license, or `.gitignore` in GitHub; the release already contains them.
3. Create free accounts at Cloudflare, Neon, Render, Alchemy, Coinbase Developer
   Platform, and ClawHub. Use GitHub sign-in where offered.
4. Send Codex only these public values: wallet address, GitHub repository URL,
   desired Cloudflare account subdomain, and ClawHub handle.

## 2. Free-account values

### Alchemy

- Create `goldkey-sepolia` for Base Sepolia and `goldkey-mainnet` for Base.
- Copy each HTTPS RPC endpoint into the relevant provider dashboard as a secret.
- Do not commit or paste either endpoint into chat.

### Neon

- Create project `goldkey` in the US region closest to Render Ohio.
- Create separate `development` and `production` branches.
- For each branch select the pooled connection and confirm the URL ends with
  `sslmode=require` (or a stronger verification mode).
- `development` is Sepolia; `production` is Base mainnet.

### Cloudflare

- Create Worker `goldkey-edge-sepolia` from repository folder `edge/`.
- Create Worker `goldkey-edge-storefront` from the same folder.
- Keep both `workers.dev` URLs permanently; never rename or delete them after the
  corresponding contract deployment.
- Build command: `npm test`.
- Deploy command: `npx wrangler deploy --env mainnet` for mainnet. The Sepolia
  Worker uses the top-level configuration with `npx wrangler deploy`.

The first deployment may have no commerce variables. `/healthz`, `/terms`,
`/v1/demo`, `/v1/catalog`, and `/openapi.json` must still respond. Put the final
Worker URL into the contract constructor before deployment.

### CDP

- Create project `goldkey`.
- Create an Ed25519 Secret API Key named `goldkey-x402`.
- Copy the key ID and raw base64 secret exactly once and enter them only as secret
  Render environment variables.
- Use `https://api.cdp.coinbase.com/platform/v2/x402` on mainnet.
- Apply for Paymaster credits only as a fallback deployment route. An application
  is not funding.

### Render

Create one Docker Web Service from the repository using `render.free-sepolia.yaml`
for acceptance. After mainnet deployment, replace its configuration with
`render.free.yaml`. Keep auto-deploy off until each configuration is validated.

## 3. Sepolia release rehearsal

1. Codex freezes the current terms hash, constructor, Worker URL, bytecode, and
   test manifest.
2. Claim Base Sepolia ETH from an official listed faucet.
3. Obtain exactly 50 Circle test USDC without evading faucet limits. A fast
   compliant combination is 20 from Circle plus up to 10 total from CDP at time
   zero, then another 20 from Circle after its two-hour interval.
4. Deploy and verify the exact release candidate with Circle Base Sepolia USDC:
   `0x036CbD53842c5426634e7929541eC2318f3dCF7e`.
5. Populate the Sepolia Worker and Render values. Enter RPC and database values as
   secrets in their dashboards.
6. Run mint, authentication, quota, exact retry, child-key, transfer invalidation,
   renewal rejection, x402, Neon contention, Neon reconnect, and Render restart
   acceptance tests.

Do not proceed if any acceptance check fails.

## 4. Mainnet deployment with no operator cash

1. Freeze bytes and URLs. No changes after this point without re-simulation.
2. Run `./scripts/mainnet-preflight.zsh`. It verifies the permanent storefront,
   freezes the exact creation input, estimates execution plus L1 data cost, and
   prints `FUNDED` or the exact `SHORT` amount without loading a signer.
3. Only then claim the one-time Base mainnet amount from `ethfaucet.com` to the
   dedicated wallet.
4. Deploy only if the confirmed balance covers simulation plus margin. Otherwise
   use a confirmed CDP-sponsored user operation through Base's fixed
   `Create2Deployer` at `0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2`.
5. Verify source and constructor arguments through Base Blockscout.
6. Configure mainnet Render and Worker with chain `8453`, Circle Base USDC
   `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, the deployed GoldKey address,
   wallet treasury, frozen terms hash, mainnet RPC, and production CDP facilitator.
7. Require all of these before publishing:
   - Worker `/healthz` says commerce is configured.
   - `/.well-known/goldkey.json` reports live identity, 50 USDC, and 10,000
     remaining primary supply.
   - Render `/readyz` passes after a cold restart.
   - A 7,200-call quote returns one 50-USDC pass, 22-USDC raw savings, and only
     ordered unsigned approval/mint transactions.

## 5. Publish where agents already search

The bundled client pins the accepted mainnet release identity. Confirm it
contains no `{{GOLDKEY_...}}` values and its `self-test` passes before a ClawHub
dry run or update is published:

```sh
npm install --global clawhub
clawhub login
clawhub skill publish ./distribution/goldkey-agent-utilities \
  --dry-run \
  --slug goldkey \
  --name "GoldKey Agent Utilities" \
  --categories integrations,security,finance \
  --topics x402,json,prompt-scan,api-payments,agent-tools
```

Repeat without `--dry-run`, adding the changelog `Initial mainnet release`, only
after inspection succeeds. The skill is free to install and clearly discloses the
external service prices.

GoldKey already advertises the x402 Bazaar v2 extension. There is no separate
Bazaar registration form: CDP indexes the endpoint after the first successful
outside settlement through its facilitator.

## 6. Revenue sequence

1. Free install and fixed demo.
2. Live quote using the agent's own forecast and risk costs.
3. First outside 0.01-USDC x402 call; confirm treasury receipt and Bazaar listing.
4. For forecasts at or below 5,000 calls, sell paygo only.
5. For positive risk-adjusted forecasts above break-even, return the exact
   unsigned 50-USDC approval and mint sequence.
6. Count a pass sale only after onchain settlement, ownership, and one successful
   authenticated call.
7. Use first proceeds for always-on hosting, separate Safe ownership/treasury,
   and operational reserves before extracting profit.
