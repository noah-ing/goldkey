# GoldKey zero-cash launch

This is the honest `$0` route: prove GoldKey on Base Sepolia, run the pre-revenue service on free infrastructure, obtain deployment gas without buying it, deploy mainnet, and let the first **outside buyer** mint normally for 50 USDC. There is no reservation, presale, self-purchase, wash trade, or promise that mainnet exists before it does.

## Hard truth

The route is conditional, not guaranteed.

- GoldKey now includes the Postgres adapter, migrations, pooled `DATABASE_URL` selection, and an opt-in live contention test. The adapter has not yet been validated against an actual Neon branch in this workspace. **Live Neon contention, idempotency, quota, migration, disconnect/reconnect, and service-restart validation remain mandatory before any mainnet sale.**
- Free Render services spin down after 15 idle minutes, can take about a minute to wake, and can restart. Neon Free also scales compute to zero after five idle minutes. Expect cold starts and disclose them. Free infrastructure is a bootstrap, not an uptime claim.
- The Base-documented mainnet faucet is a third-party service, provides only a small one-time amount, and may be unavailable, ineligible, or insufficient for this contract's deployment. Simulate the exact deployment first.
- CDP Paymaster is not automatically free. It is billed unless credits have actually been awarded. A sponsored CREATE2 deployment is an alternative to test, not a promise.
- If neither the mainnet faucet nor confirmed sponsorship covers the simulated deployment, the `$0` route is blocked. Wait for an unconditional gas grant or contribute ETH openly. Do not take a presale to hide the gap.

## Phase 1: public Base Sepolia proof behind the edge front door

1. Deploy the exact release candidate on Base Sepolia (`84532`) using test ETH and Circle test USDC.
2. Deploy `edge/` to its stable free `workers.dev` URL. Publish the test contract, source verification, terms bytes/hash, offer JSON, OpenAPI document, and reproducible smoke-test transaction hashes through that always-on front door. Set the sleeping Render service only as the Worker's `ORIGIN_API`.
3. Demonstrate mint, wallet authentication, quota debit, exact idempotent retry, child keys, transfer invalidation, renewal rejection before expiry, one test x402 call, and restart persistence.
4. Give evaluators a short-lived testnet child key or test NFT. Testnet proof is free and test assets have no monetary value.

Official references: [Base faucets](https://docs.base.org/base-chain/network-information/network-faucets), [Circle USDC addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses).

## Phase 2: validate the implemented Postgres adapter on free Neon

Before hosting mainnet:

- Use the implemented `src/database-postgres.mjs` adapter and its migrations; do not silently fall back to SQLite on Render.
- Confirm its Postgres transactions and row locking preserve atomic challenge consumption, quota increments, child-key limits, and idempotency under real Neon contention.
- Configure a pooled Neon `DATABASE_URL`; never ship the credential in the image or repository.
- Set `TEST_DATABASE_URL` to a disposable Neon branch and run the full application suite, including the opt-in parallel-call test in `test/database-postgres.test.mjs`; then perform disconnect/reconnect and Render restart tests against the same durable rows.
- Confirm `/readyz` executes its real Postgres health query after every restart.

Neon Free currently provides 100 CU-hours and 0.5 GB storage per project, up to 5 GB public transfer, and scales inactive compute to zero. Those are limits, not an SLA. Monitor all three and stop onboarding before exhaustion. [Neon pricing](https://neon.com/pricing), [Neon scale to zero](https://neon.com/docs/introduction/scale-to-zero).

## Phase 3: permanent free Worker URL plus replaceable free Render origin

1. Keep `https://goldkey-edge-storefront.<account-subdomain>.workers.dev` as the permanent `PUBLIC_ORIGIN`. Put that Worker's `/metadata/` and `/terms` URLs into the contract constructor. A custom domain is optional after revenue and must remain only an alias; it is not required for launch.
2. Create one free Render Web Service from the GoldKey Docker image and set its `https://<stable-name>.onrender.com` address only as the Worker's `ORIGIN_API`.
3. Keep all durable state in Neon; write no required state to the container filesystem.
4. Use `/readyz` as the health endpoint only after it checks Neon.
5. Do not run a second always-on free service: free instance hours are shared at workspace level.
6. The Worker serves health, terms, schema, discovery, catalog, live quotes, and metadata without Render. It proxies only authentication, quota, child-key, tool, and paygo fulfillment. Those fulfilled routes may cold-start honestly.
7. Do not rename or delete the Worker after contract deployment because the contract URLs are immutable. Render is not named onchain and can be upgraded or replaced by changing only `ORIGIN_API`.
8. Create a free Alchemy Base app at launch and use its credential-bearing HTTPS RPC URL for both the Worker and origin. Keep the key out of source control. Alchemy currently lists Base among supported networks and a Free plan with 30 million compute units per month and 25 requests per second; it is a quota, not an SLA. [Alchemy pricing](https://www.alchemy.com/pricing).

Render explicitly says free filesystems are ephemeral, persistent disks require a paid service, and idle free services spin down. The included `onrender.com` URL has managed TLS. [Render free services](https://render.com/docs/free), [Render TLS](https://render.com/docs/tls).

## Phase 4: obtain mainnet deployment gas

### Primary route: Base-documented mainnet faucet

Base's official faucet directory lists `ethfaucet.com`, operated by BringID, as providing a small one-time Base mainnet ETH claim for contract deployment. It is Base-documented, **not operated or guaranteed by Base**. [Base faucet directory](https://docs.base.org/base-chain/network-information/network-faucets).

1. Freeze bytecode, constructor arguments, owner, treasury, metadata URL, terms URL, and terms hash.
2. Simulate the exact deployment on Base mainnet and calculate execution plus L1 data fees with a safety margin.
3. Claim to the dedicated deployer only after the build is final; the mainnet claim is one-time.
4. Proceed only if the confirmed deployer balance covers the simulation and margin. Preserve any remainder for verification or `withdrawProceeds()`.
5. Use Circle's Base USDC address `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` and reverify it from Circle immediately before deployment.

Base's public RPC is rate-limited and documented as unsuitable for production. Use the free Alchemy Base app from Phase 3 for launch traffic; keep the public RPC only as a bounded diagnostic fallback. [Connecting to Base](https://docs.base.org/base-chain/quickstart/connecting-to-base).

### Alternative: confirmed CDP credits plus sponsored CREATE2

Use this only if the faucet route fails and credits are already visible in the CDP account.

1. Obtain a CDP smart account and Base mainnet Paymaster endpoint.
2. Apply for the Base Gasless Campaign; an application is not funding. CDP says Paymaster supports Base mainnet and credits require approval.
3. Build the complete GoldKey creation bytecode, including constructor arguments, and compute the deterministic address and salt locally.
4. Have the smart account call Base's fixed `Create2Deployer` at `0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2` using exactly `deploy(uint256 value, bytes32 salt, bytes code)` with `value = 0`. The included `scripts/build-create2-deployment.mjs` helper produces this calldata and refuses a different factory; do not substitute CreateX or the `0x4e59…` proxy.
5. Test the identical flow on Base Sepolia, then simulate mainnet sponsorship. Confirm the Paymaster accepts the factory call and creation calldata before relying on it.
6. Protect the Paymaster URL, set the smallest possible policy/spend limit, and disable the general-purpose factory immediately after a confirmed deployment. Allowlisting a deployment factory is broader than allowlisting GoldKey.

CDP bills Paymaster usage as actual gas cost plus its documented markup unless credits cover it. This route is `$0` only when the account shows sufficient awarded credits and the sponsored user operation succeeds. [CDP Paymaster](https://docs.cdp.coinbase.com/paymaster/introduction/welcome), [Paymaster billing and credits](https://docs.cdp.coinbase.com/paymaster/faqs), [Base CREATE2 preinstalls](https://docs.base.org/base-chain/specs/protocol/execution/evm/preinstalls).

## Phase 5: mainnet activation with no self-purchase

1. Deploy and verify GoldKey on Base mainnet (`8453`). Start the production API against the mainnet contract and free Neon database.
2. Verify every identity field from chain: bytecode, owner, treasury, USDC, 50-USDC price, 10,000 supply cap, terms URI/hash, and metadata URL.
3. Publish the live offer only after the Worker passes its static health check and its quote route independently verifies the full contract identity through Alchemy. A sleeping Render origin must not take discovery or quotes offline.
4. Configure the production CDP x402 facilitator and run its funded failure/settlement canary before advertising paygo. CDP currently documents the first 1,000 facilitator transactions per month at $0, then $0.001 each; onchain gas is separate. This is a facilitator-fee allowance, not free buyer funds or an uptime guarantee. [CDP facilitator pricing](https://docs.cdp.coinbase.com/x402/core-concepts/facilitator).
5. The first pass sale must come from an unrelated outside buyer using its own 50 USDC and transaction gas. The buyer approves the contract and calls `mint(recipient, 1)` directly. Do not buy from the treasury, owner, deployer, an operator-funded wallet, or a coordinated proxy.
6. Verify the buyer owns the NFT and can complete one authenticated utility call before describing it as a pass sale.
7. `withdrawProceeds()` is permissionless and can only send the contract's USDC balance to the configured treasury. The buyer may trigger it after minting, or it can wait until remaining sponsored/faucet gas is available.

No organic buyer means no revenue. Views, quotes, testnet activity, operator calls, and unpaid commitments are not sales.

## Immediately after the first 50-USDC sale

1. Withdraw the 50 USDC to the treasury and reconcile the mint, USDC transfer, NFT owner, and live quota ledger.
2. Upgrade the Render origin to Starter so idle cold starts stop. Its hostname is not part of the immutable contract because buyers use the Worker front door. Current Starter compute is $7/month. Keep Neon as the database; a Render disk is unnecessary after the Postgres port. [Render current cost guide](https://render.com/articles/how-much-does-cloud-application-hosting-cost-for-small-businesses).
3. Keep the Alchemy free RPC until measured usage approaches its published allowance, then fund a production tier or a second provider before throttling affects quotes or fulfillment.
4. Keep production x402 enabled only after CDP credentials, settlement, treasury receipt, and failure handling pass a funded canary. Do not count the canary as an outside customer; monitor the documented 1,000-transaction monthly free tier and its separate gas costs.
5. Keep Neon Free until storage, compute, latency, or transfer measurements require its usage-based Launch plan. Upgrade before hitting a free limit, not after an outage.
6. Reserve the remaining proceeds for the next Render month, RPC/facilitator overages, refund gas, database upgrade, and incident recovery before taking profit.

## Go/no-go rule

Mainnet sales remain closed unless all are true: the implemented Postgres adapter has passed live Neon contention and restart tests; the permanent `workers.dev` terms, metadata, offer, and quote routes are live; the Render origin is reachable after a cold start; exact mainnet deployment gas is funded by faucet or confirmed sponsorship; contract identity matches through the launch Alchemy RPC; an independent refund/recovery path exists; and no operator-funded purchase is needed to make the launch appear active.
