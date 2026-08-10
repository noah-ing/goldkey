# GoldKey always-on edge storefront

This package puts GoldKey discovery and commerce on a Cloudflare Worker. The Worker does not need Render to answer discovery, terms, catalog, OpenAPI, or commerce requests. It reads live contract identity and supply directly from Base RPC for quotes and metadata. Only the explicit authentication, quota, delegated-key, pass-gated tool, and x402 paygo routes can contact `ORIGIN_API`.

The edge is an availability split, not an uptime claim. Utility fulfillment remains stateful and may cold-start. A healthy `/healthz` means only that the Worker is running; it deliberately does not claim that Base RPC or the origin is ready.

## Route ownership

| Route | Worker static | Base RPC | `ORIGIN_API` |
|---|---:|---:|---:|
| `GET /healthz` | yes | no | no |
| `GET /terms` | yes | no | no |
| `GET /schemas/commerce-response-v1.json` | yes | no | no |
| `GET /openapi.json` | yes | no | no |
| `GET /.well-known/agent.json` | yes | no | no |
| `GET /v1/catalog` | yes | no | no |
| `GET /v1/demo` | yes | no | no |
| `GET /.well-known/goldkey.json` | yes | live state when available | no |
| `POST /v1/purchase/quote` | yes | required | no |
| `POST /v1/commerce/respond` | yes | required | no |
| `POST /v1/renewal/quote` | yes | required | no |
| `GET /metadata/:tokenId` | yes | required | no |
| `/v1/auth/challenge`, `/v1/auth/verify` | no | origin-owned | yes |
| `GET /v1/quota` | no | origin-owned | yes |
| `/v1/keys`, `DELETE /v1/keys/:id` | no | origin-owned | yes |
| `POST /v1/tools/:tool` | no | origin-owned | yes |
| `POST /v1/paygo/execute` | no | origin-owned | yes |

Every other path is answered at the edge with `404`; it is not forwarded. Wrong methods on recognized origin paths receive `405`. Query strings, authorization, idempotency, and x402 payment headers are preserved on allowed proxy requests. Origin redirects back to its own host are rewritten to the public edge host.

## Runtime configuration

Copy `.env.example` to `.dev.vars` for local work and replace every placeholder. Do not commit `.dev.vars`.

| Binding | Required for | Meaning |
|---|---|---|
| `PUBLIC_ORIGIN` | optional | Final HTTPS origin; omitted means derive it from the request. |
| `ORIGIN_API` | stateful proxy only | HTTPS origin of the existing Node service, with no path/query/fragment. |
| `CHAIN_ID` | commerce/RPC routes | `84532` for Base Sepolia or `8453` for Base mainnet. |
| `RPC_URL` | commerce/RPC routes | HTTPS JSON-RPC endpoint that accepts standard JSON-RPC batches. A dedicated endpoint is appropriate for production. |
| `GOLDKEY_CONTRACT` | commerce/RPC routes | Nonzero deployed contract address. |
| `USDC_ADDRESS` | commerce/RPC routes | Exact deployed payment token. |
| `TREASURY_ADDRESS` | commerce/RPC routes | Exact treasury stored by the contract. |
| `TERMS_HASH` | commerce/RPC routes | Exact onchain `LICENSE_TERMS_HASH` for the bytes in `../TERMS.md`. |
| `ASSETS` | static routes | Injected by Wrangler from `public/`; do not configure manually. |

Before a live quote is returned, the Worker checks chain ID, bytecode at both addresses, terms hash, USDC, treasury, 50-USDC price, 10,000 maximum supply, 10,000 calls, 365-day term, and six token decimals. A mismatch fails closed with `503`. The discovery offer remains available during an RPC outage but marks `contract.state.status` as `unavailable`; it does not present cached supply as live.

The Worker never holds a wallet key, signs a transaction, submits a transaction, spends a buyer's funds, or treats `purchase_authority: true` as anything beyond the caller's declaration. Positive quotes may contain exact ordered unsigned approval and mint/renewal calldata for the supplied wallet.

## Local verification

From this directory:

```sh
npm install
cp .env.example .dev.vars
npm test
npm run check
npm run dev
```

`npm run check` runs unit tests and a Wrangler dry-run build; it does not deploy. The test suite proves that static storefront routes never call the origin, quotes use RPC only, only allowlisted routes reach the origin, deployment identity mismatches fail closed, and the edge copies of terms and the commerce schema are byte-identical to their canonical parent files.

The canonical artifacts are `../TERMS.md` and `../agent/goldkey-commerce-response.schema.json`. If either changes, update its copy under `public/`; the drift test will fail until the deployed assets match. Recompute and deploy the correct terms hash whenever the canonical terms change.

## Cutover without committing configuration

1. Create the Worker and install the runtime bindings in the Cloudflare dashboard or with Wrangler. `keep_vars = true` preserves dashboard-managed variables on later deploys. Treat a credential-bearing `RPC_URL` as a secret.
2. Run `npm run check` against the exact commit.
3. Deploy to the default `workers.dev` URL first, exercise every route, and confirm that unknown `/v1/*` paths do not wake Render.
4. For the zero-cash route, keep the stable `https://goldkey-edge-storefront.<account-subdomain>.workers.dev` address as `PUBLIC_ORIGIN` and use its `/metadata/` and `/terms` routes in the immutable contract constructor. Do not rename or delete that Worker after deployment.
5. A custom domain is optional after revenue. Add it only as another route to the same Worker; do not imply that it changes the immutable metadata or terms URLs already stored by the contract.
6. Re-run a live quote and compare every returned identity field with the verified contract before publishing discovery URLs.

No deployment command, account identifier, secret, or live route is included in this repository.

## Free-plan boundary

Cloudflare's current Free plan documents 100,000 Worker requests per day and 10 ms CPU per invocation; limits are account-wide and are not an availability guarantee. Static assets and Worker invocations have distinct billing details, and dynamic RPC-backed routes still depend on the configured provider. Check current limits before launch: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) and [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

The asset binding and `run_worker_first = true` configuration follow Cloudflare's current [static-assets binding documentation](https://developers.cloudflare.com/workers/static-assets/binding/). Runtime variables follow Cloudflare's [environment-variable documentation](https://developers.cloudflare.com/workers/configuration/environment-variables/).
