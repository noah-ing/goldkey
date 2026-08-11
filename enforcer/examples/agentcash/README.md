# AgentCash through GoldKey Guard

This adapter gives an operator a narrow, config-driven route from a GoldKey MCP proxy to AgentCash's official local MCP server. Each exposed tool has one fixed HTTPS URL, HTTP method, x402 network, headers, and USD ceiling. The proposed JSON body is included in the canonical GoldKey call; the agent cannot supply a URL, method, header, network, protocol, or spend cap.

This is an honest wrapper, not transparent interception. AgentCash 0.17.1 documents a local `fetch` CLI/MCP tool but no supported custom transport, outbound proxy hook, or authorization callback. The adapter therefore starts the pinned local AgentCash MCP server only after GoldKey returns ALLOW and commits the execution. Do not leave AgentCash's direct `fetch` MCP server available to the same agent, or the agent can bypass GoldKey.

Official AgentCash references used for this integration:

- [CLI overview](https://agentcash.dev/docs/cli/overview)
- [`fetch` CLI](https://agentcash.dev/docs/cli/fetch)
- [MCP mode](https://agentcash.dev/docs/mcp-mode)
- [`fetch` MCP tool](https://agentcash.dev/docs/tools/fetch)
- [How payments work](https://agentcash.dev/docs/how-it-works)
- [Local wallet model](https://agentcash.dev/docs/wallet/overview)
- [Published `agentcash` package](https://www.npmjs.com/package/agentcash/v/0.17.1)

## What is paid

There are two distinct purchases, not two payments for the same service:

1. GoldKey Guard authorization: the shared runtime's existing `RemoteAuthorizer` pays the live Guard network price and reserves it in `SqlitePaymentBudgetStore` before authorization. This adapter never uses AgentCash to pay GoldKey.
2. The upstream API purchase: after ALLOW plus a fresh Guard commit, AgentCash may pay the external x402 endpoint. `max_amount_usd` is passed as AgentCash's per-call `maxAmount` and cannot be increased by the agent.

The Guard budget is durable and aggregate. AgentCash exposes a per-fetch cap, not an operator-verifiable durable aggregate budget hook. Keep the AgentCash wallet segregated and fund it only to the exposure you accept.

## Exact setup

1. Install one immutable AgentCash version in the operator runtime. Do not use an unpinned `npx agentcash@latest` command in production. Configure both the real Node.js executable and the package's real CLI entry file (`node_modules/agentcash/dist/esm/index.js`), not the mutable `.bin` symlink. GoldKey starts the pinned Node executable with the AgentCash entry file as its first argument, so it never uses a shebang or inherited `PATH` to select an interpreter. Startup rejects symlink commands, non-executable files, and group/other-writable execution surfaces.

   ```sh
   npm install --save-exact agentcash@0.17.1
   ```

2. As the dedicated adapter OS account, initialize AgentCash before GoldKey starts, list the wallet addresses, and fund only the network needed by configured operations.

   ```sh
   /opt/goldkey/node_modules/.bin/agentcash accounts
   chmod 600 "$HOME/.agentcash/wallet.json" "$HOME/.agentcash/solana-wallet.json"
   ```

   AgentCash currently loads both wallet files at MCP startup, even for a Base-only operation. Startup fails closed if either file is missing, is a symlink, is owned by another user, or is accessible to group/other users. GoldKey checks metadata only; it never reads or returns either private key.

   Instead of wallet files, set `credential_mode` to `environment` and provide both `X402_PRIVATE_KEY` and `X402_SOLANA_PRIVATE_KEY` to the operator process. GoldKey forwards only `HOME`, those two AgentCash keys, and non-secret process-mode flags. It deliberately omits `PATH`. Guard payer keys, database URLs, and unrelated service secrets are not inherited by AgentCash.

3. Copy [`goldkey.combined.example.json`](./goldkey.combined.example.json) to an operator-owned location with mode 0600. It intentionally contains both `runtime` and `agentcash`; each loader selects its own section. Replace the example policy digest, paths, and operation. Run the proxy as a separate OS account from the untrusted agent, and do not give the agent write access to this file, its directory, the AgentCash executable, wallet files, policy, or Guard state.

   `guard_origin` is not a redirect or deployment option: production normalization requires the same live GoldKey origin used by the shared runtime. A substituted origin fails before AgentCash startup, so the recursive/double-payment exclusion cannot be weakened in config.

4. Generate the onboarding artifact before signing the policy:

   ```sh
   node enforcer/bin/goldkey-agentcash.mjs \
     --inspect /etc/goldkey/goldkey.json \
     enforcer/examples/agentcash/inspect-request.example.json
   ```

   Inspection is strictly local and zero-payment. It does not resolve DNS, start AgentCash, invoke `fetch`, contact GoldKey, sign, authorize, or pay. It prints:

   - the canonical Guard call and SHA-256;
   - the policy destination/effect and input-schema hash;
   - the exact AgentCash executable plus `server --quiet` argv;
   - the exact MCP initialize/initialized/tools-call JSON lines that would go over stdin.

   The exposed input schema includes `x-goldkey-agentcash-binding` with the fixed upstream URL, method, headers, network, protocol, and cap. Its SHA-256 therefore changes if any execution binding changes. Put that hash, connector ID, tool name, `payment` effect, and `mcp://agentcash-local/<tool>` destination into the operator-signed GoldKey policy.

5. Point the agent's MCP host at GoldKey, not AgentCash. After the shared-runtime release integration described below, the operator configuration is only command plus config path; no customer connector code is required. [`mcp-host.example.json`](./mcp-host.example.json) is the complete shape:

   ```json
   {
     "mcpServers": {
       "goldkey-agentcash": {
         "command": "/usr/bin/node",
         "args": [
           "/opt/goldkey/enforcer/bin/goldkey-agentcash.mjs",
           "/etc/goldkey/goldkey.json"
         ]
       }
     }
   }
   ```

   Supply `GOLDKEY_GUARD_PAYER_PRIVATE_KEY` to the protected GoldKey process through the operator's secret manager or service supervisor, not in agent-visible MCP config. The process lists only operator-configured tools such as `people_enrich`; it never exposes AgentCash's raw `fetch`, wallet, settings, discovery, bridge, or reporting tools.

6. The normal server accepts standard MCP `tools/list` and `tools/call`. A call is equivalent to the following protected invocation, but the MCP host performs it automatically:

   ```js
   await invokeAgentCash({
     operation: "people_enrich",
     arguments: { body: { profile: "https://www.linkedin.com/in/example" } },
     idempotencyKey: "one-stable-unique-key-from-the-caller",
   });
   ```

   Every purchase must include a caller-stable MCP `_meta["com.goldkey/idempotency-key"]` containing 8-128 safe characters. Missing or malformed metadata fails before Guard and before AgentCash. Keep the same key across client reconnects, process restarts, and reconciliation; use a new key only for a second intentional purchase. Reuse is rejected.

   Once the AgentCash `tools/call` message is sent, any timeout, process exit, malformed result, payment mismatch, or missing completion is an ambiguous outcome. The adapter sends one `tools/call` and never retries. Reconcile the wallet/upstream manually before using any new explicit key.

## Network boundary and exact limitations

- Config and every invocation reject local/special hostnames or any DNS answer containing a private, reserved, metadata, or invalid address. The hostname is checked before Guard and again immediately before AgentCash starts.
- AgentCash owns the actual HTTP socket. Its documented MCP/CLI surface does not expose a pinned DNS address, redirect callback, or custom dispatcher. GoldKey therefore **does not claim DNS-rebinding-safe or redirect-safe enforcement for AgentCash traffic**. Use only an operator-vetted stable hostname that does not redirect.
- Production deployment requires an independent OS/container egress boundary around the adapter process: deny loopback, RFC1918, link-local, metadata, and other special ranges; allow TCP 443 only to the operator-approved upstream address set; and deny redirect destinations outside that set. Keep this boundary separate from agent permissions. Without it, do not use the AgentCash adapter for a hostile or arbitrary destination. It is not equivalent to GoldKey's native socket-pinned HTTPS connector.
- Only fixed JSON-object body operations are supported. URLs cannot contain query strings, and the only configurable request header is exactly `accept: application/json`; `content-type: application/json` is added internally. Dynamic URLs/query parameters, credential headers, cookies, arbitrary raw bodies, streaming, MPP, and agent-selected networks/caps are deliberately unsupported.
- Target bodies travel over local MCP stdin, not process argv. AgentCash/payment credentials remain in its local wallet files or narrowly forwarded credential variables. Neither appears in config, inspection output, receipts, command arguments, or errors.
- AgentCash's success metadata can omit a settlement transaction even after returning an HTTP response. The adapter reports `settlement: null` rather than fabricating proof. A reported unsuccessful settlement is rejected.
- The adapter does not claim AgentCash, GoldKey, or the upstream API has generated revenue, demand, audit approval, or a security guarantee beyond the checks described here.

## Shared-runtime handoff

These example files intentionally do not modify package exports or the common launcher. To make the documented import and executable available in a release, the shared integration must:

1. export `./adapters/agentcash` from `enforcer/package.json` (backed by `src/adapters/agentcash-mcp.mjs`);
2. include `bin/` and `examples/agentcash/` in the package files;
3. register `goldkey-agentcash` as the `bin/goldkey-agentcash.mjs` executable;
4. inject a `runtimeFactory` into `runAgentCashCli`; the factory receives `{ configFilename, document, agentCashConfig, connector }`, builds the one shared runtime, and returns either `{ enforcer }` or the enforcer itself;
5. preserve the existing `RemoteAuthorizer` plus `SqlitePaymentBudgetStore` bootstrap; do not create a second authorizer or payment budget in this adapter.

The exported `runAgentCashCli` contract is intentionally fail closed: normal mode refuses to start without that injected `runtimeFactory`. `--inspect` never accepts or constructs a runtime. Once the central release entry point supplies the factory, operators use only `goldkey-agentcash /etc/goldkey/goldkey.json` as shown above.
