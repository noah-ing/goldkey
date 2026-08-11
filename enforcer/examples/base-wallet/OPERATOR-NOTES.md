# Guarded Base wallet adapter

This adapter is the local signing edge for the existing GoldKey EVM Guard. It
only converts one of three operator-allowlisted operations (native transfer,
ERC-20 transfer, or bounded ERC-20 approval) into an exact EIP-1559 transaction.
The injected shared enforcer must perform hosted authorization, signed commit,
the fresh local Base fee/exposure recheck, and only then invoke the local signer.

Keep this directory and the keystore under an operator-owned account. Do not
let the agent edit the config, runtime module, environment, keystore, or process
arguments. The config never contains a raw private key. An environment signer is
also supported with `execution_signer.type` set to `env` and a `key_env` name;
the value is deleted from the process environment after loading by default.
All `0x1111…`, `0x2222…`, and `0x3333…` addresses in the examples are deliberately
non-production placeholders and must be replaced before any execute-mode use.

## Shared runtime

Use one combined operator-owned JSON file with `runtime` and `base_wallet`
sections, as shown in `config.example.json`. The packaged `goldkey-wallet` and
`goldkey-wallet-mcp` commands create the shared authorizer, signed lifecycle,
local outcome store, and cumulative payment budget directly from that file.
There is no customer-written runtime module in the normal setup.

The Guard authorization payer and protected execution signer must be different
Base wallets. The packaged runtime verifies that separation after loading the
execution signer and clears the configured execution-key environment value by
default. Library integrations may still inject a custom runtime factory, but it
must preserve the same connector, signer, lifecycle, and payment-budget bounds.

`probe` is a purely local syntax/allowlist/cap check. It never loads the runtime,
RPC URL, signer, authorizer, or payer and never signs or broadcasts.

For MCP hosts, run `goldkey-wallet-mcp --config /absolute/path/goldkey.json`.
It exposes only the native-transfer, ERC-20-transfer, and bounded-approval tool
kinds actually present in operator config. Each tool accepts `probe: true` for
the same no-runtime/no-signer local check; execute calls lazily initialize and
use the identical guarded wallet path as the CLI.

## Fee limitation

The Base GasPriceOracle result is a latest-block, point-in-time L1 fee estimate,
not an absolute guarantee of the L1 data fee charged at later inclusion. The
hard operator loss boundary is therefore the segregated execution wallet: the
enforcer refuses broadcast when its native balance exceeds
`max_wallet_native_exposure_atomic`, when it cannot fund the request plus the
fresh fee estimate, or when the estimate exceeds
`max_estimated_network_fee_atomic`. Keep only the explicitly budgeted native and
token balances in this wallet. Transaction gas and fee fields, operation amounts,
destinations, tokens, and approval spenders are separately capped by config.
