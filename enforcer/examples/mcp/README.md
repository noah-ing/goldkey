# GoldKey exclusive MCP stdio launcher

This launcher makes GoldKey the only MCP path visible to an agent. The host
starts `goldkey-mcp-stdio`; GoldKey privately starts the fixed upstream process,
mirrors only explicitly configured tools, and forwards a `tools/call` only after
`GoldKeyEnforcer.guardMcpTool` returns an authorization and lifecycle commit.

The [example config](./goldkey-mcp.config.example.yaml) is one document with
the shared `runtime` section and this adapter's `mcp_stdio` section. The
upstream command, argument vector, working directory, environment, tool
names, effects, and input-schema hashes come from one operator-owned YAML or
JSON document. There is no shell, interpolation, ambient environment
inheritance, dynamic upstream selection, or unguarded fallback.

## Inspect before enabling

Start with `tools: []`, then run:

```sh
goldkey-mcp-stdio --inspect /absolute/path/goldkey-mcp.yaml
```

Inspection starts the same pinned upstream and sends `initialize` plus
paginated `tools/list`. The JSON report records those actions and contains each
tool name and GoldKey's canonical input-schema SHA-256. GoldKey does not
instantiate its runtime or authorizer, sign, pay, or invoke a tool. This does
not make an arbitrary upstream side-effect-free: its handling of initialization
or discovery can still have effects. Copy only the wanted tools into
`connector.tools`, assign their operator effects, and replace each placeholder
hash before normal launch.

## Normal launch

Normal launch requires the package's shared GoldKey runtime bootstrap. That
bootstrap receives the prepared connector and constructs the existing
`GoldKeyEnforcer`, `RemoteAuthorizer`, durable payment budget, outcome store,
and commit/completion lifecycle clients once. After package integration:

```sh
goldkey-mcp-stdio /absolute/path/goldkey-mcp.yaml
```

Configure the agent host with that command and config path only. Do not also
expose the original upstream server to the agent.

## Fail-closed protocol boundary

- `tools/list` is a frozen startup snapshot containing only configured tools.
- Every configured tool must exist upstream and match its pinned canonical
  `inputSchema` hash. Drift stops startup.
- `tools/call` is the only forwarded request. Resources, prompts, tasks, roots,
  sampling, elicitation, logging callbacks, and unknown methods are not proxied.
- Server-to-client callback requests receive MCP `Method not found`; unknown
  notifications are consumed locally and never cross the proxy.
- Upstream tool calls are attempted once. GoldKey's durable state controls
  replay and ambiguous outcomes; the launcher never retries internally.
- Every `tools/call` must include a durable, caller-chosen
  `_meta["com.goldkey/idempotency-key"]` value: an 8-128 character safe key.
  Missing or invalid keys are rejected before GoldKey authorization or any
  upstream invocation. Reuse the same key only to retry the same exact call,
  including after a launcher restart.

## Operator controls

The config must be a regular `.yaml`, `.yml`, or `.json` file owned by root or
the launcher user and not writable by group/other users. Run the launcher and
upstream under a dedicated OS account when the agent itself can execute local
programs; file modes cannot protect operator policy from an agent sharing the
same operating-system identity.

The upstream executable must be a regular executable, not a symlink, and must
not be writable by group/other users. The working directory must be a real
directory with the same write restriction. Secret values should normally use
`from_env`; only explicitly named values reach the upstream child.

The adapter targets the current stable official MCP TypeScript SDK v1 package
(`@modelcontextprotocol/sdk` 1.30.0). Its stdio and tools behavior follows the
official guides and the 2025-11-25 protocol specification:

- https://ts.sdk.modelcontextprotocol.io/server
- https://ts.sdk.modelcontextprotocol.io/client
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
