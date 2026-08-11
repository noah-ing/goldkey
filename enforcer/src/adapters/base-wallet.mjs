import { deepFreeze } from "../canonical.mjs";
import { InvalidInputError } from "../errors.mjs";
import { buildBaseWalletCall, probeBaseWalletRequest } from "./base-wallet-request.mjs";

/**
 * Thin, runtime-agnostic wallet boundary. The injected enforcer owns the
 * authorize/commit lifecycle; this adapter only accepts the three high-level
 * wallet operations and hands it one exact, frozen EVM transaction.
 */
export class GuardedBaseWallet {
  #config;
  #enforcer;

  constructor({ config, enforcer } = {}) {
    if (!config || typeof config !== "object" || !Array.isArray(config.connectors)) {
      throw new InvalidInputError("A normalized operator-owned Base wallet config is required");
    }
    if (!enforcer || typeof enforcer.guardEvmTransaction !== "function") {
      throw new InvalidInputError("An injected configured GoldKey enforcer is required");
    }
    this.#config = config;
    this.#enforcer = enforcer;
  }

  probe(request) {
    return probeBaseWalletRequest({ config: this.#config, request });
  }

  async execute(request) {
    const call = buildBaseWalletCall({ config: this.#config, request });
    return this.#enforcer.guardEvmTransaction(Object.freeze({
      connectorId: call.connectorId,
      transaction: deepFreeze(call.transaction),
      idempotencyKey: call.idempotencyKey,
    }));
  }
}

Object.freeze(GuardedBaseWallet.prototype);

export function createGuardedBaseWallet(options) {
  return Object.freeze(new GuardedBaseWallet(options));
}
