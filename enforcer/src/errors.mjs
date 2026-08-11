export class GoldKeyEnforcerError extends Error {
  constructor(code, message, { cause, details } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = new.target.name;
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export class InvalidInputError extends GoldKeyEnforcerError {
  constructor(message, details) {
    super("invalid_input", message, { details });
  }
}

export class AuthorizationServiceError extends GoldKeyEnforcerError {
  constructor(message, options = {}) {
    super("authorization_service_error", message, options);
  }
}

export class PaymentPolicyError extends GoldKeyEnforcerError {
  constructor(message, details) {
    super("payment_policy_denied", message, { details });
  }
}

export class AuthorizationDeniedError extends GoldKeyEnforcerError {
  constructor(message = "GoldKey policy did not authorize this call", details) {
    super("authorization_denied", message, { details });
  }
}

export class ReceiptVerificationError extends GoldKeyEnforcerError {
  constructor(message, details) {
    super("invalid_authorization_receipt", message, { details });
  }
}

export class IdempotencyConflictError extends GoldKeyEnforcerError {
  constructor(message = "Idempotency key was already bound to a different call", details) {
    super("idempotency_conflict", message, { details });
  }
}

export class ReplayDetectedError extends GoldKeyEnforcerError {
  constructor(message = "This idempotency key has already been used; the call will not be forwarded again", details) {
    super("replay_detected", message, { details });
  }
}

export class AmbiguousOutcomeError extends GoldKeyEnforcerError {
  constructor(message = "The prior forwarding outcome is ambiguous and must be reconciled before any retry", options = {}) {
    super("ambiguous_outcome", message, options);
  }
}

export class NetworkPolicyError extends GoldKeyEnforcerError {
  constructor(message, details) {
    super("network_policy_denied", message, { details });
  }
}

export class ResponseLimitError extends GoldKeyEnforcerError {
  constructor(message, details) {
    super("response_too_large", message, { details });
  }
}

export class DeadlineExceededError extends GoldKeyEnforcerError {
  constructor(message = "GoldKey enforcement deadline exceeded", options = {}) {
    super("deadline_exceeded", message, options);
  }
}

export class LocalStateError extends GoldKeyEnforcerError {
  constructor(message, options = {}) {
    super("local_state_error", message, options);
  }
}
