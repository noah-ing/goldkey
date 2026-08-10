export class ServiceError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.name = "ServiceError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function assert(condition, status, code, message, details) {
  if (!condition) throw new ServiceError(status, code, message, details);
}
