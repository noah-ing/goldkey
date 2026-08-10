export class EdgeError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = "EdgeError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function assert(condition, status, code, message, details) {
  if (!condition) throw new EdgeError(status, code, message, details);
}
