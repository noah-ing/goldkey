import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { isIP } from "node:net";
import { ServiceError } from "./errors.mjs";

const PUBLIC_FIELDS = new Set([
  "name",
  "email",
  "company",
  "agent_stack",
  "connector",
  "action",
  "timeline",
  "budget_confirmed",
  "website",
]);
const REVIEW_FIELDS = new Set(["status", "admin_note"]);
const STATUSES = new Set(["received", "reviewing", "accepted", "declined", "closed"]);
const DAY_MS = 86_400_000;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function hmac(secret, context, value) {
  return createHmac("sha256", secret).update(`${context}\0${value}`).digest("hex");
}

function exactObject(value, allowed, code, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ServiceError(400, code, `${label} must be an object`);
  }
  const extras = Object.keys(value).filter((key) => !allowed.has(key));
  if (extras.length > 0) {
    throw new ServiceError(400, code, `${label} contains unsupported fields`);
  }
  return value;
}

function text(value, field, { minimum = 1, maximum, multiline = false } = {}) {
  if (typeof value !== "string") {
    throw new ServiceError(400, "invalid_pilot_application", `${field} must be text`);
  }
  let normalized = value.normalize("NFC").trim();
  if (multiline) {
    normalized = normalized.replace(/\r\n?/g, "\n");
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(normalized)) {
      throw new ServiceError(400, "invalid_pilot_application", `${field} contains unsupported control characters`);
    }
  } else {
    if (/[\u0000-\u001f\u007f]/u.test(normalized)) {
      throw new ServiceError(400, "invalid_pilot_application", `${field} must be one line`);
    }
    normalized = normalized.replace(/\s+/gu, " ");
  }
  if (normalized.length < minimum || normalized.length > maximum) {
    throw new ServiceError(400, "invalid_pilot_application", `${field} must contain ${minimum}-${maximum} characters`);
  }
  return normalized;
}

function optionalText(value, field, options) {
  if (value === undefined || value === "") return null;
  return text(value, field, options);
}

function emailAddress(value) {
  const normalized = text(value, "email", { minimum: 3, maximum: 254 }).toLowerCase();
  const parts = normalized.split("@");
  if (
    parts.length !== 2
    || parts[0].length > 64
    || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u.test(parts[0])
    || parts[0].startsWith(".")
    || parts[0].endsWith(".")
    || parts[0].includes("..")
    || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/u.test(parts[1])
  ) {
    throw new ServiceError(400, "invalid_pilot_application", "email must be a valid address");
  }
  return normalized;
}

function idempotency(value) {
  if (typeof value !== "string" || value.length < 16 || value.length > 128 || !/^[\x21-\x7e]+$/u.test(value)) {
    throw new ServiceError(400, "invalid_pilot_idempotency_key", "Idempotency-Key must contain 16-128 visible ASCII characters");
  }
  return value;
}

function pageLimit(value) {
  const normalized = typeof value === "string" && /^(?:[1-9]|[1-9]\d|100)$/u.test(value)
    ? Number(value)
    : value;
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > 100) {
    throw new ServiceError(400, "invalid_pilot_application_query", "limit must be an integer from 1 to 100");
  }
  return normalized;
}

function normalizePublicBody(body) {
  exactObject(body, PUBLIC_FIELDS, "invalid_pilot_application", "Pilot application");
  if (body.budget_confirmed !== true) {
    throw new ServiceError(400, "pilot_budget_not_confirmed", "The $1,000 implementation pilot budget must be confirmed");
  }
  return {
    name: text(body.name, "name", { minimum: 2, maximum: 100 }),
    email: emailAddress(body.email),
    company: optionalText(body.company, "company", { minimum: 1, maximum: 160 }),
    agent_stack: text(body.agent_stack, "agent_stack", { minimum: 2, maximum: 500 }),
    connector: text(body.connector, "connector", { minimum: 2, maximum: 240 }),
    action: text(body.action, "action", { minimum: 10, maximum: 2_000, multiline: true }),
    timeline: optionalText(body.timeline, "timeline", { minimum: 1, maximum: 240 }),
    budget_confirmed: true,
  };
}

function canonicalApplication(normalized) {
  return JSON.stringify({
    name: normalized.name,
    email: normalized.email,
    company: normalized.company,
    agent_stack: normalized.agent_stack,
    connector: normalized.connector,
    action: normalized.action,
    timeline: normalized.timeline,
    budget_confirmed: true,
  });
}

function adminApplication(row) {
  return {
    application_id: row.id,
    name: row.name,
    email: row.email,
    company: row.company,
    agent_stack: row.agent_stack,
    connector: row.connector,
    action: row.action_text,
    timeline: row.timeline,
    budget_confirmed: Boolean(row.budget_confirmed),
    status: row.status,
    admin_note: row.admin_note,
    created_at: new Date(row.created_at).toISOString(),
    updated_at: new Date(row.updated_at).toISOString(),
    reviewed_at: row.reviewed_at === null ? null : new Date(row.reviewed_at).toISOString(),
    retention_expires_at: new Date(row.retention_expires_at).toISOString(),
  };
}

function encodeCursor(row) {
  return Buffer.from(JSON.stringify({ createdAt: row.created_at, id: row.id }), "utf8").toString("base64url");
}

function decodeCursor(value) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || value.length > 256 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new ServiceError(400, "invalid_pilot_application_cursor", "Invalid pilot application cursor");
  }
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (
      !parsed || typeof parsed !== "object" || Array.isArray(parsed)
      || Object.keys(parsed).length !== 2
      || !Object.hasOwn(parsed, "createdAt") || !Object.hasOwn(parsed, "id")
      || !Number.isSafeInteger(parsed.createdAt) || parsed.createdAt < 0
      || typeof parsed.id !== "string" || !/^pil_[0-9a-f-]{36}$/u.test(parsed.id)
    ) throw new Error("invalid cursor");
    return parsed;
  } catch {
    throw new ServiceError(400, "invalid_pilot_application_cursor", "Invalid pilot application cursor");
  }
}

function requireNow(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ServiceError(400, "invalid_pilot_application", "now must be a millisecond timestamp");
  }
  return value;
}

export function createPilotApplicationsService({
  database,
  adminTokenSha256,
  abuseSecret,
  retentionDays = 90,
  sourceHourlyLimit = 3,
  sourceDailyLimit = 10,
  contactDailyLimit = 3,
} = {}) {
  if (!database || typeof database.createPilotApplication !== "function") {
    throw new Error("Pilot applications require a database adapter");
  }
  if (typeof adminTokenSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(adminTokenSha256)) {
    throw new Error("PILOT_ADMIN_TOKEN_SHA256 must be a lowercase SHA-256 hex digest");
  }
  if (typeof abuseSecret !== "string" || Buffer.byteLength(abuseSecret, "utf8") < 32) {
    throw new Error("PILOT_ABUSE_SECRET must contain at least 32 bytes of secret material");
  }
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 365) {
    throw new Error("Pilot application retentionDays must be an integer from 1 to 365");
  }
  for (const [value, label, maximum] of [
    [sourceHourlyLimit, "sourceHourlyLimit", 100],
    [sourceDailyLimit, "sourceDailyLimit", 1_000],
    [contactDailyLimit, "contactDailyLimit", 100],
  ]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
      throw new Error(`Pilot application ${label} is invalid`);
    }
  }
  const secret = Buffer.from(abuseSecret, "utf8");
  const expectedAdminHash = Buffer.from(adminTokenSha256, "hex");

  function authorize(authorization) {
    if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) {
      throw new ServiceError(401, "pilot_admin_unauthorized", "Unauthorized");
    }
    const token = authorization.slice(7);
    if (token.length < 32 || token.length > 512 || /\s/u.test(token)) {
      throw new ServiceError(401, "pilot_admin_unauthorized", "Unauthorized");
    }
    const actualHash = Buffer.from(sha256(token), "hex");
    if (!timingSafeEqual(actualHash, expectedAdminHash)) {
      throw new ServiceError(401, "pilot_admin_unauthorized", "Unauthorized");
    }
  }

  return {
    async submit({ body, idempotencyKey, clientAddress, now = Date.now() } = {}) {
      const submittedAt = requireNow(now);
      const key = idempotency(idempotencyKey);
      exactObject(body, PUBLIC_FIELDS, "invalid_pilot_application", "Pilot application");
      if (body.website !== undefined && (typeof body.website !== "string" || body.website.length > 500)) {
        throw new ServiceError(400, "invalid_pilot_application", "website must be text");
      }
      if (typeof body.website === "string" && body.website.trim().length > 0) {
        return {
          ok: true,
          application_id: `pil_${hmac(secret, "honeypot", key).slice(0, 8)}-${hmac(secret, "honeypot", key).slice(8, 12)}-${hmac(secret, "honeypot", key).slice(12, 16)}-${hmac(secret, "honeypot", key).slice(16, 20)}-${hmac(secret, "honeypot", key).slice(20, 32)}`,
          status: "received",
          idempotent_replay: false,
        };
      }
      if (typeof clientAddress !== "string" || isIP(clientAddress.trim()) === 0) {
        throw new ServiceError(400, "invalid_pilot_source", "A valid client network address is required");
      }
      const normalized = normalizePublicBody(body);
      const canonical = canonicalApplication(normalized);
      const result = await database.createPilotApplication({
        id: `pil_${randomUUID()}`,
        idempotencyHash: hmac(secret, "idempotency", key),
        requestHash: hmac(secret, "request", canonical),
        sourceFingerprint: hmac(secret, "source", clientAddress.trim().toLowerCase()),
        contactFingerprint: hmac(secret, "contact", normalized.email),
        name: normalized.name,
        email: normalized.email,
        company: normalized.company,
        agentStack: normalized.agent_stack,
        connector: normalized.connector,
        action: normalized.action,
        timeline: normalized.timeline,
        budgetConfirmed: true,
        createdAt: submittedAt,
        retentionExpiresAt: submittedAt + (retentionDays * DAY_MS),
        limits: { sourceHourlyLimit, sourceDailyLimit, contactDailyLimit },
      });
      return {
        ok: true,
        application_id: result.application.id,
        status: result.application.status,
        idempotent_replay: result.replay,
      };
    },

    async list({ authorization, status, limit = 50, cursor, now = Date.now() } = {}) {
      authorize(authorization);
      const listedAt = requireNow(now);
      if (status !== undefined && !STATUSES.has(status)) {
        throw new ServiceError(400, "invalid_pilot_application_query", "Unknown pilot application status");
      }
      const normalizedLimit = pageLimit(limit);
      const result = await database.listPilotApplications({
        status,
        limit: normalizedLimit,
        cursor: decodeCursor(cursor),
        now: listedAt,
      });
      const last = result.applications.at(-1);
      return {
        applications: result.applications.map(adminApplication),
        next_cursor: result.hasMore && last ? encodeCursor(last) : null,
      };
    },

    async review({ authorization, applicationId, body, now = Date.now() } = {}) {
      authorize(authorization);
      const reviewedAt = requireNow(now);
      if (typeof applicationId !== "string" || !/^pil_[0-9a-f-]{36}$/u.test(applicationId)) {
        throw new ServiceError(400, "invalid_pilot_application_review", "Invalid pilot application ID");
      }
      exactObject(body, REVIEW_FIELDS, "invalid_pilot_application_review", "Pilot application review");
      if (!STATUSES.has(body.status)) {
        throw new ServiceError(400, "invalid_pilot_application_review", "Unknown pilot application status");
      }
      const noteProvided = Object.hasOwn(body, "admin_note");
      let adminNote;
      if (noteProvided) {
        adminNote = body.admin_note === null || body.admin_note === ""
          ? null
          : text(body.admin_note, "admin_note", { minimum: 1, maximum: 2_000, multiline: true });
      }
      const application = await database.reviewPilotApplication({
        applicationId,
        status: body.status,
        adminNote,
        adminNoteProvided: noteProvided,
        reviewedAt,
      });
      return { application: adminApplication(application) };
    },

    async summary({ authorization, now = Date.now() } = {}) {
      authorize(authorization);
      const result = await database.pilotApplicationSummary({ now: requireNow(now) });
      return {
        total_active: result.totalActive,
        counts_by_status: result.countsByStatus,
        newest: result.newest
          ? {
              application_id: result.newest.application_id,
              submitted_at: new Date(result.newest.created_at).toISOString(),
            }
          : null,
      };
    },
  };
}
