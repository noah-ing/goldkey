#!/usr/bin/env node

import { execFileSync } from "node:child_process";

const ORIGIN = "https://goldkey-api-free.onrender.com";
const KEYCHAIN_SERVICE = "com.goldkey.pilot-admin";
const STATUSES = new Set(["received", "reviewing", "accepted", "declined", "closed"]);

function usage() {
  return [
    "GoldKey private pilot review",
    "",
    "Usage:",
    "  node scripts/review-pilot-applications.mjs list [status] [limit]",
    "  node scripts/review-pilot-applications.mjs review <application_id> <status>",
    "",
    "Statuses: received, reviewing, accepted, declined, closed",
    "",
    "Applicant details are written only to this command's standard output. The admin token",
    `is read from macOS Keychain service ${KEYCHAIN_SERVICE} and is never printed.`,
  ].join("\n");
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

function adminToken() {
  const configured = process.env.GOLDKEY_PILOT_ADMIN_TOKEN?.trim();
  if (configured) return configured;
  if (process.platform !== "darwin") throw new Error("GOLDKEY_PILOT_ADMIN_TOKEN is required outside macOS");
  try {
    return execFileSync("security", [
      "find-generic-password",
      "-a",
      process.env.USER ?? "",
      "-s",
      KEYCHAIN_SERVICE,
      "-w",
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    throw new Error(`Pilot admin credential is unavailable in macOS Keychain service ${KEYCHAIN_SERVICE}`);
  }
}

async function request(pathname, { method = "GET", body } = {}) {
  const token = adminToken();
  if (token.length < 32 || token.length > 512 || /[\r\n]/u.test(token)) {
    throw new Error("Pilot admin credential is malformed");
  }
  const url = new URL(pathname, ORIGIN);
  if (url.origin !== ORIGIN || url.protocol !== "https:" || url.username || url.password) {
    throw new Error("Pilot admin request target is invalid");
  }
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
  });
  const payload = await response.json().catch(() => undefined);
  if (!response.ok) {
    const code = payload?.error?.code;
    throw new Error(`Pilot admin request failed with HTTP ${response.status}${code ? ` (${code})` : ""}`);
  }
  return payload;
}

const [command, ...args] = process.argv.slice(2);
if (!command || command === "help" || command === "--help" || command === "-h") {
  process.stdout.write(`${usage()}\n`);
} else if (command === "list") {
  const [status, rawLimit = "20"] = args;
  if (status !== undefined && !STATUSES.has(status)) {
    fail(`Unknown status: ${status}\n\n${usage()}`);
  } else if (!/^(?:[1-9]|[1-9]\d|100)$/u.test(rawLimit)) {
    fail(`Limit must be 1-100\n\n${usage()}`);
  } else {
    try {
      const url = new URL("/v1/admin/pilot/applications", ORIGIN);
      url.searchParams.set("limit", rawLimit);
      if (status) url.searchParams.set("status", status);
      const result = await request(`${url.pathname}${url.search}`);
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } catch (error) {
      fail(error instanceof Error ? error.message : "Pilot admin request failed");
    }
  }
} else if (command === "review") {
  const [applicationId, status] = args;
  if (!/^pil_[0-9a-f-]{36}$/u.test(applicationId ?? "") || !STATUSES.has(status)) {
    fail(`Review requires a valid application ID and status\n\n${usage()}`);
  } else {
    try {
      const result = await request(`/v1/admin/pilot/applications/${encodeURIComponent(applicationId)}`, {
        method: "PATCH",
        body: { status },
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } catch (error) {
      fail(error instanceof Error ? error.message : "Pilot admin request failed");
    }
  }
} else {
  fail(`Unknown command: ${command}\n\n${usage()}`);
}
