#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const DEFAULT_ENDPOINT = "https://goldkey-api-free.onrender.com/v1/admin/pilot/applications/summary";
const KEYCHAIN_SERVICE = "com.goldkey.pilot-admin";
const stateDirectory = path.join(homedir(), ".goldkey");
const statePath = path.join(stateDirectory, "pilot-monitor.json");

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
    throw new Error(`GoldKey pilot monitor credential is unavailable in macOS Keychain service ${KEYCHAIN_SERVICE}`);
  }
}

function previousState() {
  try {
    const value = JSON.parse(readFileSync(statePath, "utf8"));
    return value && typeof value === "object" ? value : undefined;
  } catch {
    return undefined;
  }
}

function persistState(value) {
  mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
  chmodSync(stateDirectory, 0o700);
  const temporary = `${statePath}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(temporary, statePath);
  chmodSync(statePath, 0o600);
}

const token = adminToken();
if (token.length < 32 || token.length > 512 || /[\r\n]/.test(token)) throw new Error("GoldKey pilot monitor credential is malformed");

const endpoint = process.env.GOLDKEY_PILOT_ADMIN_SUMMARY_URL ?? DEFAULT_ENDPOINT;
const parsedEndpoint = new URL(endpoint);
if (parsedEndpoint.protocol !== "https:" || parsedEndpoint.username || parsedEndpoint.password) {
  throw new Error("GoldKey pilot admin summary URL must be credential-free HTTPS");
}

const response = await fetch(parsedEndpoint, {
  headers: { authorization: `Bearer ${token}`, accept: "application/json" },
  redirect: "error",
  signal: AbortSignal.timeout(20_000),
});
if (!response.ok) throw new Error(`GoldKey pilot summary request failed with HTTP ${response.status}`);
const summary = await response.json();
if (!summary || typeof summary !== "object" || !Number.isSafeInteger(summary.total_active) || summary.total_active < 0) {
  throw new Error("GoldKey pilot summary response is malformed");
}

const previous = previousState();
const current = {
  total: summary.total_active,
  newest_application_id: summary.newest?.application_id ?? null,
  checked_at: new Date().toISOString(),
};
const changed = Boolean(previous)
  && (current.total > (previous.total ?? 0)
    || (current.newest_application_id && current.newest_application_id !== previous.newest_application_id));
persistState(current);

console.log(JSON.stringify({
  ok: true,
  changed,
  new_applications: previous ? Math.max(0, current.total - (previous.total ?? 0)) : 0,
  total: current.total,
  counts_by_status: summary.counts_by_status,
  newest: summary.newest ?? null,
  baseline_initialized: !previous,
}));
