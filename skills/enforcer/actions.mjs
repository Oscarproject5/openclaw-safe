/**
 * Enforcement-action helpers for the openclaw-safe enforcer.
 *
 * These utilities are called by the enforcer agent to build structured records
 * of every action it takes and to health-check the watchdog heartbeat file.
 */

import { readFile } from "node:fs/promises";

// ── Enforcement record ────────────────────────────────────────────────────

/**
 * Build a structured enforcement-action record from a watchdog alert.
 *
 * The returned object is serialised as a JSONL line into
 * ~/.openclaw/audit/enforcer-actions.jsonl by the enforcer agent.
 *
 * @param {{
 *   alertId: string,
 *   ts: string,
 *   sessionId: string,
 *   patternId: string,
 *   severity: "critical"|"high"|"medium",
 *   description: string,
 *   matchSnippet?: string,
 *   sessionEntry?: unknown
 * }} alert - The alert received from the watchdog.
 *
 * @returns {{
 *   actionId: string,
 *   ts: string,
 *   alertId: string,
 *   alertTs: string,
 *   targetSession: string,
 *   patternId: string,
 *   severity: string,
 *   actionTaken: string,
 *   reason: string,
 *   humanSummary: string,
 *   matchSnippet: string | null
 * }}
 */
export function createEnforcementRecord(alert) {
  const now = new Date();
  const actionTaken = deriveAction(alert.severity);
  const reason = buildReason(alert);
  const humanSummary = buildHumanSummary(alert, actionTaken, now);

  return {
    actionId: `enforce-${now.getTime()}-${Math.random().toString(36).slice(2, 8)}`,
    ts: now.toISOString(),
    alertId: alert.alertId ?? null,
    alertTs: alert.ts ?? null,
    targetSession: alert.sessionId ?? "self-improve-session",
    patternId: alert.patternId ?? "unknown",
    severity: alert.severity ?? "unknown",
    actionTaken,
    reason,
    humanSummary,
    matchSnippet: alert.matchSnippet ?? null,
  };
}

/**
 * Map alert severity to the enforcement action string.
 *
 * @param {string} severity
 * @returns {string}
 */
function deriveAction(severity) {
  switch (severity) {
    case "critical":
      return "TERMINATE_SESSION";
    case "high":
      return "TERMINATE_SESSION";
    case "medium":
      return "WARN_AND_MONITOR";
    default:
      return "TERMINATE_SESSION"; // fail-safe: unknown severity → terminate
  }
}

/**
 * Build a short machine-readable reason string.
 *
 * @param {object} alert
 * @returns {string}
 */
function buildReason(alert) {
  return (
    `Pattern '${alert.patternId ?? "unknown"}' matched in session ` +
    `'${alert.sessionId ?? "self-improve-session"}'. ` +
    `${alert.description ?? ""}`
  ).trim();
}

/**
 * Build a human-readable summary paragraph for the incident report.
 *
 * @param {object} alert
 * @param {string} actionTaken
 * @param {Date} now
 * @returns {string}
 */
function buildHumanSummary(alert, actionTaken, now) {
  const lines = [
    `OPENCLAW-SAFE ENFORCEMENT INCIDENT`,
    `===================================`,
    `Time     : ${now.toISOString()}`,
    `Session  : ${alert.sessionId ?? "self-improve-session"}`,
    `Pattern  : ${alert.patternId ?? "unknown"}`,
    `Severity : ${alert.severity ?? "unknown"}`,
    `Action   : ${actionTaken}`,
    ``,
    `Violation description:`,
    `  ${alert.description ?? "(no description)"}`,
  ];

  if (alert.matchSnippet) {
    lines.push(``, `Matched text snippet:`, `  ${alert.matchSnippet}`);
  }

  lines.push(
    ``,
    `This incident was automatically detected by the openclaw-safe watchdog`,
    `and handled by the enforcer. Review the full audit logs at:`,
    `  ~/.openclaw/audit/watchdog-alerts.jsonl`,
    `  ~/.openclaw/audit/enforcer-actions.jsonl`
  );

  return lines.join("\n");
}

// ── Watchdog heartbeat check ──────────────────────────────────────────────

/**
 * Check whether the watchdog heartbeat file is fresh enough to indicate the
 * watchdog is alive.
 *
 * The heartbeat file is a JSON object written by the watchdog every 10 s:
 *   { "ts": "<ISO-8601 timestamp>" }
 *
 * @param {string} heartbeatPath - Absolute path to the heartbeat file
 *   (typically ~/.openclaw/audit/watchdog-heartbeat.json).
 * @param {number} maxAgeMs - Maximum acceptable heartbeat age in milliseconds.
 *   If the file is older than this the watchdog is considered dead.
 *   The enforcer uses 15 000 (15 seconds) by default.
 *
 * @returns {Promise<{ alive: boolean, lastSeen: Date | null, ageMs: number }>}
 */
export async function checkWatchdogHeartbeat(heartbeatPath, maxAgeMs) {
  let raw;
  try {
    raw = await readFile(heartbeatPath, "utf8");
  } catch {
    // File does not exist or is unreadable — watchdog has never written or is gone.
    return { alive: false, lastSeen: null, ageMs: Infinity };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Corrupt heartbeat file — treat as dead.
    return { alive: false, lastSeen: null, ageMs: Infinity };
  }

  const ts = parsed?.ts;
  if (!ts) {
    return { alive: false, lastSeen: null, ageMs: Infinity };
  }

  const lastSeen = new Date(ts);
  if (isNaN(lastSeen.getTime())) {
    return { alive: false, lastSeen: null, ageMs: Infinity };
  }

  const ageMs = Date.now() - lastSeen.getTime();
  const alive = ageMs <= maxAgeMs;

  return { alive, lastSeen, ageMs };
}
