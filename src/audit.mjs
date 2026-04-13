/**
 * audit.mjs — Read and pretty-print openclaw-safe audit logs.
 */

import { readFileSync, existsSync } from "fs";
import {
  WATCHDOG_ALERTS_LOG,
  ENFORCER_ACTIONS_LOG,
  SIGNING_LOG,
} from "./paths.mjs";

// ── ANSI color codes ───────────────────────────────────────────────────────
const RED    = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN   = "\x1b[36m";
const WHITE  = "\x1b[37m";
const BOLD   = "\x1b[1m";
const RESET  = "\x1b[0m";

const LOG_MAP = {
  watchdog: { label: "Watchdog Alerts",   path: WATCHDOG_ALERTS_LOG },
  enforcer: { label: "Enforcer Actions",  path: ENFORCER_ACTIONS_LOG },
  signing:  { label: "Signing Events",    path: SIGNING_LOG },
};

/**
 * Return the ANSI prefix for a given severity string.
 * @param {string|undefined} severity
 * @returns {string}
 */
function severityColor(severity) {
  switch ((severity || "").toLowerCase()) {
    case "critical": return RED;
    case "high":     return YELLOW;
    case "medium":   return CYAN;
    default:         return WHITE;
  }
}

/**
 * Read a single log file, parse JSON lines, apply tail, and print with colors.
 * @param {string} label   Human-readable section header
 * @param {string} filePath  Absolute path to the .jsonl file
 * @param {number} tail    Number of trailing entries to show (0 = all)
 */
function readLog(label, filePath, tail) {
  // ── Section header ────────────────────────────────────────────
  console.log(`\n${BOLD}── ${label} ──${RESET}`);
  console.log(`   ${filePath}`);

  if (!existsSync(filePath)) {
    console.log(`   (no log file yet — nothing to show)\n`);
    return;
  }

  const raw = readFileSync(filePath, "utf-8");
  const lines = raw.split("\n").filter((l) => l.trim() !== "");

  if (lines.length === 0) {
    console.log(`   (empty log)\n`);
    return;
  }

  // ── Parse all lines ───────────────────────────────────────────
  const entries = lines.map((line) => {
    try {
      return { ok: true, data: JSON.parse(line), raw: line };
    } catch {
      return { ok: false, data: null, raw: line };
    }
  });

  // ── Apply tail ────────────────────────────────────────────────
  const visible = tail > 0 ? entries.slice(-tail) : entries;

  if (visible.length === 0) {
    console.log(`   (no entries to display)\n`);
    return;
  }

  // ── Render ────────────────────────────────────────────────────
  for (const entry of visible) {
    if (!entry.ok) {
      console.log(`${RED}[parse error]${RESET} ${entry.raw}`);
      continue;
    }

    const color  = severityColor(entry.data.severity);
    const prefix = `${color}[${(entry.data.severity || "info").toUpperCase()}]${RESET}`;
    const body   = JSON.stringify(entry.data, null, 2)
      .split("\n")
      .map((l, i) => (i === 0 ? l : "  " + l))
      .join("\n");

    console.log(`${prefix} ${body}`);
  }

  console.log();
}

/**
 * Main entry point for the audit subcommand.
 *
 * @param {{ log?: string, tail?: number, follow?: boolean }} options
 */
export async function runAudit(options = {}) {
  const logTarget = options.log   ?? "all";
  const tail      = options.tail  ?? 20;
  const follow    = options.follow ?? false;

  if (follow) {
    console.log(`${YELLOW}--follow is not yet implemented.${RESET}`);
  }

  // Resolve which logs to display
  let targets;
  if (logTarget === "all") {
    targets = Object.entries(LOG_MAP).map(([, v]) => v);
  } else {
    const entry = LOG_MAP[logTarget];
    if (!entry) {
      console.error(
        `${RED}Unknown log name: "${logTarget}". ` +
        `Valid values: watchdog, enforcer, signing, all${RESET}`
      );
      process.exit(1);
    }
    targets = [entry];
  }

  for (const { label, path } of targets) {
    readLog(label, path, tail);
  }
}
