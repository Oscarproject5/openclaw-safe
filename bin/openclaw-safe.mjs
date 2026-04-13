#!/usr/bin/env node
/**
 * bin/openclaw-safe.mjs — CLI dispatcher for the openclaw-safe harness.
 */

import { checkNodeVersion } from "../src/node-check.mjs";

// Gate on Node version before anything else runs.
checkNodeVersion();

// ── Argument parsing ───────────────────────────────────────────────────────
const [, , subcommand, ...rest] = process.argv;

/**
 * Parse audit-specific flags from the remaining argv tokens.
 * Supported: --log <name>, --tail <N>, --follow
 */
function parseAuditOptions(args) {
  const opts = { log: "all", tail: 20, follow: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--log" && args[i + 1]) {
      opts.log = args[++i];
    } else if (arg === "--tail" && args[i + 1]) {
      const n = parseInt(args[++i], 10);
      if (!isNaN(n) && n >= 0) opts.tail = n;
    } else if (arg === "--follow") {
      opts.follow = true;
    }
  }
  return opts;
}

function printUsage() {
  console.log(`
openclaw-safe — Safe self-improvement harness for OpenClaw

Commands:
  setup              Install OpenClaw, create directories, generate keys, configure
  start              Verify signatures and launch watchdog → enforcer → SIA
  sign <skill>       Review and cryptographically sign a workspace skill
  audit [options]    Read audit logs

Audit options:
  --log <name>       Log to read: watchdog, enforcer, signing, all (default: all)
  --tail <N>         Show last N entries (default: 20)
  --follow           Watch for new entries (not yet implemented)

Examples:
  openclaw-safe setup
  openclaw-safe start
  openclaw-safe sign my-new-skill
  openclaw-safe audit --log watchdog --tail 50
`);
}

// ── Dispatch ───────────────────────────────────────────────────────────────
async function main() {
  switch (subcommand) {
    case "setup": {
      const { runSetup } = await import("../src/setup.mjs");
      await runSetup();
      break;
    }

    case "start": {
      const { runStart } = await import("../src/start.mjs");
      await runStart();
      break;
    }

    case "sign": {
      const skillName = rest[0];
      if (!skillName) {
        console.error("Usage: openclaw-safe sign <skillName>");
        process.exit(1);
      }
      const { runSign } = await import("../src/sign.mjs");
      await runSign(skillName, {});
      break;
    }

    case "audit": {
      const { runAudit } = await import("../src/audit.mjs");
      await runAudit(parseAuditOptions(rest));
      break;
    }

    case undefined:
    case "help":
    case "--help":
    case "-h": {
      printUsage();
      break;
    }

    default: {
      console.error(`Unknown subcommand: "${subcommand}"`);
      printUsage();
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error("\nFatal error:", err instanceof Error ? err.message : err);
  if (err instanceof Error && err.stack) {
    console.error(err.stack);
  }
  process.exit(1);
});
