/**
 * Session launcher command for openclaw-safe.
 *
 * Runs pre-flight checks and starts the three-agent topology:
 * watchdog → enforcer → SIA (self-improvement agent).
 */

import fs from "fs";
import { join } from "path";
import { execFileSync, execSync, spawn, spawnSync } from "child_process";

import {
  PUBLISHED_SKILLS_DIR,
  OPENCLAW_CONFIG_PATH,
  PUBLIC_KEY_PATH,
  PRIVATE_KEY_PATH,
  WATCHDOG_AGENT_ID,
  ENFORCER_AGENT_ID,
  SIA_AGENT_ID,
} from "./paths.mjs";

import {
  readSignedManifest,
  verifySkillSignature,
} from "../signing/verify.mjs";

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** Resolve after `ms` milliseconds. */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resolve the full path to the `openclaw` binary so we can spawn without
 * shell: true (avoids Node.js DEP0190 deprecation warning).
 *
 * @returns {string} Absolute path to the openclaw executable.
 */
function resolveOpenclawPath() {
  const whichCmd = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(whichCmd, ["openclaw"]);
  if (result.status !== 0) {
    console.error("Error: openclaw not found on PATH.");
    process.exit(1);
  }
  // `where` on Windows may return multiple lines; take the first.
  return result.stdout.toString().trim().split(/\r?\n/)[0];
}

/** Cached openclaw binary path. */
let _openclawBin;
function getOpenclawBin() {
  if (!_openclawBin) _openclawBin = resolveOpenclawPath();
  return _openclawBin;
}

/**
 * Spawn an openclaw agent command detached so the parent process can exit
 * without waiting for the long-running agent session.
 *
 * Attaches a one-shot error handler (before unref) so that OS-level launch
 * failures (e.g. binary not found) are printed rather than silently swallowed.
 *
 * @param {string} label  Human-readable name used in error messages.
 * @param {string[]} args  Arguments passed after `openclaw`.
 */
function spawnDetached(label, args) {
  const child = spawn(getOpenclawBin(), args, {
    detached: true,
    stdio: "ignore",
  });

  child.once("error", (err) => {
    console.error(`Error: Failed to launch ${label}: ${err.message}`);
  });

  child.unref();
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Run pre-flight checks and launch the three-agent session topology.
 */
export async function runStart() {
  // ── 1. Pre-flight checks ──────────────────────────────────────────────────

  // Signing keys
  if (!fs.existsSync(PRIVATE_KEY_PATH)) {
    console.error(
      `Error: Private signing key not found at ${PRIVATE_KEY_PATH}\n` +
        `Run "openclaw-safe keygen" to generate signing keys.`
    );
    process.exit(1);
  }
  if (!fs.existsSync(PUBLIC_KEY_PATH)) {
    console.error(
      `Error: Public signing key not found at ${PUBLIC_KEY_PATH}\n` +
        `Run "openclaw-safe keygen" to generate signing keys.`
    );
    process.exit(1);
  }

  // OpenClaw config
  if (!fs.existsSync(OPENCLAW_CONFIG_PATH)) {
    console.error(
      `Error: OpenClaw config not found at ${OPENCLAW_CONFIG_PATH}\n` +
        `Ensure OpenClaw is installed and configured.`
    );
    process.exit(1);
  }

  // Required published skills
  const requiredSkills = [WATCHDOG_AGENT_ID, ENFORCER_AGENT_ID];

  for (const skillName of requiredSkills) {
    const skillDir = join(PUBLISHED_SKILLS_DIR, skillName);

    if (!fs.existsSync(skillDir)) {
      console.error(
        `Error: Published skill not found: ${skillName}\n` +
          `Run "openclaw-safe sign ${skillName}" to sign and publish it.`
      );
      process.exit(1);
    }

    // Verify signature
    let manifest;
    try {
      manifest = readSignedManifest(skillDir);
    } catch (err) {
      console.error(
        `Error: Could not read signed manifest for skill "${skillName}": ${err.message}`
      );
      process.exit(1);
    }

    if (!manifest) {
      console.error(
        `Error: No signed manifest found for skill "${skillName}".\n` +
          `Run "openclaw-safe sign ${skillName}" to sign it.`
      );
      process.exit(1);
    }

    let valid;
    try {
      valid = verifySkillSignature(manifest, skillDir);
    } catch (err) {
      console.error(
        `Error: Signature verification threw for skill "${skillName}": ${err.message}`
      );
      process.exit(1);
    }

    if (!valid) {
      console.error(
        `Error: Signature verification FAILED for skill "${skillName}".\n` +
          `The skill files may have been tampered with since signing.\n` +
          `Re-review and re-sign with "openclaw-safe sign ${skillName}".`
      );
      process.exit(1);
    }

    console.log(`Signature verified: ${skillName}`);
  }

  // OpenClaw gateway — capture output to verify the RPC probe actually succeeded.
  console.log("\nChecking OpenClaw gateway...");
  try {
    const statusOutput = execFileSync(getOpenclawBin(), ["gateway", "status"], {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    console.log(statusOutput);

    // The gateway command may exit 0 even when the RPC probe fails.
    // Check for explicit probe failure indicators in the output.
    if (/RPC probe:\s*failed/i.test(statusOutput) ||
        /gateway closed/i.test(statusOutput)) {
      console.error(
        `Error: OpenClaw gateway RPC probe failed.\n` +
          `The gateway service may not be running. Try:\n` +
          `  openclaw gateway start\n` +
          `Then re-run: openclaw-safe start`
      );
      process.exit(1);
    }
  } catch (err) {
    console.error(
      `Error: OpenClaw gateway is not running or returned a non-zero exit code.\n` +
        `Start the gateway before launching sessions.\n` +
        (err.stderr ? err.stderr.toString() : "")
    );
    process.exit(1);
  }

  // ── 2. Launch sessions in order ───────────────────────────────────────────

  console.log("\nLaunching agent sessions...\n");

  // Watchdog first
  console.log(`Starting watchdog (agent-id: ${WATCHDOG_AGENT_ID})...`);
  spawnDetached("watchdog", [
    "agent",
    "--agent-id", WATCHDOG_AGENT_ID,
    "--message", "Begin watchdog monitoring loop",
  ]);

  console.log("Waiting for watchdog to initialise...");
  await sleep(2000);

  // Enforcer second
  console.log(`Starting enforcer (agent-id: ${ENFORCER_AGENT_ID})...`);
  spawnDetached("enforcer", [
    "agent",
    "--agent-id", ENFORCER_AGENT_ID,
    "--message", "Begin enforcer monitoring loop",
  ]);

  console.log("Waiting for enforcer to initialise...");
  await sleep(2000);

  // SIA last
  console.log(`Starting SIA (agent-id: ${SIA_AGENT_ID})...`);
  spawnDetached("SIA", [
    "agent",
    "--agent-id", SIA_AGENT_ID,
    "--message", "Begin self-improvement session",
  ]);

  // ── 3. Print status ───────────────────────────────────────────────────────

  console.log(`
All three agent sessions launched.

  watchdog   (${WATCHDOG_AGENT_ID})  — monitoring loop active
  enforcer   (${ENFORCER_AGENT_ID})  — monitoring loop active
  SIA        (${SIA_AGENT_ID})   — self-improvement session active

Sessions are running detached.  Monitor via "openclaw gateway status".
`);
}
