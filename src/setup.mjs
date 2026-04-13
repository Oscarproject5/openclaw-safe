/**
 * Setup / installer module for openclaw-safe.
 *
 * Runs seven sequential phases:
 *   1. Check prerequisites (Node version, openclaw on PATH)
 *   2. Prompt user through OpenClaw onboarding
 *   3. Create directory structure
 *   4. Generate ECDSA signing keypair
 *   5. Write OpenClaw config
 *   6. Copy and sign bundled skills (watchdog, enforcer)
 *   7. Print summary and next steps
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";
import readline from "readline";

import { checkNodeVersion } from "./node-check.mjs";
import { generateSigningKeys } from "../signing/keygen.mjs";
import { signSkill, writeSignedManifest, logSigningEvent } from "../signing/verify.mjs";
import {
  WORKSPACE_DIR,
  WORKSPACE_SKILLS_DIR,
  AUDIT_DIR,
  PUBLISHED_SKILLS_DIR,
  SAFETY_CONFIG_DIR,
  SIGNING_KEYS_DIR,
  BUNDLED_WATCHDOG_SKILL,
  BUNDLED_ENFORCER_SKILL,
  OPENCLAW_CONFIG_PATH,
} from "./paths.mjs";

// ─── Package root ─────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const PKG_ROOT   = path.resolve(__dirname, "..");

// ─── readline helper ──────────────────────────────────────────────────────────

/**
 * Ask a question on stdout and return the user's answer as a Promise<string>.
 * A fresh readline interface is created and closed for each call so stdin
 * does not remain held open between prompts.
 *
 * @param {string} question  Text to print before waiting for input.
 * @returns {Promise<string>}
 */
export function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input:  process.stdin,
      output: process.stdout,
    });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Run the full openclaw-safe setup sequence.
 *
 * @param {object}  [options]
 * @param {boolean} [options.force=false]  Pass through to key generation;
 *   overwrites existing signing keys when true.
 */
export async function runSetup({ force = false } = {}) {

  // ── Phase 1 — Check prerequisites ────────────────────────────────────────

  console.log("\n=== Phase 1: Checking prerequisites ===\n");

  // Node.js version gate (exits the process if too old).
  checkNodeVersion();
  console.log(`  Node.js ${process.versions.node} — OK`);

  // Check whether `openclaw` is on PATH.
  const whichCmd  = process.platform === "win32" ? "where" : "which";
  const whichResult = spawnSync(whichCmd, ["openclaw"]);

  if (whichResult.status !== 0) {
    console.log("\n  OpenClaw is not installed. Install it with:");
    console.log("    npm install -g openclaw");
    console.log("  Or:");
    console.log("    PowerShell: iwr -useb https://openclaw.ai/install.ps1 | iex");
    console.log("");
    await prompt("  Press Enter to continue once OpenClaw is installed...");
  } else {
    const found = whichResult.stdout.toString().trim();
    console.log(`  openclaw found — ${found}`);
  }

  // ── Phase 2 — Prompt for onboarding ──────────────────────────────────────

  console.log("\n=== Phase 2: OpenClaw onboarding ===\n");
  console.log("  OpenClaw requires an interactive onboard step.");
  console.log("  If you haven't already, run: openclaw onboard --install-daemon");
  await prompt("  Press Enter once onboarding is complete...");

  // ── Phase 3 — Create directory structure ─────────────────────────────────

  console.log("\n=== Phase 3: Creating directory structure ===\n");

  const dirsToCreate = [
    WORKSPACE_DIR,
    WORKSPACE_SKILLS_DIR,
    AUDIT_DIR,
    path.join(AUDIT_DIR, "incidents"),
    PUBLISHED_SKILLS_DIR,
    SAFETY_CONFIG_DIR,
  ];

  for (const dir of dirsToCreate) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`  Created: ${dir}`);
  }

  // ── Phase 4 — Generate signing keypair ───────────────────────────────────

  console.log("\n=== Phase 4: Generating signing keys ===\n");

  try {
    generateSigningKeys({ force });
  } catch (err) {
    if (!force && err.message.includes("already exist")) {
      console.log(
        "  Signing keys already exist. Skipping. Use --force to regenerate."
      );
    } else {
      throw err;
    }
  }

  // ── Phase 5 — Write OpenClaw config ──────────────────────────────────────

  console.log("\n=== Phase 5: Writing OpenClaw config ===\n");

  const configTemplatePath = path.join(PKG_ROOT, "config", "openclaw-safe.json5");
  const configTemplate = fs.readFileSync(configTemplatePath, "utf8");

  let writeConfig = true;

  if (fs.existsSync(OPENCLAW_CONFIG_PATH)) {
    const answer = await prompt(
      `  OpenClaw config already exists at ${OPENCLAW_CONFIG_PATH}.\n` +
      "  Overwrite? (y/N): "
    );
    writeConfig = answer.trim().toLowerCase() === "y";
  }

  if (writeConfig) {
    fs.mkdirSync(path.dirname(OPENCLAW_CONFIG_PATH), { recursive: true });
    fs.writeFileSync(OPENCLAW_CONFIG_PATH, configTemplate, "utf8");
    console.log(`  Written: ${OPENCLAW_CONFIG_PATH}`);
  } else {
    console.log("  Skipped (existing config preserved).");
  }

  // ── Phase 6 — Copy and sign bundled skills ────────────────────────────────

  console.log("\n=== Phase 6: Installing and signing bundled skills ===\n");

  const bundledSkills = [
    { srcRelative: BUNDLED_WATCHDOG_SKILL },
    { srcRelative: BUNDLED_ENFORCER_SKILL },
  ];

  for (const { srcRelative } of bundledSkills) {
    const skillName = path.basename(srcRelative);
    const srcPath   = path.join(PKG_ROOT, srcRelative);
    const destPath  = path.join(PUBLISHED_SKILLS_DIR, skillName);

    // Copy skill directory into PUBLISHED_SKILLS_DIR.
    fs.cpSync(srcPath, destPath, { recursive: true });

    // Sign the published copy.
    // signSkill(parentDir, skillName) — combines them internally.
    const manifest = signSkill(PUBLISHED_SKILLS_DIR, skillName);

    // Write the manifest file into the skill's own directory.
    writeSignedManifest(destPath, manifest);

    // Append an audit record.
    logSigningEvent({
      action:    "install",
      skillName,
      publishedPath: destPath,
      contentHash:   manifest.contentHash,
    });

    console.log(`  Installed and signed: ${skillName}`);
  }

  // ── Phase 7 — Summary and next steps ─────────────────────────────────────

  console.log(`
Setup complete!

Directory structure:
  Workspace (SIA writable): ${WORKSPACE_DIR}
  Published skills:         ${PUBLISHED_SKILLS_DIR}
  Audit logs:               ${AUDIT_DIR}
  Signing keys:             ${SIGNING_KEYS_DIR}

Next steps:
  1. Run NTFS hardening (as Administrator):
     powershell -ExecutionPolicy Bypass -File hardening/hardening.ps1

  2. Start the safe self-improvement system:
     openclaw-safe start
`);
}
