/**
 * Signing ceremony command for openclaw-safe.
 *
 * Runs OUTSIDE any agent session.  The human operator reviews the skill
 * contents, approves them, and the file is signed and published to the
 * protected skills directory.
 */

import fs from "fs";
import path from "path";
import readline from "readline";

import {
  WORKSPACE_DIR,
  WORKSPACE_SKILLS_DIR,
  PUBLISHED_SKILLS_DIR,
} from "./paths.mjs";

import {
  hashSkillFiles,
  signSkill,
  writeSignedManifest,
  logSigningEvent,
} from "../signing/verify.mjs";

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Collect every regular file under a directory recursively.
 * Returns paths relative to `baseDir`, sorted deterministically.
 */
function collectFiles(baseDir) {
  const results = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        results.push(path.relative(baseDir, full));
      }
    }
  }

  walk(baseDir);
  return results.sort();
}

/**
 * Prompt the user for a single line of input.
 * Always closes the readline interface before resolving.
 */
function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Run the interactive skill-signing ceremony.
 *
 * @param {string} skillName  Name of the skill subdirectory to sign.
 * @param {object} [options]  Reserved for future flags.
 */
export async function runSign(skillName, options = {}) {
  // ── 1. Validate inputs ────────────────────────────────────────────────────

  if (!skillName) {
    console.error("Error: skillName is required.");
    process.exit(1);
  }

  // Try both candidate locations for the skill directory.
  let skillDir = null;
  let workspaceParent = null;

  const candidateA = path.join(WORKSPACE_SKILLS_DIR, skillName);
  const candidateB = path.join(WORKSPACE_DIR, skillName);

  if (fs.existsSync(candidateA)) {
    skillDir = candidateA;
    workspaceParent = WORKSPACE_SKILLS_DIR;
  } else if (fs.existsSync(candidateB)) {
    skillDir = candidateB;
    workspaceParent = WORKSPACE_DIR;
  } else {
    console.error(
      `Error: Skill directory not found.\n` +
        `  Tried: ${candidateA}\n` +
        `  Tried: ${candidateB}`
    );
    process.exit(1);
  }

  console.log(`\nSkill directory: ${skillDir}`);

  // ── 2. Show skill contents for review ─────────────────────────────────────

  const files = collectFiles(skillDir);

  console.log(`\n${"─".repeat(60)}`);
  console.log(`SKILL CONTENTS — ${skillName} (${files.length} file(s))`);
  console.log("─".repeat(60));

  for (const rel of files) {
    const abs = path.join(skillDir, rel);
    const content = fs.readFileSync(abs, "utf8");
    console.log(`\n┌── ${rel}`);
    console.log(content);
    console.log(`└── (end of ${rel})`);
  }

  const contentHash = hashSkillFiles(skillDir);
  console.log(`\nSHA-256 content hash: ${contentHash}`);

  // ── 3. Show diff against published version (if exists) ────────────────────

  const publishedSkillDir = path.join(PUBLISHED_SKILLS_DIR, skillName);

  if (fs.existsSync(publishedSkillDir)) {
    console.log(`\n${"─".repeat(60)}`);
    console.log(`DIFF vs PUBLISHED VERSION`);
    console.log("─".repeat(60));

    const publishedFiles = new Set(collectFiles(publishedSkillDir));
    const workspaceFiles = new Set(files);

    const newFiles = files.filter((f) => !publishedFiles.has(f));
    const deletedFiles = [...publishedFiles].filter(
      (f) => !workspaceFiles.has(f)
    );
    const modifiedFiles = files.filter((f) => {
      if (!publishedFiles.has(f)) return false; // new, not modified
      const workspaceContent = fs.readFileSync(
        path.join(skillDir, f)
      );
      const publishedContent = fs.readFileSync(
        path.join(publishedSkillDir, f)
      );
      return !workspaceContent.equals(publishedContent);
    });

    if (
      newFiles.length === 0 &&
      deletedFiles.length === 0 &&
      modifiedFiles.length === 0
    ) {
      console.log("No changes detected — skill matches published version.");
    } else {
      if (newFiles.length > 0) {
        console.log(`\nNew files (${newFiles.length}):`);
        for (const f of newFiles) console.log(`  + ${f}`);
      }
      if (modifiedFiles.length > 0) {
        console.log(`\nModified files (${modifiedFiles.length}):`);
        for (const f of modifiedFiles) console.log(`  ~ ${f}`);
      }
      if (deletedFiles.length > 0) {
        console.log(`\nDeleted files (${deletedFiles.length}):`);
        for (const f of deletedFiles) console.log(`  - ${f}`);
      }
    }
  } else {
    console.log(`\n(No published version found — this is a first-time sign.)`);
  }

  // ── 4. Require explicit human confirmation ────────────────────────────────

  const answer = await prompt(
    "\nType SIGN to approve and sign this skill, or anything else to abort: "
  );

  if (answer !== "SIGN") {
    console.log("Signing aborted.");
    return;
  }

  // ── 5. Sign the skill ─────────────────────────────────────────────────────

  console.log("\nSigning...");
  const signedManifest = signSkill(workspaceParent, skillName);
  writeSignedManifest(skillDir, signedManifest);

  // ── 6. Copy to published directory ────────────────────────────────────────

  fs.mkdirSync(publishedSkillDir, { recursive: true });
  fs.cpSync(skillDir, publishedSkillDir, { recursive: true });

  // ── 7. Log the signing event ──────────────────────────────────────────────

  logSigningEvent({
    event: "skill_signed",
    skillName,
    contentHash: signedManifest.contentHash,
    signedAt: signedManifest.signedAt,
  });

  // ── 8. Print success message ──────────────────────────────────────────────

  console.log(`\nSkill "${skillName}" signed and published successfully.`);
  console.log(`Published path: ${publishedSkillDir}`);
  console.log(`Content hash:   ${signedManifest.contentHash}`);
  console.log(`Signed at:      ${signedManifest.signedAt}`);
}
