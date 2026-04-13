/**
 * Skill signing and verification utilities for openclaw-safe.
 *
 * Signing uses ECDSA-SHA256 (P-256).  The content hash is computed from
 * all files inside the skill directory (excluding the manifest itself) so
 * that any post-signing modification is detectable.
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
  PRIVATE_KEY_PATH,
  PUBLIC_KEY_PATH,
  AUDIT_DIR,
  SIGNING_LOG,
} from "../src/paths.mjs";

/** Name of the manifest file stored inside each skill directory. */
const MANIFEST_FILENAME = ".signed-manifest.json";

// ─── Content hashing ────────────────────────────────────────────────────────

/**
 * Compute a deterministic SHA-256 hash of all files in a skill directory.
 *
 * The manifest file itself is excluded so that writing or re-writing the
 * manifest does not invalidate an otherwise unchanged skill.
 *
 * @param {string} skillDir  Absolute path to the skill directory.
 * @returns {string}  Hex-encoded SHA-256 digest.
 */
export function hashSkillFiles(skillDir) {
  // Collect every file recursively, with directory entry metadata.
  const dirents = fs.readdirSync(skillDir, { recursive: true, withFileTypes: true });

  // Build relative paths for all regular files, excluding the manifest.
  const relPaths = dirents
    .filter((d) => d.isFile() && d.name !== MANIFEST_FILENAME)
    .map((d) => path.relative(skillDir, path.join(d.parentPath, d.name)));

  // Sort for determinism (independent of OS traversal order or absolute paths).
  relPaths.sort();

  const hasher = crypto.createHash("sha256");

  for (const rel of relPaths) {
    const absPath = path.join(skillDir, rel);
    const contents = fs.readFileSync(absPath);
    // Include the relative path itself so a rename changes the hash.
    hasher.update(rel);
    hasher.update(contents);
  }

  return hasher.digest("hex");
}

// ─── Signing ─────────────────────────────────────────────────────────────────

/**
 * Sign a skill's current content and return a signed manifest object.
 *
 * @param {string} workspacePath  Path to the workspace root.
 * @param {string} skillName      Name of the skill subdirectory.
 * @returns {{ skillName: string, contentHash: string, signature: string, signedAt: string, signedBy: string }}
 */
export function signSkill(workspacePath, skillName) {
  const skillDir = path.join(workspacePath, skillName);

  const contentHash = hashSkillFiles(skillDir);
  const privateKeyPem = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");

  const signer = crypto.createSign("SHA256");
  signer.update(contentHash);
  signer.end();

  const signature = signer.sign(privateKeyPem, "hex");

  return {
    skillName,
    contentHash,
    signature,
    signedAt: new Date().toISOString(),
    signedBy: "human-operator",
  };
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify a signed manifest against the skill files currently on disk.
 *
 * The signature is checked against the *recomputed* hash of the actual files
 * rather than the stored `contentHash` field to prevent a substitution attack
 * where an attacker replaces both the files and the manifest hash together.
 *
 * @param {object} signedManifest  Manifest object (as returned by `signSkill`).
 * @param {string} skillDir        Absolute path to the skill directory.
 * @returns {boolean}  True if the signature is valid for the current disk contents.
 */
export function verifySkillSignature(signedManifest, skillDir) {
  const recomputedHash = hashSkillFiles(skillDir);
  const publicKeyPem   = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");

  const verifier = crypto.createVerify("SHA256");
  verifier.update(recomputedHash);
  verifier.end();

  try {
    return verifier.verify(publicKeyPem, signedManifest.signature, "hex");
  } catch {
    return false;
  }
}

// ─── Manifest I/O ─────────────────────────────────────────────────────────────

/**
 * Write a signed manifest as `.signed-manifest.json` inside the skill directory.
 *
 * @param {string} skillDir      Absolute path to the skill directory.
 * @param {object} signedManifest  The manifest object to serialise.
 */
export function writeSignedManifest(skillDir, signedManifest) {
  const manifestPath = path.join(skillDir, MANIFEST_FILENAME);
  fs.writeFileSync(manifestPath, JSON.stringify(signedManifest, null, 2) + "\n", "utf8");
}

/**
 * Read and parse the `.signed-manifest.json` from a skill directory.
 *
 * @param {string} skillDir  Absolute path to the skill directory.
 * @returns {object|null}  Parsed manifest, or null if it does not exist.
 */
export function readSignedManifest(skillDir) {
  const manifestPath = path.join(skillDir, MANIFEST_FILENAME);
  if (!fs.existsSync(manifestPath)) return null;
  return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
}

// ─── Audit logging ────────────────────────────────────────────────────────────

/**
 * Append a signing event as a JSON line to the signing audit log.
 *
 * @param {object} event  Arbitrary event object; `timestamp` is injected if absent.
 */
export function logSigningEvent(event) {
  fs.mkdirSync(AUDIT_DIR, { recursive: true });
  const record = { timestamp: new Date().toISOString(), ...event };
  fs.appendFileSync(SIGNING_LOG, JSON.stringify(record) + "\n", "utf8");
}
