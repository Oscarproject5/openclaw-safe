/**
 * ECDSA P-256 key-pair generator for openclaw-safe signing.
 *
 * Keys are written to SIGNING_KEYS_DIR (~/.openclaw-keys), which is
 * intentionally outside the OpenClaw directory tree so no agent session
 * can read or modify them.
 */

import crypto from "crypto";
import fs from "fs";
import { SIGNING_KEYS_DIR, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH } from "../src/paths.mjs";

/**
 * Generate an ECDSA P-256 signing key-pair and write the PEM files to disk.
 *
 * @param {object}  [options]
 * @param {boolean} [options.force=false]  Overwrite existing keys if true.
 * @returns {{ privateKeyPath: string, publicKeyPath: string }}
 */
export function generateSigningKeys({ force = false } = {}) {
  // Guard: refuse to clobber existing keys unless explicitly forced.
  const privateExists = fs.existsSync(PRIVATE_KEY_PATH);
  const publicExists  = fs.existsSync(PUBLIC_KEY_PATH);

  if ((privateExists || publicExists) && !force) {
    throw new Error(
      `Signing keys already exist at ${SIGNING_KEYS_DIR}.\n` +
      `Pass { force: true } (or --force) to overwrite them.\n` +
      `  private: ${PRIVATE_KEY_PATH}\n` +
      `  public:  ${PUBLIC_KEY_PATH}`
    );
  }

  // Ensure the key directory exists (outside the OpenClaw tree).
  fs.mkdirSync(SIGNING_KEYS_DIR, { recursive: true });

  // Generate the key-pair.
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  // Write keys to disk.
  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey,  { encoding: "utf8" });
  fs.writeFileSync(PUBLIC_KEY_PATH,  publicKey,   { encoding: "utf8" });

  // Restrict private key to owner-read-only (best-effort; silently ignored on Windows).
  try {
    fs.chmodSync(PRIVATE_KEY_PATH, 0o600);
  } catch {
    // Non-POSIX platforms (Windows) do not support chmod — continue.
  }

  console.log("Signing keys written:");
  console.log(`  private: ${PRIVATE_KEY_PATH}`);
  console.log(`  public:  ${PUBLIC_KEY_PATH}`);

  return { privateKeyPath: PRIVATE_KEY_PATH, publicKeyPath: PUBLIC_KEY_PATH };
}
