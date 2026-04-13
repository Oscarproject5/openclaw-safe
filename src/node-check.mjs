/**
 * Gate: exit with a clear message if Node.js version is too old.
 * OpenClaw requires Node 22.14+ (24 recommended).
 */

const MINIMUM_VERSION = [22, 14, 0];

export function checkNodeVersion() {
  const parts = process.versions.node.split(".").map(Number);

  for (let i = 0; i < 3; i++) {
    if (parts[i] > MINIMUM_VERSION[i]) return; // definitely OK
    if (parts[i] < MINIMUM_VERSION[i]) {
      console.error(
        `\n  openclaw-safe requires Node.js >= ${MINIMUM_VERSION.join(".")}\n` +
          `  You are running Node.js ${process.versions.node}\n\n` +
          `  Upgrade: https://nodejs.org/en/download\n` +
          `  Recommended: Node.js 24\n`
      );
      process.exit(1);
    }
    // equal — check next component
  }
}
