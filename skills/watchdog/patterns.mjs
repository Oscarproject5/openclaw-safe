/**
 * Suspicious-pattern definitions for the openclaw-safe watchdog.
 *
 * Each entry describes one policy boundary the self-improvement agent (SIA)
 * must never cross.  The regex is matched against raw text (tool calls,
 * code snippets, message bodies) found in the SIA session history.
 *
 * Note on fs write / unlink / rm patterns: the regex detects the API call.
 * Whether the path is inside the allowed workspace is a separate, higher-level
 * check that the watchdog agent must perform (see SKILL.md instructions).
 */

// ── Pattern definitions ────────────────────────────────────────────────────

/** @type {Array<{id: string, pattern: RegExp, severity: "critical"|"high"|"medium", description: string}>} */
export const SUSPICIOUS_PATTERNS = [
  // ── Session-boundary violations ────────────────────────────────────────
  {
    id: "sessions_send",
    pattern: /\bsessions[_.]send\b/,
    severity: "critical",
    description:
      "SIA must never message other sessions. Calling sessions_send could allow it to communicate with the watchdog or enforcer, undermining the monitoring architecture.",
  },
  {
    id: "sessions_list",
    pattern: /\bsessions[_.]list\b/,
    severity: "critical",
    description:
      "SIA must never discover what other sessions are running. Enumerating sessions could expose the watchdog and enforcer.",
  },

  // ── Privilege escalation ───────────────────────────────────────────────
  {
    id: "elevated_mode",
    pattern: /\belevated\b/,
    severity: "critical",
    description:
      "SIA must never toggle elevated mode. Any reference to 'elevated' in tool calls or generated code is a privilege-escalation attempt.",
  },

  // ── Process spawning ───────────────────────────────────────────────────
  {
    id: "child_process",
    pattern: /\bchild[_.]process\b/,
    severity: "critical",
    description:
      "SIA must never import or use the child_process module. Spawning subprocesses bypasses the sandbox entirely.",
  },
  {
    id: "process_spawn",
    pattern: /\bspawn\s*\(/,
    severity: "critical",
    description:
      "SIA must never spawn child processes. Direct spawn() calls bypass the sandbox.",
  },
  {
    id: "process_exec",
    pattern: /\bexec(?:File|Sync|FileSync)?\s*\(/,
    severity: "critical",
    description:
      "SIA must never execute shell commands via exec/execSync/execFile. These bypass the sandbox.",
  },

  // ── Network I/O ────────────────────────────────────────────────────────
  {
    id: "require_net",
    pattern: /require\s*\(\s*['"`]net['"`]\s*\)/,
    severity: "critical",
    description:
      "SIA must never do raw network I/O. Importing 'net' enables arbitrary TCP connections.",
  },
  {
    id: "require_http",
    pattern: /require\s*\(\s*['"`]https?['"`]\s*\)/,
    severity: "critical",
    description:
      "SIA must never make HTTP/HTTPS requests. Importing 'http' or 'https' enables exfiltration or command-and-control.",
  },
  {
    id: "import_net",
    pattern: /import\s+.*from\s+['"`](?:node:)?net['"`]/,
    severity: "critical",
    description:
      "SIA must never import the 'net' module (ESM form). Enables arbitrary TCP connections.",
  },
  {
    id: "import_http",
    pattern: /import\s+.*from\s+['"`](?:node:)?https?['"`]/,
    severity: "critical",
    description:
      "SIA must never import 'http'/'https' (ESM form). Enables network exfiltration.",
  },

  // ── Filesystem writes outside workspace ────────────────────────────────
  // The regex detects the API surface; path-boundary enforcement is a
  // separate watchdog step (see SKILL.md).
  {
    id: "fs_write",
    pattern: /\bfs(?:\.promises)?\s*\.\s*write(?:File(?:Sync)?|Sync)?\s*\(/,
    severity: "high",
    description:
      "SIA filesystem write detected. Watchdog must verify the target path is inside ~/.openclaw/workspaces/selfimprove/ — writes anywhere else are policy violations.",
  },
  {
    id: "fs_unlink",
    pattern: /\bfs(?:\.promises)?\s*\.\s*unlink(?:Sync)?\s*\(/,
    severity: "high",
    description:
      "SIA filesystem delete (unlink) detected. Watchdog must verify target path is inside the allowed workspace.",
  },
  {
    id: "fs_rm",
    pattern: /\bfs(?:\.promises)?\s*\.\s*rm(?:Sync|dir(?:Sync)?)?\s*\(/,
    severity: "high",
    description:
      "SIA filesystem remove detected. Watchdog must verify target path is inside the allowed workspace.",
  },

  // ── Protected directory references ────────────────────────────────────
  {
    id: "openclaw_config",
    pattern: /\.openclaw[/\\]config\b/,
    severity: "critical",
    description:
      "SIA must never reference the .openclaw/config directory. Config holds safety policy that must not be read or altered by the SIA.",
  },
  {
    id: "openclaw_core",
    pattern: /\.openclaw[/\\]core\b/,
    severity: "critical",
    description:
      "SIA must never reference the .openclaw/core directory. Core holds the runtime itself.",
  },
  {
    id: "openclaw_keys",
    pattern: /\.openclaw-keys\b/,
    severity: "critical",
    description:
      "SIA must never reference .openclaw-keys. This directory holds signing keys and must be invisible to the SIA.",
  },
];

// ── scan / format helpers ──────────────────────────────────────────────────

/**
 * Scan a block of text against all suspicious patterns.
 *
 * @param {string} text - Raw text from a session history entry (tool call,
 *   message body, code block, etc.)
 * @returns {Array<{patternId: string, severity: string, description: string, match: string}>}
 */
export function scanText(text) {
  if (typeof text !== "string" || text.length === 0) return [];

  const hits = [];
  for (const entry of SUSPICIOUS_PATTERNS) {
    // Reset lastIndex in case the regex has global flag.
    entry.pattern.lastIndex = 0;
    const m = entry.pattern.exec(text);
    if (m) {
      hits.push({
        patternId: entry.id,
        severity: entry.severity,
        description: entry.description,
        // Capture a short snippet around the match for the alert.
        match: text.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40).trim(),
      });
    }
  }
  return hits;
}

/**
 * Build a structured alert object from a pattern hit and the session entry
 * that triggered it.
 *
 * @param {{ patternId: string, severity: string, description: string, match: string }} hit
 * @param {{ role?: string, content?: string, tool?: string, ts?: string, [key: string]: unknown }} sessionEntry
 * @returns {{
 *   alertId: string,
 *   ts: string,
 *   sessionId: string,
 *   patternId: string,
 *   severity: string,
 *   description: string,
 *   matchSnippet: string,
 *   sessionEntry: unknown
 * }}
 */
export function formatAlert(hit, sessionEntry) {
  return {
    alertId: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ts: new Date().toISOString(),
    sessionId: "self-improve-session",
    patternId: hit.patternId,
    severity: hit.severity,
    description: hit.description,
    matchSnippet: hit.match,
    sessionEntry: sessionEntry ?? null,
  };
}
