/**
 * Canonical path constants for openclaw-safe.
 *
 * Signing keys are stored OUTSIDE the OpenClaw directory tree to prevent
 * any agent session from reading or modifying them.
 */

import { homedir } from "os";
import { join } from "path";

const HOME = homedir();

// ── OpenClaw root ──────────────────────────────────────────────
export const OPENCLAW_HOME = join(HOME, ".openclaw");

// ── Protected zones (deny-write to agent process) ──────────────
export const CORE_DIR = join(OPENCLAW_HOME, "core");
export const SAFETY_CONFIG_DIR = join(OPENCLAW_HOME, "config", "safety");
export const PUBLISHED_SKILLS_DIR = join(OPENCLAW_HOME, "skills");

// ── Writable zone (only place the SIA can write) ───────────────
export const WORKSPACE_DIR = join(OPENCLAW_HOME, "workspaces", "selfimprove");
export const WORKSPACE_SKILLS_DIR = join(WORKSPACE_DIR, "skills");

// ── Audit (append-only) ────────────────────────────────────────
export const AUDIT_DIR = join(OPENCLAW_HOME, "audit");
export const WATCHDOG_ALERTS_LOG = join(AUDIT_DIR, "watchdog-alerts.jsonl");
export const ENFORCER_ACTIONS_LOG = join(AUDIT_DIR, "enforcer-actions.jsonl");
export const SIGNING_LOG = join(AUDIT_DIR, "signing-events.jsonl");

// ── Signing keys — OUTSIDE OpenClaw tree ───────────────────────
export const SIGNING_KEYS_DIR = join(HOME, ".openclaw-keys");
export const PRIVATE_KEY_PATH = join(SIGNING_KEYS_DIR, "signing.key");
export const PUBLIC_KEY_PATH = join(SIGNING_KEYS_DIR, "signing.pub");

// ── Config ─────────────────────────────────────────────────────
export const OPENCLAW_CONFIG_PATH = join(OPENCLAW_HOME, "openclaw.json");
export const SAFE_CONFIG_TEMPLATE = "config/openclaw-safe.json5";

// ── Session / agent IDs ────────────────────────────────────────
export const SIA_SESSION_ID = "self-improve-session";
export const WATCHDOG_SESSION_ID = "watchdog-session";
export const ENFORCER_SESSION_ID = "enforcer-session";

export const SIA_AGENT_ID = "self-improve";
export const WATCHDOG_AGENT_ID = "watchdog";
export const ENFORCER_AGENT_ID = "enforcer";

// ── Bundled skill source paths (relative to package root) ──────
export const BUNDLED_WATCHDOG_SKILL = "skills/watchdog";
export const BUNDLED_ENFORCER_SKILL = "skills/enforcer";
