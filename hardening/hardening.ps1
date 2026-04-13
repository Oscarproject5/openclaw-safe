#Requires -RunAsAdministrator
<#
.SYNOPSIS
    openclaw-safe NTFS Hardening Script

.DESCRIPTION
    Applies NTFS ACL deny rules to protect OpenClaw's core, safety config,
    published skills, and signing keys from modification by the agent process.
    Defense-in-depth layer for if the process sandbox is bypassed.

    Must be run as Administrator.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  openclaw-safe NTFS Hardening Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── Path definitions (mirrors src/paths.mjs) ──────────────────────────────
$OPENCLAW_HOME  = "$env:USERPROFILE\.openclaw"
$CORE_DIR       = "$OPENCLAW_HOME\core"
$SAFETY_DIR     = "$OPENCLAW_HOME\config\safety"
$PUBLISHED_DIR  = "$OPENCLAW_HOME\skills"
$WORKSPACE_DIR  = "$OPENCLAW_HOME\workspaces\selfimprove"
$AUDIT_DIR      = "$OPENCLAW_HOME\audit"
$KEYS_DIR       = "$env:USERPROFILE\.openclaw-keys"

$CurrentUser    = "$env:USERDOMAIN\$env:USERNAME"

# ── Pre-flight: verify OPENCLAW_HOME exists ───────────────────────────────
Write-Host "Pre-flight check..." -ForegroundColor Yellow
if (-not (Test-Path $OPENCLAW_HOME)) {
    Write-Host "  FAIL: $OPENCLAW_HOME does not exist." -ForegroundColor Red
    Write-Host "  Run 'openclaw-safe setup' first, then re-run this script." -ForegroundColor Red
    exit 1
}
Write-Host "  OK: $OPENCLAW_HOME exists" -ForegroundColor Green
Write-Host ""

# ── Helper: create a directory if it doesn't exist ────────────────────────
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Host "  Creating directory: $Path" -ForegroundColor Gray
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# ── Helper: apply deny rules to a protected directory ─────────────────────
function Apply-ProtectedDenyRules {
    param(
        [string]$Path,
        [string]$Label
    )

    Write-Host "  Hardening: $Label" -ForegroundColor Yellow
    Write-Host "    Path: $Path"

    Ensure-Directory -Path $Path

    $acl = Get-Acl -Path $Path

    # Deny the current user: Write, Delete, ChangePermissions on this
    # directory and all children.
    $inheritFlags  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation   = [System.Security.AccessControl.PropagationFlags]"None"
    $denyType      = [System.Security.AccessControl.AccessControlType]"Deny"

    $denyRights = (
        [System.Security.AccessControl.FileSystemRights]"Write, Delete, ChangePermissions"
    )

    $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $CurrentUser,
        $denyRights,
        $inheritFlags,
        $propagation,
        $denyType
    )

    $acl.AddAccessRule($denyRule)
    Set-Acl -Path $Path -AclObject $acl

    Write-Host "    Applied DENY Write|Delete|ChangePermissions for $CurrentUser" -ForegroundColor Green
}

# ── Helper: apply audit-directory rules (append allowed, delete denied) ───
function Apply-AuditDirRules {
    param([string]$Path)

    Write-Host "  Hardening: Audit Directory" -ForegroundColor Yellow
    Write-Host "    Path: $Path"

    Ensure-Directory -Path $Path

    $acl           = Get-Acl -Path $Path
    $inheritFlags  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation   = [System.Security.AccessControl.PropagationFlags]"None"

    # Allow AppendData so log writers can append to existing log files.
    $allowRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $CurrentUser,
        [System.Security.AccessControl.FileSystemRights]"AppendData",
        $inheritFlags,
        $propagation,
        [System.Security.AccessControl.AccessControlType]"Allow"
    )

    # Deny Delete and ChangePermissions to prevent log tampering.
    $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $CurrentUser,
        [System.Security.AccessControl.FileSystemRights]"Delete, ChangePermissions",
        $inheritFlags,
        $propagation,
        [System.Security.AccessControl.AccessControlType]"Deny"
    )

    $acl.AddAccessRule($allowRule)
    $acl.AddAccessRule($denyRule)
    Set-Acl -Path $Path -AclObject $acl

    Write-Host "    Applied ALLOW AppendData + DENY Delete|ChangePermissions for $CurrentUser" -ForegroundColor Green
}

# ── Apply rules ────────────────────────────────────────────────────────────
Write-Host "Applying NTFS ACL rules..." -ForegroundColor Cyan
Write-Host ""

Apply-ProtectedDenyRules -Path $CORE_DIR      -Label "Core Directory"
Apply-ProtectedDenyRules -Path $SAFETY_DIR    -Label "Safety Config Directory"
Apply-ProtectedDenyRules -Path $PUBLISHED_DIR -Label "Published Skills Directory"
Apply-ProtectedDenyRules -Path $KEYS_DIR      -Label "Signing Keys Directory"
Apply-AuditDirRules      -Path $AUDIT_DIR

Write-Host ""

# ── Verification step ─────────────────────────────────────────────────────
Write-Host "Verifying deny rules..." -ForegroundColor Cyan
Write-Host ""

$protectedDirs = @{
    "Core Directory"             = $CORE_DIR
    "Safety Config Directory"    = $SAFETY_DIR
    "Published Skills Directory" = $PUBLISHED_DIR
    "Signing Keys Directory"     = $KEYS_DIR
}

$allPassed = $true

foreach ($entry in $protectedDirs.GetEnumerator()) {
    $label = $entry.Key
    $path  = $entry.Value

    Write-Host "  Checking: $label ($path)"

    if (-not (Test-Path $path)) {
        Write-Host "    FAIL — directory does not exist" -ForegroundColor Red
        $allPassed = $false
        continue
    }

    $acl        = Get-Acl -Path $path
    $denyRules  = $acl.Access | Where-Object {
        $_.AccessControlType -eq "Deny" -and
        $_.IdentityReference -like "*$env:USERNAME*"
    }

    if ($denyRules) {
        Write-Host "    PASS — deny rule(s) confirmed for $env:USERNAME" -ForegroundColor Green
    } else {
        Write-Host "    FAIL — no deny rules found for $env:USERNAME" -ForegroundColor Red
        $allPassed = $false
    }
}

# Audit dir: check for deny on Delete/ChangePermissions
Write-Host "  Checking: Audit Directory ($AUDIT_DIR)"
if (Test-Path $AUDIT_DIR) {
    $auditAcl   = Get-Acl -Path $AUDIT_DIR
    $auditDeny  = $auditAcl.Access | Where-Object {
        $_.AccessControlType -eq "Deny" -and
        $_.IdentityReference -like "*$env:USERNAME*"
    }
    if ($auditDeny) {
        Write-Host "    PASS — deny rule(s) confirmed for $env:USERNAME" -ForegroundColor Green
    } else {
        Write-Host "    FAIL — no deny rules found for $env:USERNAME" -ForegroundColor Red
        $allPassed = $false
    }
} else {
    Write-Host "    FAIL — directory does not exist" -ForegroundColor Red
    $allPassed = $false
}

Write-Host ""

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if ($allPassed) {
    Write-Host "  All hardening rules applied and verified." -ForegroundColor Green
} else {
    Write-Host "  One or more rules could not be verified. Review output above." -ForegroundColor Red
}

Write-Host ""
Write-Host "  Protected zones (agent cannot write):" -ForegroundColor Yellow
Write-Host "    $CORE_DIR"
Write-Host "    $SAFETY_DIR"
Write-Host "    $PUBLISHED_DIR"
Write-Host "    $KEYS_DIR"
Write-Host ""
Write-Host "  Writable zone (SIA writes here only):" -ForegroundColor Yellow
Write-Host "    $WORKSPACE_DIR"
Write-Host ""
Write-Host "  Audit zone (append-only):" -ForegroundColor Yellow
Write-Host "    $AUDIT_DIR"
Write-Host ""
Write-Host "  NOTE: NTFS ACLs are a defense-in-depth layer." -ForegroundColor Gray
Write-Host "  Primary isolation is provided by OpenClaw's Docker sandbox + tool policy." -ForegroundColor Gray
Write-Host "  These ACLs defend against sandbox escapes only." -ForegroundColor Gray
Write-Host ""
