#!/usr/bin/env python3
"""
agent-shell-filter -- Server-side command validation script.

Deployed to /usr/local/bin/agent-shell-filter on each target server.
Invoked as an SSH forced-command (via authorized_keys `command=` directive).

Protocol:
  The agent sends: "<6-digit TOTP> <command>"
  This script:
    1. Parses the input
    2. Validates TOTP against the local secret
    3. Checks command against unconditional blocklist
    4. Executes via shell or rejects

Usage (on server):
  /usr/local/bin/agent-shell-filter 123456 df -h
"""

import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone

# Path to TOTP secret on the server (deployed once during setup)
TOTP_SECRET_PATH = "/etc/agent/totp_secret"

# Server-side audit log path
AUDIT_LOG_PATH = "/var/log/agent-shell-filter.jsonl"

# Commands that are NEVER allowed, even with valid TOTP.
# This is defense-in-depth -- the agent side should also block these.
UNCONDITIONAL_BLOCKED: list[tuple[str, str]] = [
    (r"\brm\s+-(?:rf?|fr)\s+/", "Recursive delete of root is unconditionally blocked"),
    (r"\brm\s+-(?:rf?|fr)\s+~", "Recursive delete of home is unconditionally blocked"),
    (r"\bmkfs\.", "Filesystem creation (mkfs) is unconditionally blocked"),
    (r"\bshutdown\b", "shutdown is unconditionally blocked"),
    (r"\breboot\b", "reboot is unconditionally blocked"),
    (r"\bhalt\b", "halt is unconditionally blocked"),
    (r"\bpoweroff\b", "poweroff is unconditionally blocked"),
    (r"\bdd\s+if=.*of=/dev/[sh]d", "dd to block device is unconditionally blocked"),
    (r">\s*/dev/sd[a-z]+\s*$", "Redirect to block device is unconditionally blocked"),
    (r"\bchmod\s+.*777\s+/", "chmod 777 on root paths is unconditionally blocked"),
    (r"\b:\(\)\s*\{", "Fork bomb pattern is unconditionally blocked"),
]

# Patterns for commands considered read-only (auto-approved, no TOTP required)
_READONLY_PATTERNS = [
    r"^ls\b", r"^ll\b", r"^df\b", r"^du\b", r"^stat\b", r"^cat\b", r"^head\b", r"^tail\b",
    r"^less\b", r"^zcat\b", r"^file\b", r"^find\b", r"^locate\b", r"^grep\b", r"^egrep\b",
    r"^ps\b", r"^top\b", r"^htop\b", r"^uptime\b", r"^free\b", r"^vmstat\b", r"^iostat\b",
    r"^dmesg\b", r"^lsof\b", r"^lsblk\b", r"^systemctl\s+status\b", r"^systemctl\s+list-\b",
    r"^systemctl\s+is-\b", r"^systemctl\s+show\b", r"^systemctl\s+cat\b", r"^journalctl\b",
    r"^who\b", r"^w\b", r"^whoami\b", r"^id\b", r"^last\b", r"^lastb\b", r"^getent\b",
    r"^ss\b", r"^netstat\b", r"^ip\s+addr\b", r"^ip\s+link\b", r"^ip\s+route\b",
    r"^hostname\b", r"^hostnamectl\b", r"^ping\b", r"^traceroute\b", r"^nslookup\b",
    r"^dig\b", r"^curl\b", r"^wget\b", r"^uname\b", r"^lscpu\b", r"^lspci\b",
    r"^timedatectl\b", r"^pgrep\b", r"^pidof\b", r"^dpkg\s+-[lL]\b", r"^rpm\s+-q",
    r"^apt\s+list\b", r"^findmnt\b", r"^env\b", r"^printenv\b", r"^echo\b",
    r"--help$", r"--version$", r"^man\b", r"^info\b", r"^whatis\b", r"^docker\s+ps\b",
    r"^docker\s+images\b", r"^docker\s+logs\b", r"^docker\s+inspect\b",
]


def _ensure_audit_file() -> None:
    """Create audit log with restrictive permissions if it doesn't exist."""
    if not os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, "w") as f:
            f.write("")
        os.chmod(AUDIT_LOG_PATH, 0o600)


def _write_audit_entry(
    command: str,
    category: str,
    approved: bool,
    exit_code: int,
    stdout: str,
    stderr: str,
) -> None:
    """Append a JSON audit line to the server-side audit log."""
    _ensure_audit_file()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": socket.gethostname(),
        "command": command,
        "category": category,
        "approved": approved,
        "exit_code": exit_code,
        "stdout": stdout[:8192] if stdout else "",
        "stderr": stderr[:8192] if stderr else "",
    }
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def SERVER_SIDE_BLOCKED(command: str) -> bool:
    """Check if command matches unconditionally blocked patterns. Returns True if blocked."""
    for pattern, _msg in UNCONDITIONAL_BLOCKED:
        if re.search(pattern, command):
            return True
    return False


def parse_ssh_command_input(raw_input: str) -> tuple[str | None, str]:
    """Parse the SSH_ORIGINAL_COMMAND-style input.

    Expected format: "TOTP_CODE COMMAND"

    Returns (totp_code_or_none, command_string).
    """
    raw = raw_input.strip()
    if not raw:
        return None, ""

    parts = raw.split(maxsplit=1)
    if len(parts) < 2:
        # No TOTP prefix -- treat whole thing as command (will be rejected
        # for modifying commands, allowed for read-only if no TOTP is needed)
        return None, raw

    first, rest = parts[0], parts[1]
    if first.isdigit() and len(first) == 6:
        return first, rest

    # First token doesn't look like TOTP
    return None, raw


def validate_totp(code: str, secret: str) -> bool:
    """Validate a TOTP code against the secret.

    Uses pyotp for validation with +/-1 step tolerance (30s before/after).
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=0)
    except ImportError:
        # Fallback: pyotp not installed on server, reject
        return False
    except Exception:
        return False


def get_secret() -> str | None:
    """Read the TOTP secret from the configured path."""
    try:
        with open(TOTP_SECRET_PATH) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None
    except Exception:
        return None


def main() -> None:
    """Main entry point -- invoked by SSH forced-command."""
    raw_input = os.environ.get("SSH_ORIGINAL_COMMAND", " ".join(sys.argv[1:]))

    if not raw_input:
        print("REJECTED: no command provided", file=sys.stderr)
        sys.exit(1)

    totp_code, command = parse_ssh_command_input(raw_input)

    # Check unconditional blocklist first
    if SERVER_SIDE_BLOCKED(command):
        print(f"REJECTED: command matches unconditionally blocked pattern", file=sys.stderr)
        sys.exit(1)

    # Determine if this is a modifying command using module-level read-only patterns
    is_ro = any(re.search(p, command) for p in _READONLY_PATTERNS)

    if not is_ro:
        # Modifying command -- TOTP required
        if not totp_code:
            print("REJECTED: modifying command requires TOTP code", file=sys.stderr)
            sys.exit(1)

        secret = get_secret()
        if not secret:
            print("REJECTED: TOTP secret not configured on this server", file=sys.stderr)
            sys.exit(1)

        if not validate_totp(totp_code, secret):
            print("REJECTED: invalid or expired TOTP code", file=sys.stderr)
            sys.exit(1)

    # Set category based on read-only classification
    category = "readonly" if is_ro else "modifying"
    approved = True

    # Execute
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        _write_audit_entry(command, category, approved, result.returncode,
                           result.stdout, result.stderr)
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        _write_audit_entry(command, category, approved, -1, "", "Command timed out")
        print("REJECTED: command timed out", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        _write_audit_entry(command, category, approved, -1, "", str(e))
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
