"""Command parser — splits chained commands and blocks injection patterns."""

import re


class CommandSecurityError(Exception):
    """Raised when a command contains a blocked shell pattern."""
    pass


# Patterns that are always blocked regardless of context
BLOCKED_PATTERNS: list[tuple[str, str]] = [
    # Subshell execution
    (r"\$\(.*\)", "Command substitution $() is blocked"),
    # Backtick execution
    (r"`[^`]*`", "backtick substitution is blocked"),
    # eval / exec builtins
    (r"\beval\b", "'eval' builtin is blocked"),
    (r"\bexec\b", "'exec' builtin is blocked"),
    # Dangerous redirects to device files
    (r">\s*/dev/(sd[a-z]+|nvme\d+n\d+|mmcblk\d+)", "Redirect to block device is blocked"),
    # Source /dev/tcp reverse shells (defense in depth)
    (r"/dev/tcp/", "/dev/tcp reverse shell pattern blocked"),
]


def parse_command(command: str) -> list[str]:
    """Split a command string on `&&`, `||`, `;` into individual commands.

    Pipes (`|`) within a single command are preserved as one unit.
    Does NOT split inside quoted strings.
    """
    if not command or not command.strip():
        return []

    # Use a simple state-machine split that respects quoting
    parts: list[str] = []
    current: list[str] = []
    quote_char: str | None = None
    i = 0
    chars = list(command)

    while i < len(chars):
        ch = chars[i]

        # Handle quotes
        if ch in ("'", '"') and quote_char is None:
            quote_char = ch
            current.append(ch)
            i += 1
            continue
        elif ch == quote_char:
            quote_char = None
            current.append(ch)
            i += 1
            continue

        # Inside quotes, just accumulate
        if quote_char is not None:
            current.append(ch)
            i += 1
            continue

        # Check for && separator
        if ch == "&" and i + 1 < len(chars) and chars[i + 1] == "&":
            parts.append("".join(current).strip())
            current = []
            i += 2
            continue

        # Check for || separator (but not | alone — that's a pipe)
        if ch == "|" and i + 1 < len(chars) and chars[i + 1] == "|":
            parts.append("".join(current).strip())
            current = []
            i += 2
            continue

        # Check for ; separator
        if ch == ";":
            parts.append("".join(current).strip())
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    remainder = "".join(current).strip()
    if remainder:
        parts.append(remainder)

    return [p for p in parts if p]


def validate_commands(commands: list[str]) -> tuple[bool, str]:
    """Check all commands against blocked patterns.

    Returns (is_safe, reason). If is_safe is False, reason explains why.
    """
    for cmd in commands:
        cmd_normalized = cmd.strip()
        for pattern, message in BLOCKED_PATTERNS:
            if re.search(pattern, cmd_normalized):
                return False, f"Blocked: {message} (in command: {cmd_normalized[:80]})"
    return True, ""
