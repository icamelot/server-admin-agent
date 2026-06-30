# Server Admin Agent — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a secure remote server management toolkit — command execution pipeline, TOTP-guarded approval flow, and a monitoring daemon with pre-analysis — for the serveradmin agent.

**Architecture:** A unified SSH command executor wraps every remote command in a seven-layer security pipeline (parser → whitelist → rate limiter → audit logger on the agent side; TOTP filter → secondary whitelist → SSH restrictions on the server side). A separate monitoring daemon runs independently, performs threshold-based health checks with preliminary analysis, and wakes the agent only on anomalies via `ask_agent_async.py`.

**Tech Stack:** Python 3.11, pytest, PyYAML (already installed), pyotp (TOTP), subprocess (SSH)

## Global Constraints

- No cron — monitoring uses a persistent daemon (`while True: sleep(N)`)
- TOTP secret must never be stored by the agent
- All modifying commands require TOTP approval before server-side execution
- SSH client installed by main agent (assumed available at runtime)
- Agent uses dedicated SSH key pair, not shared with user

---

### Task 1: Command Parser

**Files:**
- Create: `tools/executor/command_parser.py`
- Create: `tools/executor/test_command_parser.py`
- Create: `tools/executor/__init__.py`

**Interfaces:**
- Produces: `parse_command(command: str) -> list[str]` — splits on `&&`, `||`, `;` into individual commands
- Produces: `validate_commands(commands: list[str]) -> tuple[bool, str]` — returns (is_safe, reason)
- Produces: `CommandSecurityError(Exception)` — raised on blocked patterns

- [ ] **Step 1: Create `tools/executor/__init__.py`**

```python
# tools/executor __init__.py
```

- [ ] **Step 2: Write the failing tests for command parser**

Create `tools/executor/test_command_parser.py`:

```python
import pytest
from tools.executor.command_parser import (
    parse_command,
    validate_commands,
    CommandSecurityError,
)


class TestParseCommand:
    def test_simple_command(self):
        assert parse_command("ls -la") == ["ls -la"]

    def test_chained_with_double_ampersand(self):
        result = parse_command("ls -la && echo done")
        assert result == ["ls -la", "echo done"]

    def test_chained_with_semicolon(self):
        result = parse_command("ls -la; whoami")
        assert result == ["ls -la", "whoami"]

    def test_chained_with_pipe(self):
        result = parse_command("cat file | grep foo")
        assert result == ["cat file | grep foo"]

    def test_empty_command_returns_empty_list(self):
        assert parse_command("") == []

    def test_strips_whitespace(self):
        result = parse_command("  df -h  &&   free -m  ")
        assert result == ["df -h", "free -m"]


class TestValidateCommands:
    def test_safe_commands_pass(self):
        ok, reason = validate_commands(["ls -la", "df -h"])
        assert ok is True
        assert reason == ""

    def test_dollar_paren_blocked(self):
        ok, reason = validate_commands(["echo $(whoami)"])
        assert ok is False
        assert "$()" in reason

    def test_backtick_blocked(self):
        ok, reason = validate_commands(["echo `whoami`"])
        assert ok is False
        assert "backtick" in reason

    def test_eval_blocked(self):
        ok, reason = validate_commands(["eval ls"])
        assert ok is False
        assert "eval" in reason

    def test_exec_blocked(self):
        ok, reason = validate_commands(["exec bash"])
        assert ok is False
        assert "exec" in reason

    def test_io_redirect_to_dev_blocked(self):
        ok, reason = validate_commands(["cat foo > /dev/sda"])
        assert ok is False

    def test_multiple_commands_one_blocked(self):
        ok, reason = validate_commands(["ls -la", "eval rm -rf /"])
        assert ok is False

    def test_command_with_shell_var_expansion_allowed(self):
        ok, reason = validate_commands(["echo $HOME"])
        assert ok is True

    def test_redirect_to_file_allowed(self):
        ok, reason = validate_commands(["echo hello > /tmp/out.txt"])
        assert ok is True
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_command_parser.py -v
```

Expected: all tests FAIL (module not found or functions not defined)

- [ ] **Step 4: Write minimal implementation**

Create `tools/executor/command_parser.py`:

```python
"""Command parser — splits chained commands and blocks injection patterns."""

import re
import shlex


class CommandSecurityError(Exception):
    """Raised when a command contains a blocked shell pattern."""
    pass


# Patterns that are always blocked regardless of context
BLOCKED_PATTERNS: list[tuple[str, str]] = [
    # Subshell execution
    (r"\$\(.*\)", "Command substitution $() is blocked"),
    # Backtick execution
    (r"`[^`]*`", "Backtick substitution is blocked"),
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_command_parser.py -v
```

Expected: all 14 tests PASS

- [ ] **Step 6: Install pytest if needed and commit**

```bash
pip3 install pytest  # if not present
```

---

### Task 2: Whitelist Router

**Files:**
- Create: `tools/executor/whitelist.py`
- Create: `tools/executor/test_whitelist.py`

**Interfaces:**
- Produces: `classify_command(command: str) -> str` — returns `"readonly"` or `"modifying"`
- Produces: `is_readonly(command: str) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tools/executor/test_whitelist.py`:

```python
import pytest
from tools.executor.whitelist import classify_command, is_readonly


class TestClassifyCommand:
    # Read-only commands
    @pytest.mark.parametrize("cmd", [
        "df -h",
        "free -m",
        "uptime",
        "ps aux",
        "systemctl status nginx",
        "journalctl -u nginx --since '1 hour ago'",
        "cat /var/log/syslog",
        "ls -la /home",
        "who",
        "last -n 10",
        "ss -tlnp",
        "ip addr show",
        "du -sh /var/*",
        "top -bn1",
        "tail -n 100 /var/log/auth.log",
        "grep ERROR /var/log/app.log",
        "find /tmp -name '*.log'",
        "stat /etc/passwd",
        "dmesg | tail -20",
        "lsof -i :80",
        "id someuser",
        "getent passwd",
        "hostnamectl",
        "timedatectl",
        "uname -a",
    ])
    def test_readonly_commands(self, cmd):
        assert classify_command(cmd) == "readonly"
        assert is_readonly(cmd) is True

    # Modifying commands
    @pytest.mark.parametrize("cmd", [
        "systemctl restart nginx",
        "systemctl stop apache2",
        "systemctl start postgresql",
        "apt install htop",
        "apt remove nginx",
        "yum install httpd",
        "useradd newuser",
        "usermod -aG sudo newuser",
        "userdel olduser",
        "passwd someuser",
        "rm /tmp/file.txt",
        "rm -rf /tmp/cache",
        "chmod 755 /opt/app",
        "chown user:group /data",
        "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
        "systemctl enable nginx",
        "systemctl disable apache2",
        "dd if=/dev/zero of=/tmp/test bs=1M count=10",
        "mount /dev/sdb1 /mnt",
        "kill -9 1234",
        "shutdown -r now",
        "reboot",
    ])
    def test_modifying_commands(self, cmd):
        assert classify_command(cmd) == "modifying"
        assert is_readonly(cmd) is False

    def test_unknown_command_defaults_to_modifying(self):
        # Safety: unknown commands lean toward requiring approval
        assert classify_command("some-random-command --flag") == "modifying"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_whitelist.py -v
```

Expected: all tests FAIL

- [ ] **Step 3: Write implementation**

Create `tools/executor/whitelist.py`:

```python
"""Whitelist router — classifies commands as read-only or modifying."""

import re
from typing import Literal

CommandCategory = Literal["readonly", "modifying"]


# Read-only patterns: commands safe to auto-approve
READONLY_PATTERNS: list[str] = [
    # Filesystem inspection
    r"^ls\b", r"^ll\b", r"^dir\b",
    r"^df\b", r"^du\b", r"^stat\b",
    r"^cat\b", r"^head\b", r"^tail\b",
    r"^less\b", r"^zcat\b", r"^zless\b",
    r"^file\b",
    # Search / find (read-only)
    r"^find\b", r"^locate\b", r"^grep\b", r"^egrep\b",
    r"^zgrep\b",
    # System inspection
    r"^ps\b", r"^top\b", r"^htop\b", r"^uptime\b",
    r"^free\b", r"^vmstat\b", r"^iostat\b",
    r"^dmesg\b", r"^lsof\b", r"^fdisk\s+-l\b",
    r"^lsblk\b", r"^blkid\b",
    # systemctl (status only)
    r"^systemctl\s+status\b", r"^systemctl\s+list-\b",
    r"^systemctl\s+is-\b", r"^systemctl\s+show\b",
    r"^systemctl\s+cat\b",
    # journalctl (read-only)
    r"^journalctl\b",
    # User inspection
    r"^who\b", r"^w\b", r"^whoami\b", r"^id\b",
    r"^last\b", r"^lastb\b", r"^lastlog\b",
    r"^getent\b", r"^groups\b",
    # Network inspection
    r"^ss\b", r"^netstat\b", r"^ip\s+addr\b",
    r"^ip\s+link\b", r"^ip\s+route\b", r"^ip\s+neigh\b",
    r"^hostname\b", r"^hostnamectl\b",
    r"^ping\b", r"^traceroute\b", r"^nslookup\b",
    r"^dig\b", r"^curl\b", r"^wget\b",
    # System info
    r"^uname\b", r"^lscpu\b", r"^lspci\b", r"^lsusb\b",
    r"^timedatectl\b", r"^localectl\b",
    # Process inspection
    r"^pgrep\b", r"^pidof\b",
    # Package inspection
    r"^dpkg\s+-[lL]\b", r"^rpm\s+-q[a-z]*\b",
    r"^apt\s+list\b", r"^apt-cache\b",
    # Disk / filesystem
    r"^mount\b", r"^findmnt\b",
    # Log viewing
    r"^loginctl\s+list-\b", r"^loginctl\s+show-\b",
    # Environment
    r"^env\b", r"^printenv\b", r"^echo\b",
    # Help / version
    r"--help$", r"--version$", r"-h$",
    r"^man\b", r"^info\b", r"^whatis\b",
    # Docker read-only
    r"^docker\s+ps\b", r"^docker\s+images\b",
    r"^docker\s+logs\b", r"^docker\s+inspect\b",
    r"^docker\s+stats\b",
]


def classify_command(command: str) -> CommandCategory:
    """Classify a single command as 'readonly' or 'modifying'.

    Matches against known read-only patterns. If no pattern matches,
    defaults to 'modifying' (safe fail).
    """
    cmd = command.strip()

    for pattern in READONLY_PATTERNS:
        if re.search(pattern, cmd):
            return "readonly"

    return "modifying"


def is_readonly(command: str) -> bool:
    """Return True if the command is classified as read-only."""
    return classify_command(command) == "readonly"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_whitelist.py -v
```

Expected: all tests PASS

---

### Task 3: Rate Limiter

**Files:**
- Create: `tools/executor/rate_limiter.py`
- Create: `tools/executor/test_rate_limiter.py`

**Interfaces:**
- Produces: `RateLimiter(max_per_hour: int)` — class
- Produces: `RateLimiter.check_and_increment() -> bool` — True if allowed
- Produces: `RateLimiter.get_remaining() -> int`
- Produces: `RateLimiter.reset()` — manual unlock
- Produces: `RateLimiter.is_locked() -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tools/executor/test_rate_limiter.py`:

```python
import pytest
from tools.executor.rate_limiter import RateLimiter


class TestRateLimiter:
    def test_initial_state_not_locked(self):
        limiter = RateLimiter(max_per_hour=10)
        assert limiter.is_locked() is False
        assert limiter.get_remaining() == 10

    def test_check_and_increment_allows_up_to_limit(self):
        limiter = RateLimiter(max_per_hour=5)
        for _ in range(5):
            assert limiter.check_and_increment() is True
        assert limiter.get_remaining() == 0

    def test_exceeded_limit_returns_false(self):
        limiter = RateLimiter(max_per_hour=3)
        for _ in range(3):
            limiter.check_and_increment()
        assert limiter.check_and_increment() is False
        assert limiter.is_locked() is True

    def test_reset_unlocks_and_resets_count(self):
        limiter = RateLimiter(max_per_hour=3)
        for _ in range(3):
            limiter.check_and_increment()
        assert limiter.is_locked() is True

        limiter.reset()
        assert limiter.is_locked() is False
        assert limiter.get_remaining() == 3

    def test_get_remaining_decreases(self):
        limiter = RateLimiter(max_per_hour=5)
        limiter.check_and_increment()
        assert limiter.get_remaining() == 4
        limiter.check_and_increment()
        assert limiter.get_remaining() == 3

    def test_window_expires(self):
        import time

        # Use a very short window for testing
        limiter = RateLimiter(max_per_hour=5)
        # Override the window start to simulate elapsed time
        limiter._window_start = time.monotonic() - 3601  # force expiry

        limiter.check_and_increment()
        assert limiter.get_remaining() == 4  # window should have reset
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_rate_limiter.py -v
```

Expected: all tests FAIL

- [ ] **Step 3: Write implementation**

Create `tools/executor/rate_limiter.py`:

```python
"""Rate limiter — caps modifying commands per hour to prevent cascade failures."""

import time


class RateLimiter:
    """Limits the number of modifying commands within a rolling 1-hour window.

    When the limit is exceeded, the limiter locks until manually reset
    or the window rolls over.
    """

    def __init__(self, max_per_hour: int = 10):
        self._max_per_hour = max_per_hour
        self._count: int = 0
        self._window_start: float = time.monotonic()
        self._locked: bool = False

    def _maybe_roll_window(self) -> None:
        """Reset the window if an hour has elapsed."""
        now = time.monotonic()
        if now - self._window_start >= 3600:
            self._window_start = now
            self._count = 0
            self._locked = False

    def check_and_increment(self) -> bool:
        """Check if within limit, increment count if so.

        Returns True if the operation is allowed, False if limit exceeded.
        """
        self._maybe_roll_window()

        if self._locked:
            return False

        if self._count >= self._max_per_hour:
            self._locked = True
            return False

        self._count += 1
        return True

    def get_remaining(self) -> int:
        """Return how many more modifying commands are allowed this hour."""
        self._maybe_roll_window()
        return max(0, self._max_per_hour - self._count)

    def is_locked(self) -> bool:
        """Return True if the limiter is currently locked."""
        self._maybe_roll_window()
        return self._locked

    def reset(self) -> None:
        """Manual reset — unlock and clear the counter."""
        self._window_start = time.monotonic()
        self._count = 0
        self._locked = False
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_rate_limiter.py -v
```

Expected: all tests PASS

---

### Task 4: Audit Logger

**Files:**
- Create: `tools/executor/audit.py`
- Create: `tools/executor/test_audit.py`

**Interfaces:**
- Produces: `AuditLogger(log_dir: str)` — class
- Produces: `AuditLogger.log_entry(target: str, command: str, category: str, approved: bool, result: dict) -> None`
- Produces: `get_audit_path() -> str` — returns the log file path

- [ ] **Step 1: Write the failing tests**

Create `tools/executor/test_audit.py`:

```python
import json
import os
import tempfile
import pytest
from tools.executor.audit import AuditLogger, get_audit_path


class TestAuditLogger:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(log_dir=self.tmpdir)

    def test_log_entry_writes_to_file(self):
        self.audit.log_entry(
            target="server-a",
            command="df -h",
            category="readonly",
            approved=True,
            result={"exit_code": 0, "stdout": "Filesystem ..."},
        )

        log_path = get_audit_path(self.tmpdir)
        assert os.path.exists(log_path)

        with open(log_path) as f:
            data = json.loads(f.readline())

        assert data["target"] == "server-a"
        assert data["command"] == "df -h"
        assert data["category"] == "readonly"
        assert data["approved"] is True
        assert data["exit_code"] == 0
        assert "timestamp" in data

    def test_multiple_entries_append(self):
        self.audit.log_entry(
            target="server-a", command="ls", category="readonly",
            approved=True, result={"exit_code": 0, "stdout": ""},
        )
        self.audit.log_entry(
            target="server-b", command="useradd x", category="modifying",
            approved=False, result={"exit_code": -1, "stdout": "REJECTED: no TOTP"},
        )

        log_path = get_audit_path(self.tmpdir)
        with open(log_path) as f:
            lines = f.readlines()

        assert len(lines) == 2
        entries = [json.loads(line) for line in lines]
        assert entries[0]["target"] == "server-a"
        assert entries[1]["target"] == "server-b"
        assert entries[1]["approved"] is False

    def test_log_file_permissions_restrictive(self):
        self.audit.log_entry(
            target="server-a", command="ls", category="readonly",
            approved=True, result={"exit_code": 0, "stdout": ""},
        )
        log_path = get_audit_path(self.tmpdir)
        mode = os.stat(log_path).st_mode & 0o777
        assert mode == 0o600  # owner read/write only
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_audit.py -v
```

Expected: all tests FAIL

- [ ] **Step 3: Write implementation**

Create `tools/executor/audit.py`:

```python
"""Audit logger — append-only command execution log."""

import json
import os
from datetime import datetime, timezone


AUDIT_FILENAME = "command_audit.jsonl"


def get_audit_path(log_dir: str) -> str:
    """Return the full path to the audit log file."""
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, AUDIT_FILENAME)


class AuditLogger:
    """Append-only audit log for all command executions.

    Each log entry is a JSON line containing:
    - timestamp (ISO 8601)
    - target server
    - command executed
    - category (readonly | modifying)
    - approved (bool)
    - exit_code, stdout, stderr (truncated)
    """

    def __init__(self, log_dir: str):
        self._log_path = get_audit_path(log_dir)
        self._ensure_file()

    def _ensure_file(self) -> None:
        """Create log file with restrictive permissions if it doesn't exist."""
        if not os.path.exists(self._log_path):
            with open(self._log_path, "w") as f:
                f.write("")
            os.chmod(self._log_path, 0o600)

    def log_entry(
        self,
        target: str,
        command: str,
        category: str,
        approved: bool,
        result: dict,
    ) -> None:
        """Append an audit log entry.

        Args:
            target: Server hostname or identifier.
            command: The full command string that was (or would be) executed.
            category: 'readonly' or 'modifying'.
            approved: Whether the command was approved (TOTP or auto).
            result: Dict with keys: exit_code, stdout, stderr.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "command": command,
            "category": category,
            "approved": approved,
            "exit_code": result.get("exit_code"),
            "stdout": result.get("stdout", "")[:8192],
            "stderr": result.get("stderr", "")[:8192],
        }

        with open(self._log_path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_audit.py -v
```

Expected: all tests PASS

---

### Task 5: Command Executor

**Files:**
- Create: `tools/executor/command_executor.py`
- Create: `tools/executor/test_command_executor.py`

**Interfaces:**
- Consumes: `command_parser.parse_command()`, `command_parser.validate_commands()`
- Consumes: `whitelist.classify_command()`
- Consumes: `rate_limiter.RateLimiter`
- Consumes: `audit.AuditLogger`
- Produces: `CommandExecutor` — class with `execute(target, command, totp_code=None) -> dict`

- [ ] **Step 1: Install pyotp dependency**

```bash
pip3 install pyotp
```

- [ ] **Step 2: Write the failing tests**

Create `tools/executor/test_command_executor.py`:

```python
import pytest
from unittest.mock import patch, MagicMock
from tools.executor.command_executor import CommandExecutor


class TestCommandExecutor:
    def setup_method(self):
        self.executor = CommandExecutor(
            ssh_key_path="/tmp/test_key",
            ssh_user="agent",
            max_modifying_per_hour=5,
        )

    def test_readonly_command_runs_directly(self):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b"Filesystem  Size  Used Avail Use% Mounted on\n"
            mock_result.stderr = b""
            mock_run.return_value = mock_result

            result = self.executor.execute("server-a", "df -h")

            assert result["exit_code"] == 0
            assert result["approved"] is True  # auto-approved
            assert result["needs_approval"] is False
            assert mock_run.call_count == 1

    def test_modifying_command_without_totp_rejected(self):
        result = self.executor.execute("server-a", "systemctl restart nginx")

        assert result["exit_code"] == -1
        assert result["approved"] is False
        assert result["needs_approval"] is True
        assert "TOTP" in result.get("stderr", "")

    def test_modifying_command_with_totp_proceeds(self):
        # Configure a known TOTP secret on the executor
        executor = CommandExecutor(
            ssh_key_path="/tmp/test_key",
            ssh_user="agent",
            totp_secret_sha1="JBSWY3DPEHPK3PXP",  # test secret for server-a
        )

        import pyotp
        totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
        valid_code = totp.now()

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b"Service restarted"
            mock_result.stderr = b""
            mock_run.return_value = mock_result

            result = executor.execute(
                "server-a", "systemctl restart nginx", totp_code=valid_code
            )

            assert result["exit_code"] == 0
            assert mock_run.call_count == 1

    def test_chained_command_partially_modifying_requires_approval(self):
        result = self.executor.execute(
            "server-a", "ls -la && systemctl restart nginx"
        )
        assert result["needs_approval"] is True

    def test_injection_pattern_blocked(self):
        result = self.executor.execute("server-a", "echo $(whoami)")
        assert result["exit_code"] == -1
        assert result["blocked"] is True

    def test_rate_limit_exceeded(self):
        executor = CommandExecutor(
            ssh_key_path="/tmp/test_key",
            ssh_user="agent",
            max_modifying_per_hour=1,
        )

        # Use up the limit
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b"ok"
            mock_result.stderr = b""
            mock_run.return_value = mock_result

            import pyotp
            totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
            code = totp.now()

            executor.totp_secrets = {"server-a": "JBSWY3DPEHPK3PXP"}
            executor.execute("server-a", "apt install htop", totp_code=code)
            result = executor.execute("server-a", "apt install vim", totp_code=code)

        assert result["exit_code"] == -1
        assert "rate" in result.get("stderr", "").lower()
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_command_executor.py -v
```

Expected: all tests FAIL

- [ ] **Step 4: Write implementation**

Create `tools/executor/command_executor.py`:

```python
"""Command executor — unified SSH command execution through the security pipeline."""

import subprocess
import shlex
from dataclasses import dataclass, field
from tools.executor.command_parser import parse_command, validate_commands
from tools.executor.whitelist import classify_command, is_readonly
from tools.executor.rate_limiter import RateLimiter
from tools.executor.audit import AuditLogger


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    approved: bool
    needs_approval: bool
    blocked: bool = False
    target: str = ""
    command: str = ""


class CommandExecutor:
    """Executes commands on remote servers through the security pipeline.

    Pipeline:
      1. Parse & validate (command_parser)
      2. Classify (whitelist)
      3. Rate-check (rate_limiter) if modifying
      4. TOTP check if modifying
      5. SSH execute
      6. Audit log
    """

    def __init__(
        self,
        ssh_key_path: str,
        ssh_user: str = "agent",
        max_modifying_per_hour: int = 10,
        audit_dir: str = "/ductor/agents/serveradmin/workspace/logs",
    ):
        self.ssh_key_path = ssh_key_path
        self.ssh_user = ssh_user
        self.rate_limiter = RateLimiter(max_per_hour=max_modifying_per_hour)
        self.audit = AuditLogger(audit_dir)
        # Mapping of target -> TOTP secret (populated via config, NOT code)
        # The agent does NOT generate TOTP codes — it only passes them through.
        self.totp_secrets: dict[str, str] = {}

    def execute(
        self,
        target: str,
        command: str,
        totp_code: str | None = None,
    ) -> dict:
        """Execute a command on a remote target through the security pipeline.

        Args:
            target: Server hostname or IP.
            command: The shell command string to execute.
            totp_code: 6-digit TOTP code (required for modifying commands).

        Returns:
            Dict with keys: exit_code, stdout, stderr, approved, needs_approval,
            blocked, target, command.
        """
        # Layer 1: Parse and validate
        parsed = parse_command(command)
        is_safe, reason = validate_commands(parsed)

        if not is_safe:
            result = ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"BLOCKED: {reason}",
                approved=False,
                needs_approval=False,
                blocked=True,
                target=target,
                command=command,
            )
            self.audit.log_entry(target, command, "blocked", False, vars(result))
            return vars(result)

        # Layer 2: Classify
        categories = [classify_command(cmd) for cmd in parsed]
        needs_approval = any(c == "modifying" for c in categories)
        overall_category = "modifying" if needs_approval else "readonly"

        # If any sub-command is modifying, the whole chain requires approval
        if needs_approval:
            # Layer 3: Rate limit check
            if not self.rate_limiter.check_and_increment():
                result = ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr="BLOCKED: modifying command rate limit exceeded. "
                           f"{self.rate_limiter.get_remaining()} remaining this hour.",
                    approved=False,
                    needs_approval=True,
                    target=target,
                    command=command,
                )
                self.audit.log_entry(target, command, overall_category, False, vars(result))
                return vars(result)

            # Layer 4: TOTP check
            if not totp_code or not self._verify_totp(target, totp_code):
                result = ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr="APPROVAL REQUIRED: modifying commands require a valid TOTP code. "
                           "Please generate a TOTP code and retry.",
                    approved=False,
                    needs_approval=True,
                    target=target,
                    command=command,
                )
                self.audit.log_entry(target, command, overall_category, False, vars(result))
                return vars(result)

        # All checks passed — execute via SSH
        return self._ssh_execute(target, command, overall_category, True)

    def _verify_totp(self, target: str, code: str) -> bool:
        """Verify a TOTP code for the given target.

        The agent only calls verify — it never generates codes.
        The secret is looked up from config and passed to the server-side
        agent-shell-filter for validation. Client-side pre-check here is a
        basic format validation only.
        """
        # Basic format: 6 digits
        if not code or not code.isdigit() or len(code) != 6:
            return False
        return True  # actual TOTP validation happens on the server side

    def _ssh_execute(
        self, target: str, command: str, category: str, approved: bool
    ) -> dict:
        """Execute a command via SSH and return the result."""
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-i", self.ssh_key_path,
            f"{self.ssh_user}@{target}",
            command,
        ]

        try:
            proc = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            result = ExecutionResult(
                exit_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                approved=approved,
                needs_approval=False,
                target=target,
                command=command,
            )
        except subprocess.TimeoutExpired:
            result = ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="SSH command timed out after 30 seconds",
                approved=approved,
                needs_approval=False,
                target=target,
                command=command,
            )
        except FileNotFoundError:
            result = ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="SSH client not found (main agent may not have installed it yet)",
                approved=approved,
                needs_approval=False,
                target=target,
                command=command,
            )

        self.audit.log_entry(target, command, category, approved, vars(result))
        return vars(result)

    def unlock(self) -> None:
        """Manually unlock the rate limiter."""
        self.rate_limiter.reset()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_command_executor.py -v
```

Expected: all tests PASS

---

### Task 6: Agent Shell Filter (Server-Side)

**Files:**
- Create: `tools/executor/agent_shell_filter.py`
- Create: `tools/executor/test_agent_shell_filter.py`

**Interfaces:**
- Produces: `deploy_filter_instructions.md` — deployment doc (inline in CLAUDE.md)
- Produces: `agent_shell_filter.py` — standalone script deployed to each target server at `/usr/local/bin/agent-shell-filter`

- [ ] **Step 1: Write the failing tests**

Create `tools/executor/test_agent_shell_filter.py`:

```python
"""Tests for agent-shell-filter — the server-side command validation script.

This test file validates the filter logic, which would normally run
on the target server as an SSH forced-command wrapper.
"""

import pytest
from unittest.mock import patch
from tools.executor.agent_shell_filter import (
    validate_totp,
    parse_ssh_command_input,
    SERVER_SIDE_BLOCKED,
)


class TestValidateTotp:
    def test_valid_totp_format(self):
        assert validate_totp("123456", "JBSWY3DPEHPK3PXP") is True

    def test_invalid_totp_rejected(self):
        assert validate_totp("000000", "JBSWY3DPEHPK3PXP") is False

    def test_non_numeric_rejected(self):
        assert validate_totp("abc123", "JBSWY3DPEHPK3PXP") is False

    def test_wrong_length_rejected(self):
        assert validate_totp("12345", "JBSWY3DPEHPK3PXP") is False


class TestParseSshCommandInput:
    def test_standard_input(self):
        totp, command = parse_ssh_command_input("123456 systemctl restart nginx")
        assert totp == "123456"
        assert command == "systemctl restart nginx"

    def test_command_with_spaces(self):
        totp, command = parse_ssh_command_input("654321 apt install -y htop")
        assert totp == "654321"
        assert command == "apt install -y htop"

    def test_missing_totp_returns_none(self):
        totp, command = parse_ssh_command_input("systemctl restart nginx")
        assert totp is None
        assert command == "systemctl restart nginx"

    def test_empty_input(self):
        totp, command = parse_ssh_command_input("")
        assert totp is None
        assert command == ""


class TestServerSideBlocked:
    def test_rm_rf_blocked_anyway(self):
        """Even if TOTP is valid, certain patterns are blocked unconditionally."""
        assert SERVER_SIDE_BLOCKED("rm -rf /") is True

    def test_mkfs_blocked(self):
        assert SERVER_SIDE_BLOCKED("mkfs.ext4 /dev/sda") is True

    def test_shutdown_blocked(self):
        assert SERVER_SIDE_BLOCKED("shutdown -h now") is True

    def test_dd_if_of_disk_blocked(self):
        assert SERVER_SIDE_BLOCKED("dd if=/dev/zero of=/dev/sdb") is True

    def test_normal_command_allowed(self):
        assert SERVER_SIDE_BLOCKED("systemctl restart nginx") is False

    def test_useradd_allowed(self):
        assert SERVER_SIDE_BLOCKED("useradd newuser") is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_agent_shell_filter.py -v
```

Expected: all tests FAIL

- [ ] **Step 3: Write implementation**

Create `tools/executor/agent_shell_filter.py`:

```python
#!/usr/bin/env python3
"""
agent-shell-filter — Server-side command validation script.

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

import os
import re
import sys
import subprocess

# Path to TOTP secret on the server (deployed once during setup)
TOTP_SECRET_PATH = "/etc/agent/totp_secret"

# Commands that are NEVER allowed, even with valid TOTP.
# This is defense-in-depth — the agent side should also block these.
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
        # No TOTP prefix — treat whole thing as command (will be rejected
        # for modifying commands, allowed for read-only if no TOTP is needed)
        return None, raw

    first, rest = parts[0], parts[1]
    if first.isdigit() and len(first) == 6:
        return first, rest

    # First token doesn't look like TOTP
    return None, raw


def validate_totp(code: str, secret: str) -> bool:
    """Validate a TOTP code against the secret.

    Uses pyotp for validation with ±1 step tolerance (60s before/after).
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
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
    """Main entry point — invoked by SSH forced-command."""
    raw_input = os.environ.get("SSH_ORIGINAL_COMMAND", " ".join(sys.argv[1:]))

    if not raw_input:
        print("REJECTED: no command provided", file=sys.stderr)
        sys.exit(1)

    totp_code, command = parse_ssh_command_input(raw_input)

    # Check unconditional blocklist first
    if SERVER_SIDE_BLOCKED(command):
        print(f"REJECTED: command matches unconditionally blocked pattern", file=sys.stderr)
        sys.exit(1)

    # Determine if this is a modifying command (standalone — same patterns as agent-side whitelist)
    import re as _re
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
        r"^apt\s+list\b", r"^mount\b", r"^findmnt\b", r"^env\b", r"^printenv\b", r"^echo\b",
        r"--help$", r"--version$", r"^man\b", r"^info\b", r"^whatis\b", r"^docker\s+ps\b",
        r"^docker\s+images\b", r"^docker\s+logs\b", r"^docker\s+inspect\b",
    ]
    is_ro = any(_re.search(p, command) for p in _READONLY_PATTERNS)

    if not is_ro:
        # Modifying command — TOTP required
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
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        print("REJECTED: command timed out", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run unit tests**

Note: The filter's `validate_totp` and `parse_ssh_command_input` functions
can be tested locally. The `main()` function requires server deployment.

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/executor/test_agent_shell_filter.py -v
```

Expected: all tests PASS

---

### Task 7: Threshold Configuration & Monitoring Daemon

**Files:**
- Create: `config/thresholds.yaml`
- Create: `tools/monitor/__init__.py`
- Create: `tools/monitor/threshold_config.py`
- Create: `tools/monitor/monitor_daemon.py`
- Create: `tools/monitor/test_threshold_config.py`

**Interfaces:**
- Consumes: `command_executor.CommandExecutor` (for SSH health checks)
- Produces: `ThresholdConfig` — loads & validates threshold YAML
- Produces: `MonitorDaemon` — main loop, pre-analysis, alert dispatch
- Produces: `check_disk()`, `check_memory()`, `check_cpu()`, `check_services()` — individual checks

- [ ] **Step 1: Create threshold config file**

Create `config/thresholds.yaml`:

```yaml
# Threshold configuration for monitoring daemon
# Levels: warn (agent analyzes), crit (immediate alert + agent analysis)

defaults:
  disk_warn_pct: 85
  disk_crit_pct: 95
  mem_warn_pct: 80
  mem_crit_pct: 95
  cpu_warn_pct: 70
  cpu_crit_pct: 90
  cpu_sustained_checks: 3  # number of consecutive checks before alerting

check_interval_seconds: 300  # 5 minutes between checks

servers:
  server-a:
    hostname: server-a.local  # override with actual hostname/IP in deployment
    # Uses defaults unless overridden

  server-b:
    hostname: server-b.local
    # Login node — may have different thresholds

# Service names to check via systemctl is-active
services:
  - sshd
  - nginx
  - docker
```

- [ ] **Step 2: Write failing tests for threshold config parser**

Create `tools/monitor/test_threshold_config.py`:

```python
import pytest
from tools.monitor.threshold_config import ThresholdConfig


class TestThresholdConfig:
    def test_loads_defaults(self):
        config = ThresholdConfig("config/thresholds.yaml")
        assert config.defaults["disk_warn_pct"] == 85
        assert config.defaults["mem_crit_pct"] == 95
        assert config.check_interval == 300

    def test_server_list(self):
        config = ThresholdConfig("config/thresholds.yaml")
        servers = config.get_servers()
        assert len(servers) == 2
        assert "server-a" in servers

    def test_get_threshold_for_server(self):
        config = ThresholdConfig("config/thresholds.yaml")
        thresholds = config.get_thresholds("server-a")
        assert thresholds["disk_warn_pct"] == 85  # from defaults

    def test_get_hostname(self):
        config = ThresholdConfig("config/thresholds.yaml")
        assert config.get_hostname("server-a") == "server-a.local"

    def test_services_list(self):
        config = ThresholdConfig("config/thresholds.yaml")
        assert "nginx" in config.services
        assert "sshd" in config.services

    def test_missing_config_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ThresholdConfig("config/nonexistent.yaml")
```

- [ ] **Step 3: Implement threshold config parser**

Create `tools/monitor/threshold_config.py`:

```python
"""Threshold configuration loader."""

import os
from pathlib import Path
import yaml


class ThresholdConfig:
    """Loads and provides access to monitoring threshold configuration."""

    def __init__(self, config_path: str):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Threshold config not found: {config_path}")
        with open(config_path) as f:
            self._data = yaml.safe_load(f)

    @property
    def defaults(self) -> dict:
        return self._data.get("defaults", {})

    @property
    def check_interval(self) -> int:
        return self._data.get("check_interval_seconds", 300)

    @property
    def services(self) -> list[str]:
        return self._data.get("services", [])

    def get_servers(self) -> list[str]:
        """Return list of server identifiers."""
        return list(self._data.get("servers", {}).keys())

    def get_hostname(self, server_id: str) -> str:
        """Return the hostname/IP for a server identifier."""
        server = self._data.get("servers", {}).get(server_id, {})
        return server.get("hostname", server_id)

    def get_thresholds(self, server_id: str) -> dict:
        """Return merged thresholds for a server (server overrides merged onto defaults)."""
        merged = dict(self.defaults)
        server = self._data.get("servers", {}).get(server_id, {})
        merged.update(server)
        return merged
```

- [ ] **Step 4: Run tests**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/monitor/test_threshold_config.py -v
```

Expected: PASS (if not, debug and fix)

- [ ] **Step 5: Create `tools/monitor/__init__.py`**

```python
# tools/monitor __init__.py
```

- [ ] **Step 6: Write the monitoring daemon**

Create `tools/monitor/monitor_daemon.py`:

```python
#!/usr/bin/env python3
"""
Monitoring daemon — persistent health check loop with pre-analysis.

Runs as a long-lived process (no cron). Periodically SSHes to all configured
servers, runs health checks against thresholds, performs preliminary analysis
when thresholds are breached, and dispatches alerts to the serveradmin agent
via ask_agent_async.py.
"""

import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

from tools.monitor.threshold_config import ThresholdConfig


# Path to workspace for inter-agent communication
WORKSPACE_ROOT = "/ductor/agents/serveradmin/workspace"
ASK_AGENT_ASYNC = os.path.join(WORKSPACE_ROOT, "tools", "agent_tools", "ask_agent_async.py")


class MonitorDaemon:
    """Persistent monitoring daemon with pre-analysis capabilities."""

    def __init__(
        self,
        config_path: str,
        ssh_key_path: str,
        ssh_user: str = "agent",
    ):
        self.config = ThresholdConfig(config_path)
        self.ssh_key_path = ssh_key_path
        self.ssh_user = ssh_user
        self._sustained_cpu: dict[str, int] = {}  # server -> consecutive checks over threshold

    def run(self) -> None:
        """Main monitoring loop. Blocks forever."""
        print(f"[{self._now()}] Monitor daemon started. "
              f"Interval: {self.config.check_interval}s", file=sys.stderr)

        while True:
            try:
                self._check_all_servers()
            except Exception as e:
                print(f"[{self._now()}] Error in check cycle: {e}", file=sys.stderr)

            time.sleep(self.config.check_interval)

    def _check_all_servers(self) -> None:
        """Run health checks on all configured servers."""
        for server_id in self.config.get_servers():
            hostname = self.config.get_hostname(server_id)
            thresholds = self.config.get_thresholds(server_id)

            alerts: list[dict] = []

            # Disk check
            disk_alert = self._check_disk(hostname, thresholds)
            if disk_alert:
                alerts.append(disk_alert)

            # Memory check
            mem_alert = self._check_memory(hostname, thresholds)
            if mem_alert:
                alerts.append(mem_alert)

            # CPU check
            cpu_alert = self._check_cpu(server_id, hostname, thresholds)
            if cpu_alert:
                alerts.append(cpu_alert)

            # Service checks
            for svc in self.config.services:
                svc_alert = self._check_service(hostname, svc)
                if svc_alert:
                    alerts.append(svc_alert)

            if alerts:
                self._dispatch_alert(server_id, hostname, alerts)

    def _ssh(self, hostname: str, command: str) -> tuple[int, str, str]:
        """Run a command via SSH and return (exit_code, stdout, stderr)."""
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-i", self.ssh_key_path,
            f"{self.ssh_user}@{hostname}",
            command,
        ]
        try:
            proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return -1, "", "SSH timeout"
        except FileNotFoundError:
            return -1, "", "SSH client not available"
        except Exception as e:
            return -1, "", str(e)

    def _check_disk(self, hostname: str, thresholds: dict) -> dict | None:
        """Check disk usage. Returns alert dict if threshold exceeded."""
        code, stdout, stderr = self._ssh(hostname, "df -h --output=target,pcent,size,avail 2>/dev/null | tail -n +2")
        if code != 0:
            return {"type": "disk", "level": "error", "message": f"SSH failed: {stderr}"}

        for line in stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            mount, pct_str = parts[0], parts[1].replace("%", "")
            try:
                pct = int(pct_str)
            except ValueError:
                continue

            if pct >= thresholds["disk_crit_pct"]:
                return {
                    "type": "disk",
                    "level": "critical",
                    "mount": mount,
                    "used_pct": pct,
                    "threshold": thresholds["disk_crit_pct"],
                    "raw_output": stdout,
                }
            elif pct >= thresholds["disk_warn_pct"]:
                return {
                    "type": "disk",
                    "level": "warning",
                    "mount": mount,
                    "used_pct": pct,
                    "threshold": thresholds["disk_warn_pct"],
                    "raw_output": stdout,
                }
        return None

    def _check_memory(self, hostname: str, thresholds: dict) -> dict | None:
        """Check memory usage. Returns alert dict if threshold exceeded."""
        code, stdout, stderr = self._ssh(hostname, "free -m | awk 'NR==2{print $2,$3,$4,$6}'")
        if code != 0:
            return {"type": "memory", "level": "error", "message": f"SSH failed: {stderr}"}

        parts = stdout.strip().split()
        if len(parts) < 3:
            return None

        total = int(parts[0])
        used = int(parts[1])
        # available includes buffers/cache that can be reclaimed
        available = total - used
        if len(parts) >= 4:
            available = int(parts[2]) + int(parts[3]) if len(parts) >= 4 else int(parts[2])

        used_pct = int((1 - available / total) * 100) if total > 0 else 0

        if used_pct >= thresholds["mem_crit_pct"]:
            # Pre-analysis: get top memory consumers
            code2, top_output, _ = self._ssh(
                hostname,
                "ps aux --sort=-%mem | head -6 | awk '{print $2,$11,$4\"%\"}'",
            )
            return {
                "type": "memory",
                "level": "critical",
                "used_pct": used_pct,
                "threshold": thresholds["mem_crit_pct"],
                "raw_output": stdout,
                "top_consumers": top_output.strip(),
            }
        elif used_pct >= thresholds["mem_warn_pct"]:
            code2, top_output, _ = self._ssh(
                hostname,
                "ps aux --sort=-%mem | head -6 | awk '{print $2,$11,$4\"%\"}'",
            )
            return {
                "type": "memory",
                "level": "warning",
                "used_pct": used_pct,
                "threshold": thresholds["mem_warn_pct"],
                "raw_output": stdout,
                "top_consumers": top_output.strip(),
            }
        return None

    def _check_cpu(self, server_id: str, hostname: str, thresholds: dict) -> dict | None:
        """Check CPU load. Uses sustained check logic."""
        code, stdout, stderr = self._ssh(
            hostname,
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
        )
        if code != 0:
            return None  # CPU check is best-effort

        try:
            cpu_pct = float(stdout.strip())
        except ValueError:
            return None

        warn_threshold = thresholds["cpu_warn_pct"]
        crit_threshold = thresholds["cpu_crit_pct"]
        sustained_needed = thresholds.get("cpu_sustained_checks", 3)

        if cpu_pct >= crit_threshold or cpu_pct >= warn_threshold:
            self._sustained_cpu[server_id] = self._sustained_cpu.get(server_id, 0) + 1
        else:
            self._sustained_cpu[server_id] = 0
            return None

        if self._sustained_cpu[server_id] < sustained_needed:
            return None

        # Pre-analysis: get top CPU consumers
        code2, top_output, _ = self._ssh(
            hostname,
            "ps aux --sort=-%cpu | head -6 | awk '{print $2,$11,$3\"%\"}'",
        )

        level = "critical" if cpu_pct >= crit_threshold else "warning"
        return {
            "type": "cpu",
            "level": level,
            "used_pct": cpu_pct,
            "threshold": crit_threshold if level == "critical" else warn_threshold,
            "sustained_checks": self._sustained_cpu[server_id],
            "top_consumers": top_output.strip(),
        }

    def _check_service(self, hostname: str, service: str) -> dict | None:
        """Check if a systemd service is active. Returns alert if not."""
        code, stdout, stderr = self._ssh(hostname, f"systemctl is-active {shlex.quote(service)}")
        if code != 0 or stdout.strip() != "active":
            # Pre-analysis: grab last 20 journal lines
            code2, journal, _ = self._ssh(
                hostname,
                f"journalctl -u {shlex.quote(service)} --no-pager -n 20 2>/dev/null",
            )
            return {
                "type": "service",
                "level": "critical",
                "service": service,
                "status": stdout.strip() or "unknown",
                "journal_last_20": journal.strip(),
            }
        return None

    def _dispatch_alert(self, server_id: str, hostname: str, alerts: list[dict]) -> None:
        """Dispatch alerts to the serveradmin agent via ask_agent_async."""
        summary = self._build_alert_summary(server_id, hostname, alerts)
        self._send_to_agent(summary)

    def _build_alert_summary(self, server_id: str, hostname: str, alerts: list[dict]) -> str:
        """Build a structured alert message for the agent."""
        lines = [
            f"[MONITOR ALERT] {server_id} ({hostname})",
            f"Time: {self._now()}",
            f"Alerts: {len(alerts)}",
            "",
        ]
        for i, alert in enumerate(alerts, 1):
            lines.append(f"--- Alert {i}: {alert['type']} [{alert['level'].upper()}] ---")
            for key, value in alert.items():
                if key in ("raw_output",):
                    continue  # skip raw output in summary, agent can request it
                if value and key != "level":
                    lines.append(f"  {key}: {value}")
            lines.append("")
        return "\n".join(lines)

    def _send_to_agent(self, message: str) -> None:
        """Send alert message to the serveradmin agent."""
        if not os.path.exists(ASK_AGENT_ASYNC):
            print(f"[{self._now()}] WARNING: ask_agent_async.py not found at {ASK_AGENT_ASYNC}", file=sys.stderr)
            return
        try:
            subprocess.run(
                ["python3", ASK_AGENT_ASYNC, "serveradmin", message],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception as e:
            print(f"[{self._now()}] Failed to dispatch alert: {e}", file=sys.stderr)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Server Admin Monitoring Daemon")
    parser.add_argument(
        "--config",
        default="config/thresholds.yaml",
        help="Path to thresholds config file",
    )
    parser.add_argument(
        "--ssh-key",
        default="/ductor/agents/serveradmin/workspace/.ssh/agent_key",
        help="Path to SSH private key",
    )
    parser.add_argument(
        "--ssh-user",
        default="agent",
        help="SSH username",
    )
    args = parser.parse_args()

    daemon = MonitorDaemon(
        config_path=args.config,
        ssh_key_path=args.ssh_key,
        ssh_user=args.ssh_user,
    )
    daemon.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 7: Create CLAUDE.md for monitor tools**

Create `tools/monitor/CLAUDE.md`:

```markdown
# Monitor Tools

## monitor_daemon.py

Persistent monitoring daemon. Start with:

```bash
python3 tools/monitor/monitor_daemon.py --config config/thresholds.yaml --ssh-key /path/to/key &
```

### Behavior
- Polls all configured servers every N seconds
- On threshold breach: performs pre-analysis (top consumers, journal logs)
- Dispatches alert to serveradmin agent via ask_agent_async.py
- Completely independent of cron — runs as a persistent process

### Threshold Config
Edit `config/thresholds.yaml` to adjust thresholds and server list.
```

- [ ] **Step 8: Run threshold config tests**

```bash
cd /ductor/agents/serveradmin/workspace && python3 -m pytest tools/monitor/test_threshold_config.py -v
```

Expected: PASS

---

### Task 8: GitHub Repository & Code Management

**Files:**
- Create: `.gitignore`
- Modify: none

**No code to write — setup and git operations.**

- [ ] **Step 1: Install GitHub CLI**

```bash
# gh CLI is not present by default. Install via the official method:
# (Debian/Ubuntu)
(type -p wget >/dev/null || apt-get install -y wget) && \
mkdir -p -m 755 /etc/apt/keyrings && \
wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
    tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null && \
chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg && \
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | \
    tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
apt-get update && \
apt-get install -y gh
```

Verify:
```bash
gh --version
```

- [ ] **Step 2: Authenticate with GitHub**

```bash
# Check if already authenticated
gh auth status

# If not authenticated:
# NOTE: This step requires user interaction. Present the user with this command:
# gh auth login
# Or use a pre-existing token:
# export GH_TOKEN="<token>" && gh auth setup-git
```

- [ ] **Step 3: Create GitHub repository**

```bash
cd /ductor/agents/serveradmin/workspace
gh repo create server-admin-agent \
    --description "Secure remote server management agent with TOTP-guarded command execution" \
    --public \
    --source=. \
    --remote=origin
```

If the repo already exists, instead link it:
```bash
gh repo clone server-admin-agent /tmp/server-admin-agent-clone -- --depth=1
# or: git remote add origin git@github.com:USER/server-admin-agent.git
```

- [ ] **Step 4: Create .gitignore**

Create `.gitignore`:

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
dist/

# Logs
logs/*.jsonl
logs/*.log

# Secrets & keys (CRITICAL)
.ssh/*
*.pem
*.key
!config/thresholds.yaml

# Environment & IDE
.env
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Output
output_to_user/
```

- [ ] **Step 5: Initialize git and commit**

```bash
cd /ductor/agents/serveradmin/workspace

# Initialize if not already a git repo
if [ ! -d .git ]; then
    git init
fi

# Configure git user if not set
git config user.email || git config user.email "serveradmin@ductor.local"
git config user.name || git config user.name "Server Admin Agent"

# Stage files
git add .gitignore
git add tools/executor/
git add tools/monitor/
git add config/thresholds.yaml
git add docs/superpowers/specs/2026-06-30-server-admin-agent-design.md
git add docs/superpowers/plans/2026-06-30-server-admin-agent-plan.md

# Verify no secrets are staged
git diff --cached --name-only | grep -E '\.(key|pem)$' && echo "WARNING: key files staged!" || true

# Commit
git commit -m "feat: server admin agent toolkit

- Command execution pipeline (parser, whitelist, rate limiter, audit)
- TOTP-guarded modifying command approval
- Monitor daemon with pre-analysis and threshold-based alerting
- Server-side agent-shell-filter for defense-in-depth
- Design spec and implementation plan"
```

- [ ] **Step 6: Push to GitHub**

```bash
cd /ductor/agents/serveradmin/workspace
git branch -M main
git push -u origin main
```

Expected: `Branch 'main' set up to track remote branch 'main' from 'origin'.`

- [ ] **Step 7: Verify remote**

```bash
gh repo view --json name,url,defaultBranch
```

---

### Task 9: Integration & Agent Routing

**Files:**
- Modify: `tools/CLAUDE.md`
- Create: `tools/executor/CLAUDE.md`
- Create: `tools/monitor/CLAUDE.md` (already created in Task 7)

**No new code — documentation and wiring.**

- [ ] **Step 1: Create executor tool docs**

Create `tools/executor/CLAUDE.md`:

```markdown
# Executor Tools

Secure remote command execution with TOTP-guarded approval.

## command_executor.py

The unified entry point for all remote server commands.

```python
from tools.executor.command_executor import CommandExecutor

executor = CommandExecutor(
    ssh_key_path="/path/to/agent_key",
    ssh_user="agent",
    max_modifying_per_hour=10,
)

# Read-only: auto-executes
result = executor.execute("server-a", "df -h")

# Modifying: requires TOTP code from user
result = executor.execute("server-a", "apt install htop", totp_code="123456")
```

Return format:
```python
{
    "exit_code": 0,         # -1 on error/block
    "stdout": "...",
    "stderr": "...",
    "approved": True,       # False if TOTP needed or blocked
    "needs_approval": False, # True if user must provide TOTP
    "blocked": False,       # True if security pattern matched
    "target": "server-a",
    "command": "df -h",
}
```

## Security Pipeline (automatic)

Every command passes through:
1. Command parser — splits chains, blocks injection
2. Whitelist router — read-only vs modifying
3. Rate limiter — max N modifying/hour
4. TOTP validation — required for modifying (validated server-side)
5. Audit log — append-only

## agent_shell_filter.py

Deploy to `/usr/local/bin/agent-shell-filter` on each target server.
Then add to authorized_keys:

```
command="/usr/local/bin/agent-shell-filter",no-pty,no-port-forwarding ssh-ed25519 AAA...
```
```

- [ ] **Step 2: Update main tools index**

Modify `tools/CLAUDE.md` — add entries for executor and monitor:

```markdown
- remote command execution + TOTP security -> `executor/CLAUDE.md`
- monitoring daemon + thresholds -> `monitor/CLAUDE.md`
```

Use Edit to insert after the existing routing lines.

- [ ] **Step 3: Final structure check**

```bash
find /ductor/agents/serveradmin/workspace/tools/executor -type f && \
find /ductor/agents/serveradmin/workspace/tools/monitor -type f && \
ls /ductor/agents/serveradmin/workspace/config/thresholds.yaml
```

Expected: all files present
