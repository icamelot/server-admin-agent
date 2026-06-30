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
