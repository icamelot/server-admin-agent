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
3. TOTP validation — required for modifying (format check agent-side, cryptographically validated server-side)
4. Rate limiter — max N modifying/hour
5. Audit log — append-only

## agent_shell_filter.py

Deploy to `/usr/local/bin/agent-shell-filter` on each target server.
Then add to authorized_keys:

```
command="/usr/local/bin/agent-shell-filter",no-pty,no-port-forwarding ssh-ed25519 AAA...
```
