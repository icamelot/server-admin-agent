# ops-skill

Server operations toolkit — secure remote command execution, monitoring daemon with threshold-based alerting, and rate-limited TOTP-guarded SSH access.

## Structure

```
skills/ops_skill/
├── SKILL.md                        # This file
├── config/
│   └── thresholds.yaml             # Monitoring thresholds and server list
└── tools/
    ├── executor/                   # SSH command execution with security pipeline
    │   ├── command_executor.py     # Unified entry point for remote commands
    │   ├── command_parser.py       # Command parsing and injection detection
    │   ├── whitelist.py            # Read-only vs modifying classification
    │   ├── agent_shell_filter.py   # Server-side TOTP validation and blocking
    │   ├── rate_limiter.py         # Per-hour modifying command cap
    │   └── audit.py                # Append-only audit logging
    └── monitor/                    # Persistent health monitoring
        ├── monitor_daemon.py       # Long-lived monitoring loop
        └── threshold_config.py     # YAML threshold configuration loader
```

## Quick Start

### Command Execution

```python
from skills.ops_skill.tools.executor.command_executor import CommandExecutor

executor = CommandExecutor(
    ssh_key_path="/path/to/agent_key",
    ssh_user="agent",
    max_modifying_per_hour=10,
)

# Read-only: auto-executes
result = executor.execute("server-a", "df -h")

# Modifying: requires TOTP code
result = executor.execute("server-a", "apt install htop", totp_code="123456")
```

### Monitoring Daemon

```bash
python3 skills/ops_skill/tools/monitor/monitor_daemon.py \
    --config skills/ops_skill/config/thresholds.yaml \
    --ssh-key /path/to/agent_key &
```

## Security Pipeline

Every modifying command passes through:
1. Command parser — splits chains, blocks injection patterns
2. Whitelist router — classify as read-only vs modifying
3. TOTP validation — 6-digit TOTP required for modifying commands
4. Rate limiter — caps modifying commands per hour
5. Server-side filter — second layer on the target (agent-shell-filter)
6. Audit log — append-only, all command results recorded

## Configuration

Edit `skills/ops_skill/config/thresholds.yaml` to adjust:
- Disk/memory/CPU warning and critical thresholds
- Check interval (seconds)
- Server list with hostnames and optional jump hosts
- Services to monitor via systemctl

## Tests

```bash
pytest skills/ops_skill/tools/executor/ skills/ops_skill/tools/monitor/ -v
```
