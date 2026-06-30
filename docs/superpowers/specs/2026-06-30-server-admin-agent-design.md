# Server Admin Agent — Design Spec

**Date**: 2026-06-30
**Agent**: serveradmin (sub-agent in Ductor multi-agent system)
**Status**: Draft

## 1. Overview

The serveradmin agent executes commands on behalf of a human server administrator
to manage remote servers in the same network. It covers monitoring, user
management, and troubleshooting — with a strict security boundary between
read-only and modifying operations.

## 2. Managed Infrastructure

| Server | Role | Access |
|---|---|---|
| Server A | Standalone compute server | Agent SSH directly |
| Server B | Cluster login node | Agent SSH directly |
| Nodes N1–N5 | Compute nodes | Accessible **only** via Server B (bastion/jump) |

All servers are on the same network. SSH client installation in the agent
container is handled by the `main` agent.

## 3. Task Scope

- **Monitoring & inspection** — disk, memory, CPU, service status, key processes
- **User management** — create, modify, delete users; adjust permissions
- **Troubleshooting** — log analysis, root-cause diagnosis

## 4. Autonomy Model

| Operation type | Behavior |
|---|---|
| Read-only (query, inspect, monitor, logs) | Agent executes directly, notifies user of result |
| Modifying (install, remove, restart, user changes, config writes) | Agent presents diagnosis + proposed action to user; requires TOTP approval before execution |

## 5. Monitoring Architecture

### 5.1 Daemon

A persistent Python daemon (`while True: sleep(N)`) — **no cron whatsoever**.

- Deployed in the agent container or on a dedicated host
- Periodically SSHes to all servers and runs health checks
- Checks against a configurable threshold file
- On normal readings: silent, no output

### 5.2 Alert Flow

```
Daemon detects threshold breach
  → Daemon performs preliminary analysis (key metrics, relevant log snippets)
  → Calls ask_agent_async.py to wake serveradmin agent (with pre-analysis data)
  → serveradmin agent:
       - Reviews pre-analysis
       - Performs deeper diagnosis if needed
       - Generates a solution
       - If solution is read-only → executes directly, reports to user
       - If solution requires modification → presents diagnosis + proposal
         to user, waits for TOTP approval
```

### 5.3 Threshold Configuration

A single thresholds config file (format TBD, likely YAML or JSON):

```yaml
disk_warn_pct: 85
disk_crit_pct: 95
mem_warn_pct: 80
mem_crit_pct: 95
cpu_warn_pct: 70  # sustained over N checks
cpu_crit_pct: 90
# per-server overrides available
```

## 6. Command Execution & Security Pipeline

All remote commands flow through a unified execution tool inside the agent.
Every command passes through these layers:

### Layer 1 — Command Parser (agent side)

- Splits chained commands (`&&`, `||`, `;`, pipes)
- Blocks shell injection patterns: `$()`, backticks, `eval`, `exec`
- A chained command is only permitted if **every** link in the chain is
  individually authorized

### Layer 2 — Whitelist Router (agent side)

| Category | Command examples | Action |
|---|---|---|
| Read-only | `df`, `free`, `top`, `ps`, `systemctl status`, `journalctl`, `cat`, `ls`, `who`, `last`, `ss`, `ip addr`, `du` | Auto-approve |
| Modifying | `systemctl restart/stop/start`, `apt/yum install/remove`, `useradd/usermod/userdel`, `passwd`, `rm`, `chmod`, `chown`, `iptables`, config file writes | Require TOTP |

### Layer 3 — Rate Limiter (agent side)

- Maximum N modifying commands per hour (configurable, suggested default: 10)
- Exceeded → lock; requires manual unlock by user
- Prevents cascade failures and runaway loops

### Layer 4 — TOTP Validation (server side)

- TOTP secret is deployed to each target server as part of `agent-shell-filter`
- Secret is **never** stored by the agent — agent only passes the code through
- Server-side filter validates TOTP before executing any modifying command
- TOTP window: 60 seconds, with ±1 step tolerance for clock skew

### Layer 5 — agent-shell-filter (server side)

A small script deployed on each target server:
- Receives the command + TOTP code
- Validates TOTP against local secret
- Performs a second whitelist check (defense in depth)
- Executes only if all checks pass
- Returns result to agent

### Layer 6 — SSH Key Restrictions (server side)

The agent's SSH key in `~/.ssh/authorized_keys` on each server:

```
command="/usr/local/bin/agent-shell-filter",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAA... agent-key
```

This forces all connections through the filter and disables interactive shells,
port forwarding, and agent forwarding at the SSH protocol level.

### Layer 7 — Audit Log

- Every command logged: timestamp, source, target server, full command,
  approval status, execution result
- Append-only, stored on both agent and server sides
- Not deletable by the agent

## 7. TOTP Approval Flow

```
User receives approval request ("diagnosis + proposed command")
  → User opens Authenticator app
  → Generates 6-digit TOTP code
  → Sends code back to agent via Telegram
  → Agent passes code + command to target server
  → agent-shell-filter validates TOTP
  → Executes or rejects
```

- TOTP secret provisioning is a one-time setup per server
- The user (or main agent) holds the secret for code generation
- The agent never possesses the secret and cannot self-approve

## 8. Authentication

- Agent uses a **dedicated SSH key pair** (not shared with the user's personal key)
- Key pair generated during setup, public key deployed to each target server
- Separate identity enables audit trail and easy revocation

## 9. Interaction Model

### 9.1 User-Initiated

User sends a request via Telegram → serveradmin agent processes it:
- Parse intent → generate command sequence
- Read-only: execute → report
- Modifying: present plan → request TOTP → execute → confirm

### 9.2 Alert-Initiated

Daemon → ask_agent_async → agent:
- Agent receives pre-analyzed alert
- Performs deeper investigation
- Presents findings + solution (read-only parts auto-executed, modifying parts
  held for TOTP)

### 9.3 Approval Notification Path

Tentative: agent → main agent → user (exact routing TBD)

## 10. Components to Build

| Component | Where | Purpose |
|---|---|---|
| Monitoring daemon | Agent container / dedicated | SSH health checks, pre-analysis, alert dispatch |
| Threshold config | Workspace | Per-server health thresholds |
| Command executor tool | Agent tools | Unified SSH command execution with security pipeline |
| Command parser | Within executor | Chain splitting, injection blocking |
| Whitelist router | Within executor | Read-only vs modifying classification |
| Rate limiter | Within executor | Modifying command cap per hour |
| agent-shell-filter | Each target server | TOTP validation, secondary whitelist |
| Audit logger | Agent + servers | Append-only command log |
| Key setup helper | Setup tooling | SSH key generation, deployment |

## 11. Open Decisions

- Exact approval notification path (main → user vs direct)
- TOTP secret provisioning mechanism (manual deployment vs automated)
- Specific threshold values and check intervals for monitoring
- Rate limiter N value for modifying commands per hour
