#!/bin/bash
# Start the ops-skill monitor daemon with nohup (no supervisor needed).
# Run inside the container: bash skills/ops_skill/setup/start-daemon.sh
set -e

WORKSPACE="/ductor/agents/serveradmin/workspace"
PIDFILE="$WORKSPACE/logs/monitor-daemon.pid"
LOGFILE="$WORKSPACE/logs/monitor-daemon.log"
CONFIG="$WORKSPACE/skills/ops_skill/config/thresholds.yaml"
SSH_KEY="$WORKSPACE/.ssh/agent_key"

# Check if already running
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Daemon is already running (PID $(cat "$PIDFILE"))"
    exit 0
fi

# Ensure SSH key exists
if [ ! -f "$SSH_KEY" ]; then
    echo "ERROR: SSH key not found at $SSH_KEY"
    echo "Generate one first: ssh-keygen -t ed25519 -f $SSH_KEY -C 'ops-skill'"
    exit 1
fi

# Ensure config exists
if [ ! -f "$CONFIG" ]; then
    echo "ERROR: Threshold config not found at $CONFIG"
    exit 1
fi

mkdir -p "$WORKSPACE/logs"

echo "Starting monitor daemon..."
nohup python3 "$WORKSPACE/skills/ops_skill/tools/monitor/monitor_daemon.py" \
    --config "$CONFIG" \
    --ssh-key "$SSH_KEY" \
    >> "$LOGFILE" 2>&1 &

PID=$!
echo $PID > "$PIDFILE"
echo "Daemon started (PID $PID)"
echo "Logs: $LOGFILE"
echo "Stop: kill $(cat $PIDFILE)"
