#!/bin/bash
# ops-skill container setup
# Run as root inside the Docker container (ductor-sub-serveradmin):
#   docker exec -u root ductor-sub-serveradmin bash /path/to/install.sh
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must run as root. Use: docker exec -u root ..."
    exit 1
fi

echo "=== ops-skill container setup ==="

# ---------- 1. system packages ----------
echo "[1/4] Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    openssh-client \
    logrotate \
    python3-pip

# ---------- 2. Python dependencies ----------
echo "[2/4] Installing Python packages..."
pip3 install pyotp pyyaml

# ---------- 3. logrotate for audit logs ----------
echo "[3/4] Setting up logrotate..."
mkdir -p /ductor/agents/serveradmin/workspace/logs
cat > /etc/logrotate.d/ops-skill-audit << 'LOGROTATE'
/ductor/agents/serveradmin/workspace/logs/command_audit.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
LOGROTATE

# ---------- 4. verify ----------
echo "[4/4] Verifying..."
echo "  SSH:   $(ssh -V 2>&1 | head -1 || echo 'NOT FOUND')"
echo "  pyOTP: $(python3 -c 'import pyotp; print(pyotp.__version__)' 2>/dev/null || pip3 show pyotp | grep Version)"
echo "  YAML:  $(python3 -c 'import yaml; print(yaml.__version__)' 2>/dev/null || echo 'NOT FOUND')"
echo "  logrotate: $(logrotate --version 2>&1 | head -1 || echo 'NOT FOUND')"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Generate SSH key: ssh-keygen -t ed25519 -f .ssh/agent_key -C 'ops-skill'"
echo "  2. Deploy to target servers (copy agent_shell_filter.py + TOTP secret + pubkey)"
echo "  3. Edit thresholds: skills/ops_skill/config/thresholds.yaml"
echo "  4. Start daemon: bash skills/ops_skill/setup/start-daemon.sh"
echo ""
echo "NTP: Docker container shares host clock — ensure the HOST runs NTP."
echo "Restart: Add --restart=always to the Docker container for auto-recovery."
