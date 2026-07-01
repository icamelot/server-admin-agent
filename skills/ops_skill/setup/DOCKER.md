# Docker Host Setup

The ops-skill agent runs inside a Docker container (`ductor-sub-serveradmin`).
No NTP or supervisor is needed inside the container — the host handles both.

## Host Requirements

```bash
# Host must run NTP for accurate TOTP validation
sudo apt-get install -y ntpsec
sudo systemctl enable --now ntpsec

# Verify
ntpq -p
```

## Container Lifecycle

```bash
# Run with auto-restart so the monitor daemon recovers after crashes
docker run -d \
    --name ductor-sub-serveradmin \
    --restart=always \
    --mount type=bind,source=$HOME/.ductor,target=/ductor \
    ductor-sub-serveradmin
```

## Install ops-skill in the Container

```bash
# One-time setup (as root)
docker exec -u root ductor-sub-serveradmin \
    bash /ductor/agents/serveradmin/workspace/skills/ops_skill/setup/install.sh
```

## Start the Monitor Daemon

```bash
# After SSH key and threshold config are ready
docker exec ductor-sub-serveradmin \
    bash /ductor/agents/serveradmin/workspace/skills/ops_skill/setup/start-daemon.sh
```

## Stop the Daemon

```bash
docker exec ductor-sub-serveradmin \
    kill $(cat /ductor/agents/serveradmin/workspace/logs/monitor-daemon.pid)
```

## Log Rotation

Logrotate handles audit log growth automatically (installed by install.sh).
To run manually:

```bash
docker exec -u root ductor-sub-serveradmin logrotate -f /etc/logrotate.d/ops-skill-audit
```
