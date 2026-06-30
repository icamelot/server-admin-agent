# Monitor Tools

## monitor_daemon.py

Persistent monitoring daemon. Start with:

```bash
python3 skills/ops_skill/tools/monitor/monitor_daemon.py --config skills/ops_skill/config/thresholds.yaml --ssh-key /path/to/key &
```

### Behavior
- Polls all configured servers every N seconds
- On threshold breach: performs pre-analysis (top consumers, journal logs)
- Dispatches alert to serveradmin agent via ask_agent_async.py
- Completely independent of cron — runs as a persistent process

### Threshold Config
Edit `skills/ops_skill/config/thresholds.yaml` to adjust thresholds and server list.
