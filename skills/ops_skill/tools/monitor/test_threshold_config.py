import pytest
from skills.ops_skill.tools.monitor.threshold_config import ThresholdConfig


class TestThresholdConfig:
    def test_loads_defaults(self):
        config = ThresholdConfig("skills/ops_skill/config/thresholds.yaml")
        assert config.defaults["disk_warn_pct"] == 85
        assert config.defaults["mem_crit_pct"] == 95
        assert config.check_interval == 300

    def test_server_list(self):
        config = ThresholdConfig("skills/ops_skill/config/thresholds.yaml")
        servers = config.get_servers()
        assert len(servers) == 2
        assert "server-a" in servers

    def test_get_threshold_for_server(self):
        config = ThresholdConfig("skills/ops_skill/config/thresholds.yaml")
        thresholds = config.get_thresholds("server-a")
        assert thresholds["disk_warn_pct"] == 85  # from defaults

    def test_get_hostname(self):
        config = ThresholdConfig("skills/ops_skill/config/thresholds.yaml")
        assert config.get_hostname("server-a") == "server-a.local"

    def test_services_list(self):
        config = ThresholdConfig("skills/ops_skill/config/thresholds.yaml")
        assert "nginx" in config.services
        assert "sshd" in config.services

    def test_missing_config_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ThresholdConfig("config/nonexistent.yaml")
