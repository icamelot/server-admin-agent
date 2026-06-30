"""Tests for monitor daemon health check methods.

All tests mock the _ssh method to avoid real SSH connections.
"""

import pytest
from unittest.mock import MagicMock
from tools.monitor.monitor_daemon import MonitorDaemon


@pytest.fixture
def daemon():
    return MonitorDaemon(
        config_path="config/thresholds.yaml",
        ssh_key_path="/tmp/test_key",
        ssh_user="agent",
    )


class TestCheckDisk:
    def test_disk_normal_no_alert(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "target1  12%\ntarget2  45%\n", ""))
        thresholds = {"disk_warn_pct": 85, "disk_crit_pct": 95}
        result = daemon._check_disk("testhost", thresholds)
        assert result is None

    def test_disk_warning(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "/       88%\n", ""))
        thresholds = {"disk_warn_pct": 85, "disk_crit_pct": 95}
        result = daemon._check_disk("testhost", thresholds)
        assert result is not None
        assert result["type"] == "disk"
        assert result["level"] == "warning"
        assert result["used_pct"] == 88

    def test_disk_critical(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "/       97%\n", ""))
        thresholds = {"disk_warn_pct": 85, "disk_crit_pct": 95}
        result = daemon._check_disk("testhost", thresholds)
        assert result is not None
        assert result["level"] == "critical"
        assert result["used_pct"] == 97

    def test_disk_ssh_error(self, daemon):
        daemon._ssh = MagicMock(return_value=(1, "", "Connection refused"))
        thresholds = {"disk_warn_pct": 85, "disk_crit_pct": 95}
        result = daemon._check_disk("testhost", thresholds)
        assert result["type"] == "disk"
        assert result["level"] == "error"

    def test_disk_skips_missing_mount_data(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "/\n", ""))
        thresholds = {"disk_warn_pct": 85, "disk_crit_pct": 95}
        result = daemon._check_disk("testhost", thresholds)
        assert result is None


class TestCheckMemory:
    def test_memory_normal_no_alert(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "16000 4000 12000\n", ""))
        thresholds = {"mem_warn_pct": 80, "mem_crit_pct": 95}
        result = daemon._check_memory("testhost", thresholds)
        assert result is None

    def test_memory_warning_with_top_consumers(self, daemon):
        def mock_ssh(hostname, command, jump_host=None):
            if "free -m" in command:
                return (0, "16000 12000 2000\n", "")
            if "ps aux" in command:
                return (0, "1234 nginx 15.3%\n", "")
            return (-1, "", "")

        daemon._ssh = MagicMock(side_effect=mock_ssh)
        thresholds = {"mem_warn_pct": 80, "mem_crit_pct": 95}
        result = daemon._check_memory("testhost", thresholds)
        assert result is not None
        assert result["type"] == "memory"
        assert result["level"] == "warning"
        assert "top_consumers" in result

    def test_memory_ssh_error(self, daemon):
        daemon._ssh = MagicMock(return_value=(1, "", "timeout"))
        thresholds = {"mem_warn_pct": 80, "mem_crit_pct": 95}
        result = daemon._check_memory("testhost", thresholds)
        assert result["level"] == "error"

    def test_memory_insufficient_columns(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "16000 4000\n", ""))
        thresholds = {"mem_warn_pct": 80, "mem_crit_pct": 95}
        result = daemon._check_memory("testhost", thresholds)
        assert result is None


class TestCheckCpu:
    def test_cpu_normal_no_alert(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "25.3\n", ""))
        thresholds = {"cpu_warn_pct": 70, "cpu_crit_pct": 90, "cpu_sustained_checks": 3}
        result = daemon._check_cpu("srv1", "testhost", thresholds)
        assert result is None

    def test_cpu_sustained_warning(self, daemon):
        thresholds = {"cpu_warn_pct": 70, "cpu_crit_pct": 90, "cpu_sustained_checks": 2}
        daemon._ssh = MagicMock(return_value=(0, "75.0\n", ""))
        assert daemon._check_cpu("srv1", "testhost", thresholds) is None  # 1st
        assert daemon._check_cpu("srv1", "testhost", thresholds) is not None  # 2nd

    def test_cpu_recovers_after_dip(self, daemon):
        thresholds = {"cpu_warn_pct": 70, "cpu_crit_pct": 90, "cpu_sustained_checks": 3}
        daemon._ssh = MagicMock(return_value=(0, "75.0\n", ""))
        daemon._check_cpu("srv1", "testhost", thresholds)  # count=1
        daemon._check_cpu("srv1", "testhost", thresholds)  # count=2
        daemon._ssh = MagicMock(return_value=(0, "30.0\n", ""))
        result = daemon._check_cpu("srv1", "testhost", thresholds)
        assert result is None
        assert daemon._sustained_cpu["srv1"] == 0

    def test_cpu_ssh_failure_returns_none(self, daemon):
        daemon._ssh = MagicMock(return_value=(1, "", ""))
        thresholds = {"cpu_warn_pct": 70, "cpu_crit_pct": 90, "cpu_sustained_checks": 3}
        assert daemon._check_cpu("srv1", "testhost", thresholds) is None


class TestCheckService:
    def test_service_active_no_alert(self, daemon):
        daemon._ssh = MagicMock(return_value=(0, "active\n", ""))
        result = daemon._check_service("testhost", "nginx")
        assert result is None

    def test_service_inactive_alert_with_journal(self, daemon):
        def mock_ssh(hostname, command, jump_host=None):
            if "is-active" in command:
                return (3, "inactive\n", "")
            if "journalctl" in command:
                return (0, "Failed to start service\n", "")
            return (-1, "", "")

        daemon._ssh = MagicMock(side_effect=mock_ssh)
        result = daemon._check_service("testhost", "nginx")
        assert result is not None
        assert result["type"] == "service"
        assert result["level"] == "critical"
        assert result["status"] == "inactive"
        assert "journal_last_20" in result


class TestAlertDedup:
    def test_should_dispatch_new_alert(self, daemon):
        alert = {"type": "disk", "level": "warning"}
        assert daemon._should_dispatch("srv1", alert) is True

    def test_should_not_dispatch_same_alert_immediately(self, daemon):
        alert = {"type": "disk", "level": "warning"}
        daemon._should_dispatch("srv1", alert)
        assert daemon._should_dispatch("srv1", alert) is False

    def test_should_dispatch_escalation(self, daemon):
        daemon._should_dispatch("srv1", {"type": "disk", "level": "warning"})
        alert = {"type": "disk", "level": "critical"}
        assert daemon._should_dispatch("srv1", alert) is True
