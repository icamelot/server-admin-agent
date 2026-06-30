"""Tests for agent-shell-filter — the server-side command validation script.

This test file validates the filter logic, which would normally run
on the target server as an SSH forced-command wrapper.
"""

import pytest
from unittest.mock import patch
from tools.executor.agent_shell_filter import (
    validate_totp,
    parse_ssh_command_input,
    SERVER_SIDE_BLOCKED,
)


class TestValidateTotp:
    def test_valid_totp_format(self):
        with patch("pyotp.TOTP") as mock_totp_class:
            mock_totp_instance = mock_totp_class.return_value
            mock_totp_instance.verify.return_value = True
            assert validate_totp("123456", "JBSWY3DPEHPK3PXP") is True
            mock_totp_class.assert_called_once_with("JBSWY3DPEHPK3PXP")
            mock_totp_instance.verify.assert_called_once_with("123456", valid_window=1)

    def test_invalid_totp_rejected(self):
        with patch("pyotp.TOTP") as mock_totp_class:
            mock_totp_instance = mock_totp_class.return_value
            mock_totp_instance.verify.return_value = False
            assert validate_totp("000000", "JBSWY3DPEHPK3PXP") is False

    def test_non_numeric_rejected(self):
        assert validate_totp("abc123", "JBSWY3DPEHPK3PXP") is False

    def test_wrong_length_rejected(self):
        assert validate_totp("12345", "JBSWY3DPEHPK3PXP") is False


class TestParseSshCommandInput:
    def test_standard_input(self):
        totp, command = parse_ssh_command_input("123456 systemctl restart nginx")
        assert totp == "123456"
        assert command == "systemctl restart nginx"

    def test_command_with_spaces(self):
        totp, command = parse_ssh_command_input("654321 apt install -y htop")
        assert totp == "654321"
        assert command == "apt install -y htop"

    def test_missing_totp_returns_none(self):
        totp, command = parse_ssh_command_input("systemctl restart nginx")
        assert totp is None
        assert command == "systemctl restart nginx"

    def test_empty_input(self):
        totp, command = parse_ssh_command_input("")
        assert totp is None
        assert command == ""


class TestServerSideBlocked:
    def test_rm_rf_blocked_anyway(self):
        """Even if TOTP is valid, certain patterns are blocked unconditionally."""
        assert SERVER_SIDE_BLOCKED("rm -rf /") is True

    def test_mkfs_blocked(self):
        assert SERVER_SIDE_BLOCKED("mkfs.ext4 /dev/sda") is True

    def test_shutdown_blocked(self):
        assert SERVER_SIDE_BLOCKED("shutdown -h now") is True

    def test_dd_if_of_disk_blocked(self):
        assert SERVER_SIDE_BLOCKED("dd if=/dev/zero of=/dev/sdb") is True

    def test_normal_command_allowed(self):
        assert SERVER_SIDE_BLOCKED("systemctl restart nginx") is False

    def test_useradd_allowed(self):
        assert SERVER_SIDE_BLOCKED("useradd newuser") is False
