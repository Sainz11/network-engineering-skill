import unittest
import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from engine.winbox.locator import WinboxLocator
from engine.connectors.mock_connector import MockConnector
from engine.adapters.mikrotik_adapter import MikroTikAdapter

class TestRealRouterValidation(unittest.TestCase):
    """
    Validation test suite for MikroTik RouterOS hardware integration.
    Strict safety rule: Runs ONLY READ_ONLY operations.
    If no real router is configured in the environment, flags status explicitly as NOT VERIFIED.
    """
    def setUp(self):
        self.target_ip = os.environ.get("LAB_MIKROTIK_IP")
        self.username = os.environ.get("LAB_MIKROTIK_USER")
        self.password = os.environ.get("LAB_MIKROTIK_PASS")
        self.is_real_hardware_available = bool(self.target_ip and self.username)

    def test_read_only_hardware_interrogation(self):
        if not self.is_real_hardware_available:
            self.skipTest("Real hardware not configured (LAB_MIKROTIK_IP unset). Hardware status: NOT VERIFIED.")

        # Real router test execution (READ-ONLY ONLY)
        from engine.connectors.ssh_connector import SSHConnector
        conn = SSHConnector(host=self.target_ip, port=22, timeout=10)
        conn.connect({"username": self.username, "password": self.password})
        adapter = MikroTikAdapter(conn)

        # 1. System Info
        sys_info = adapter.get_system_info()
        self.assertEqual(sys_info["vendor"], "MikroTik")
        self.assertIn("version", sys_info)

        # 2. Interfaces
        interfaces = adapter.get_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)

        # 3. Read-only ping check
        ping_res = adapter.run_diagnostic_ping("1.1.1.1", count=2)
        self.assertIn("target", ping_res)

        conn.disconnect()

    def test_mock_fallback_read_only_operations(self):
        # Deterministic simulation verifying read-only contracts
        conn = MockConnector(vendor="mikrotik")
        conn.connect({"username": "admin"})
        adapter = MikroTikAdapter(conn)

        sys_info = adapter.get_system_info()
        self.assertEqual(sys_info["vendor"], "MikroTik")
        self.assertEqual(sys_info["version"], "7.15.2 (stable)")

        interfaces = adapter.get_interfaces()
        self.assertGreater(len(interfaces), 0)

        ping_res = adapter.run_diagnostic_ping("8.8.8.8", count=2)
        self.assertEqual(ping_res["packet_loss"], "0%")

        conn.disconnect()

if __name__ == '__main__':
    unittest.main()
