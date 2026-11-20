import unittest
import os
from unittest import mock
import os
import tempfile
from engine.winbox.locator import WinboxLocator
from engine.winbox.selector import ConnectorSelector
from engine.winbox.mock_adapter import MockWinboxAdapter
from engine.winbox.ui_automation import WindowsUIAWrapper

class TestWinboxLiveSecurity(unittest.TestCase):
    def test_open_session_rejects_caller_credentials(self):
        from engine.winbox.adapter import WinboxAdapter
        adapter = WinboxAdapter(winbox_path="winbox.exe")
        with self.assertRaises(PermissionError):
            adapter.open_session("RTR-CORE-01", "admin", "secret")

    def test_open_session_rejects_without_verified_context(self):
        from engine.winbox.adapter import WinboxAdapter
        adapter = WinboxAdapter(winbox_path="winbox.exe")
        with self.assertRaises(PermissionError):
            adapter.open_session("RTR-CORE-01")

    def test_navigate_requires_active_session(self):
        from engine.winbox.adapter import WinboxAdapter
        adapter = WinboxAdapter(winbox_path="winbox.exe")
        with self.assertRaises(PermissionError):
            adapter.navigate_menu("interfaces")

    def test_live_winbox_rejects_development_identity(self):
        from engine.winbox.adapter import WinboxAdapter
        from engine.auth_provider import LocalDevAuthProvider
        from engine.inventory.inventory_manager import DeviceInventoryManager
        from engine.policy.types import TargetDevice
        from unittest.mock import Mock
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "dev-user"}):
            user = LocalDevAuthProvider().authenticate()
        inventory = Mock()
        inventory.get_device.return_value = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", credentials_ref="vault://rtr", environment="PRODUCTION")
        credentials = Mock()
        adapter = WinboxAdapter(winbox_path="winbox.exe", user_ctx=user, inventory_manager=inventory, credential_provider=credentials)
        with self.assertRaises(PermissionError):
            adapter.open_session("RTR-CORE-01")
        credentials.get_credentials.assert_not_called()


class TestWinboxIntegration(unittest.TestCase):
    def setUp(self):
        self.mock_adapter = MockWinboxAdapter()
        self.temp_dir = tempfile.mkdtemp()

    def test_winbox_locator_methods(self):
        # Locator should safely return None or string path without crashing
        path = WinboxLocator.find_executable()
        self.assertTrue(path is None or isinstance(path, str))

        # Check process listing query
        procs = WinboxLocator.get_running_processes()
        self.assertIsInstance(procs, list)

    def test_connector_selector_logic(self):
        # 1. Visual/GUI request with Winbox available -> Winbox
        conn, reason = ConnectorSelector.select_connector("visual_inspection", winbox_available=True)
        self.assertEqual(conn, "winbox")
        self.assertIn("selecting Winbox GUI", reason)

        # 2. Visual request with Winbox NOT available -> Fallback to SSH
        conn, reason = ConnectorSelector.select_connector("visual_inspection", winbox_available=False)
        self.assertEqual(conn, "ssh")
        self.assertIn("falling back to SSH", reason)

        # 3. High throughput bulk API request -> API
        conn, reason = ConnectorSelector.select_connector("bulk_provisioning_api")
        self.assertEqual(conn, "api")

        # 4. Standard operation -> SSH
        conn, reason = ConnectorSelector.select_connector("standard_routing_check")
        self.assertEqual(conn, "ssh")

    def test_mock_winbox_lifecycle(self):
        # Initial status
        st = self.mock_adapter.get_status()
        self.assertTrue(st["installed"])
        self.assertIsNone(st["active_session"])

        # Launch
        res_launch = self.mock_adapter.launch()
        self.assertEqual(res_launch["status"], "LAUNCHED")
        self.assertTrue(self.mock_adapter.is_running)

        # Open session with credential redaction check
        res_sess = self.mock_adapter.open_session("10.0.0.1", "admin", "SecretPass123!")
        self.assertEqual(res_sess["status"], "SESSION_OPENED")
        self.assertEqual(self.mock_adapter.active_session["password"], "***REDACTED***")

        # Menu navigation across supported menus
        nav_res = self.mock_adapter.navigate_menu("System -> Resources")
        self.assertTrue(nav_res["success"])
        self.assertEqual(self.mock_adapter.current_menu, "System -> Resources")

        nav_res2 = self.mock_adapter.navigate_menu("IP -> Addresses")
        self.assertTrue(nav_res2["success"])

        # Unsupported menu rejected
        bad_nav = self.mock_adapter.navigate_menu("NonExistent -> Submenu")
        self.assertFalse(bad_nav["success"])
        self.assertIn("error", bad_nav)

        # Evidence capture
        shot_path = os.path.join(self.temp_dir, "winbox_evidence.png")
        cap_res = self.mock_adapter.capture_evidence(shot_path)
        self.assertTrue(cap_res["success"])
        self.assertIn(shot_path, self.mock_adapter.captured_screenshots)

        # Close session
        close_res = self.mock_adapter.close_session()
        self.assertEqual(close_res["status"], "CLOSED")
        self.assertFalse(self.mock_adapter.is_running)
        self.assertIsNone(self.mock_adapter.active_session)

    def test_mock_authentication_failure(self):
        with self.assertRaises(PermissionError):
            self.mock_adapter.open_session("10.0.0.1", "invalid_user", "wrongpass")

    def test_windows_uia_wrapper(self):
        uia = WindowsUIAWrapper()
        # Verify basic query functions run safely without uncaught exceptions
        windows = uia.list_windows_by_title("desktop")
        self.assertIsInstance(windows, list)

if __name__ == '__main__':
    unittest.main()
