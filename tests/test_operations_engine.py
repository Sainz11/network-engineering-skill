import unittest
import tempfile
import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from engine.auth_provider import UserContext as AuthUserContext, LocalDevAuthProvider
from tests.helpers.auth_test_helper import create_test_context
from engine.policy.types import TargetDevice, UserContext, OperationRequest, OperationClassification, ExecutionMode
from engine.policy.security_policy import SecurityPolicyEngine
from engine.policy.audit import AuditLogger
from engine.execution.operations_engine import OperationsEngine
from engine.connectors.mock_connector import MockConnector
from engine.adapters.factory import AdapterFactory
from engine.inventory.inventory_manager import DeviceInventoryManager
from unittest import mock

class TestEngineLayer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.audit_log = os.path.join(self.temp_dir, "test_audit.jsonl")
        self.engine = OperationsEngine(audit_log_path=self.audit_log)

        self.mock_rtr = TargetDevice(
            device_id="RTR-CORE-01",
            hostname="core-rtr01.isp.net",
            ip_address="10.0.0.1",
            vendor="MikroTik",
            model="CCR2004-16G-2S+",
            device_category="router",
            environment="SIMULATED",
            port=22,
            protocol="ssh",
        )
        self.user_eng = create_test_context(
            username="engineer1",
            role="NOC_Engineer",
            scopes=frozenset(["READ_ONLY", "DIAGNOSTIC"]),
            is_dev_mode=True,
            authorized_devices=frozenset(["*"])
        )
        self.user_ro = create_test_context(
            username="guest_user",
            role="ReadOnlyTech",
            scopes=frozenset(["READ_ONLY"]),
            is_dev_mode=True,
            authorized_devices=frozenset(["*"])
        )

    def test_policy_classification_detection(self):
        policy = SecurityPolicyEngine()
        self.assertEqual(policy.classify_command("show ip route"), OperationClassification.READ_ONLY)
        self.assertEqual(policy.classify_command("/ip address print"), OperationClassification.READ_ONLY)
        self.assertEqual(policy.classify_command("ping 8.8.8.8"), OperationClassification.DIAGNOSTIC)
        self.assertEqual(policy.classify_command("/tool traceroute 1.1.1.1"), OperationClassification.DIAGNOSTIC)
        self.assertEqual(policy.classify_command("configure terminal"), OperationClassification.WRITE)
        self.assertEqual(policy.classify_command("/interface set 0 disabled=yes"), OperationClassification.WRITE)
        self.assertEqual(policy.classify_command("reload"), OperationClassification.CRITICAL)
        self.assertEqual(policy.classify_command("/system reboot"), OperationClassification.CRITICAL)

    def test_unauthorized_user_blocked(self):
        req = OperationRequest(
            request_id="REQ-001",
            user=self.user_ro,
            device=self.mock_rtr,
            classification=OperationClassification.WRITE,
            action="apply_config",
            command="/interface set 0 disabled=yes",
            execution_mode=ExecutionMode.SIMULATED
        )
        res = self.engine.execute(req)
        self.assertFalse(res.success)
        self.assertIn("lacks authorization for WRITE", res.error)

    def test_unapproved_write_blocked(self):
        req = OperationRequest(
            request_id="REQ-002",
            user=self.user_eng,
            device=self.mock_rtr,
            classification=OperationClassification.WRITE,
            action="apply_config",
            command="/interface set 0 disabled=yes",
            execution_mode=ExecutionMode.SIMULATED,
            approved=False # not approved!
        )
        res = self.engine.execute(req)
        self.assertFalse(res.success)
        self.assertIn("lacks authorization for WRITE", res.error)

    def test_dry_run_execution(self):
        req = OperationRequest(
            request_id="REQ-003",
            user=self.user_eng,
            device=self.mock_rtr,
            classification=OperationClassification.READ_ONLY,
            action="system_info",
            execution_mode=ExecutionMode.DRY_RUN,
        )
        res = self.engine.execute(req)
        self.assertTrue(res.success)
        self.assertEqual(res.mode, ExecutionMode.DRY_RUN)
        self.assertIn("Dry-run completed", res.output["message"])

    def test_simulated_execution_and_audit(self):
        req = OperationRequest(
            request_id="REQ-004",
            user=self.user_eng,
            device=self.mock_rtr,
            classification=OperationClassification.READ_ONLY,
            action="system_info",
            execution_mode=ExecutionMode.SIMULATED
        )
        res = self.engine.execute(req)
        self.assertTrue(res.success)
        self.assertEqual(res.status, "SIMULATED")
        self.assertEqual(res.output["vendor"], "MikroTik")
        self.assertIn("version", res.output)

        # Verify audit record written
        self.assertTrue(os.path.exists(self.audit_log))
        with open(self.audit_log, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertGreater(len(lines), 0)
        self.assertIn("OPERATION_SUCCESS", lines[-1])

    def test_unknown_target_rejected_before_connector(self):
        req = OperationRequest(request_id="REQ-005", user=self.user_eng, device=TargetDevice(
            device_id="unknown", hostname="unknown", ip_address="203.0.113.10", vendor="Cisco", model="unknown", environment="SIMULATED"),
            classification=OperationClassification.READ_ONLY, action="system_info", execution_mode=ExecutionMode.SIMULATED)
        with mock.patch("engine.execution.operations_engine.MockConnector") as connector:
            result = self.engine.execute(req)
        self.assertFalse(result.success)
        self.assertIn("not registered", result.error)
        connector.assert_not_called()

    def test_target_ip_substitution_rejected_before_connector(self):
        spoofed = TargetDevice(device_id="RTR-CORE-01", hostname="core-rtr01.isp.net", ip_address="203.0.113.7", vendor="MikroTik", model="CCR2004-16G-2S+", device_category="router", environment="SIMULATED")
        req = OperationRequest(request_id="REQ-006", user=self.user_eng, device=spoofed, classification=OperationClassification.READ_ONLY, action="system_info", execution_mode=ExecutionMode.SIMULATED)
        with mock.patch("engine.execution.operations_engine.MockConnector") as connector:
            result = self.engine.execute(req)
        self.assertFalse(result.success)
        self.assertIn("ip_address", result.error)
        connector.assert_not_called()

    def test_live_mode_fails_closed_without_production_identity_and_credentials(self):
        req = OperationRequest(request_id="REQ-007", user=self.user_eng, device=self.mock_rtr, classification=OperationClassification.READ_ONLY, action="system_info", execution_mode=ExecutionMode.LIVE)
        with mock.patch("engine.execution.operations_engine.SSHConnector") as connector:
            result = self.engine.execute(req)
        self.assertFalse(result.success)
        self.assertIn("SIMULATED", result.error)
        connector.assert_not_called()

    def test_output_redaction_applies_recursively(self):
        result = self.engine._redact_output({"password": "secret", "nested": [{"token": "abc"}, "community=public"]})
        self.assertEqual(result["password"], "***REDACTED***")
        self.assertEqual(result["nested"][0]["token"], "***REDACTED***")
        self.assertNotIn("public", result["nested"][1])

    def test_adapter_factory(self):
        conn = MockConnector(vendor="cisco")
        conn.connect({"username": "admin"})
        adapter = AdapterFactory.get_adapter("cisco", conn)
        info = adapter.get_system_info()
        self.assertEqual(info["vendor"], "Cisco")
        self.assertIn("IOS XE", info["software"])

if __name__ == '__main__':
    unittest.main()
