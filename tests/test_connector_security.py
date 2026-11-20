import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from engine.connectors.ssh_connector import SSHConnector
from engine.connectors.rest_connector import RESTConnector
from engine.connectors.snmp_connector import SNMPConnector
from engine.policy.audit import AuditLogger
from engine.policy.security_policy import SecurityPolicyEngine, ApprovalVerificationResult
from engine.policy.types import OperationRequest, OperationClassification, ExecutionMode, TargetDevice
from tests.helpers.auth_test_helper import create_test_context


class TestConnectorHardening(unittest.TestCase):
    def test_ssh_defaults_to_reject_unknown_host_keys(self):
        connector = SSHConnector("router.example", host_key_policy="RejectUnknown")
        self.assertEqual(connector.host_key_policy, "RejectUnknown")

    def test_ssh_rejects_auto_add_policy(self):
        connector = SSHConnector("router.example", host_key_policy="AutoAdd")
        with mock.patch("engine.connectors.ssh_connector.PARAMIKO_AVAILABLE", False):
            with self.assertRaises(ValueError):
                connector.connect({})

    def test_rest_requires_tls_verification(self):
        with self.assertRaises(ValueError):
            RESTConnector("router.example", use_https=False)
        with self.assertRaises(ValueError):
            RESTConnector("router.example", verify_ssl=False)

    def test_rest_rejects_url_as_host(self):
        with self.assertRaises(ValueError):
            RESTConnector("https://evil.example/path")
        with self.assertRaises(ValueError):
            RESTConnector("bad host")
        with self.assertRaises(ValueError):
            RESTConnector("evil.example\r\nX-Header: injected")

    def test_rest_mutating_method_rejected_by_default(self):
        connector = RESTConnector("router.example")
        connector.is_connected = True
        connector.session = mock.Mock()
        with self.assertRaises(PermissionError):
            connector.request("POST", "/api/config", data={"x": 1})
        connector.session.request.assert_not_called()

    def test_rest_rejects_unsafe_api_key_header(self):
        connector = RESTConnector("router.example")
        with self.assertRaises(ValueError):
            connector.connect({"api_key": "secret", "api_key_header": "Authorization\r\nInjected"})

    def test_rest_endpoint_cannot_override_host(self):
        connector = RESTConnector("router.example")
        connector.is_connected = True
        connector.session = mock.Mock()
        with self.assertRaises(ValueError):
            connector.request("GET", "https://evil.example/steal")
        with self.assertRaises(ValueError):
            connector.request("GET", "//evil.example/steal")
        with self.assertRaises(ValueError):
            connector.request("GET", "/../admin")
        connector.session.request.assert_not_called()

    def test_ssh_direct_command_rejects_shell_and_write_by_default(self):
        connector = SSHConnector("router.example")
        connector.is_connected = True
        connector.client = mock.Mock()
        with self.assertRaises(PermissionError):
            connector.execute_command("show ip route; reboot")
        with self.assertRaises(PermissionError):
            connector.execute_command("/system reboot")
        connector.client.exec_command.assert_not_called()

    def test_rest_encoded_path_traversal_rejected(self):
        connector = RESTConnector("router.example")
        connector.is_connected = True
        connector.session = mock.Mock()
        with self.assertRaises(ValueError):
            connector.request("GET", "/%2e%2e/admin")
        connector.session.request.assert_not_called()

    def test_snmp_live_connect_fails_closed_not_simulated(self):
        connector = SNMPConnector("router.example")
        with self.assertRaises(NotImplementedError):
            connector.connect({"community": "public"})
        self.assertFalse(connector.is_connected)


class TestAuditHardening(unittest.TestCase):
    def test_sensitive_fields_are_redacted_and_permissions_restricted(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            logger = AuditLogger(path)
            logger.log_event("TEST", "user", "router", "action", {
                "password": "supersecret",
                "nested": {"api_key": "keysecret", "snmp_community": "communitysecret", "text": "token=tokensecret"},
            }, "OK")
            record = json.loads(Path(path).read_text())
            self.assertEqual(record["details"]["password"], "***REDACTED***")
            self.assertEqual(record["details"]["nested"]["api_key"], "***REDACTED***")
            self.assertNotIn("supersecret", Path(path).read_text())
            self.assertNotIn("keysecret", Path(path).read_text())
            self.assertNotIn("communitysecret", Path(path).read_text())
            if os.name != "nt":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_symlink_audit_target_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "real.log"
            target.write_text("safe")
            link = Path(d) / "audit.log"
            link.symlink_to(target)
            with self.assertRaises(PermissionError):
                AuditLogger(str(link))


class TestInventoryTrustBoundary(unittest.TestCase):
    def test_inventory_rejects_symlink(self):
        from engine.inventory.inventory_manager import DeviceInventoryManager
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "inventory.json"
            target.write_text("[]")
            link = Path(d) / "linked.json"
            link.symlink_to(target)
            with self.assertRaises(PermissionError):
                DeviceInventoryManager(str(link))

    def test_inventory_rejects_duplicate_management_ip(self):
        from engine.inventory.inventory_manager import DeviceInventoryManager
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "devices.json"
            device1 = {"device_id": "r1", "hostname": "r1", "ip_address": "192.0.2.1", "vendor": "x", "model": "y"}
            device2 = {"device_id": "r2", "hostname": "r2", "ip_address": "192.0.2.1", "vendor": "x", "model": "y"}
            path.write_text(json.dumps([device1, device2]))
            manager = DeviceInventoryManager(str(path))
            with self.assertRaises(ValueError):
                manager.list_devices()

    def test_inventory_rejects_duplicate_ids(self):
        from engine.inventory.inventory_manager import DeviceInventoryManager
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "devices.json"
            device = {"device_id": "r1", "hostname": "r1", "ip_address": "192.0.2.1", "vendor": "x", "model": "y"}
            path.write_text(json.dumps([device, device]))
            manager = DeviceInventoryManager(str(path))
            with self.assertRaises(ValueError):
                manager.list_devices()


class TestPolicyHardening(unittest.TestCase):
    def _request(self, command):
        user = create_test_context("policy-user", "dev", {"READ_ONLY", "DIAGNOSTIC"})
        device = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", device_category="router", environment="SIMULATED")
        return OperationRequest("req", user, device, OperationClassification.READ_ONLY, "raw", command=command, execution_mode=ExecutionMode.DRY_RUN)

    def test_shell_operators_rejected(self):
        policy = SecurityPolicyEngine()
        for command in ("show ip route; reboot", "show ip route | grep default", "show ip route && reboot", "show ip route\nreboot", "show $HOME"):
            with self.subTest(command=command):
                valid, reason = policy.validate_request(self._request(command))
                self.assertFalse(valid)
                self.assertIn("shell", reason.lower())

    def test_write_approval_requires_external_provider(self):
        user = create_test_context("policy-user", "dev", {"READ_ONLY", "DIAGNOSTIC"})
        device = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", device_category="router", environment="SIMULATED")
        request = OperationRequest("req", user, device, OperationClassification.WRITE, "apply_config", command="/interface set 0 disabled=yes", approved=True, approval_token="legacy-token", execution_mode=ExecutionMode.DRY_RUN)
        valid, reason = SecurityPolicyEngine().validate_request(request)
        self.assertFalse(valid)
        self.assertIn("lacks authorization", reason)

    def test_apply_config_cannot_be_declared_read_only(self):
        request = self._request("show ip route")
        request.action = "apply_config"
        valid, reason = SecurityPolicyEngine().validate_request(request)
        self.assertFalse(valid)
        self.assertIn("WRITE classification", reason)

    def test_parameter_command_list_shell_injection_rejected(self):
        request = self._request(None)
        request.parameters = {"commands": ["/interface set 0 disabled=yes; reboot"]}
        valid, reason = SecurityPolicyEngine().validate_request(request)
        self.assertFalse(valid)
        self.assertIn("shell control", reason)

    def test_ping_target_and_count_are_validated(self):
        request = self._request(None)
        request.action = "ping"
        request.classification = OperationClassification.DIAGNOSTIC
        request.parameters = {"target": "8.8.8.8;reboot", "count": 4}
        valid, reason = SecurityPolicyEngine().validate_request(request)
        self.assertFalse(valid)
        self.assertIn("target", reason.lower())

    def test_approval_verifier_receives_exact_target_and_diff_hash(self):
        from types import SimpleNamespace
        user = SimpleNamespace(username="policy-user", role="test", authorized_scopes=frozenset({"WRITE"}), has_scope=lambda scope: True, can_access_device=lambda _id: True)
        device = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", device_category="router", environment="SIMULATED")
        request = OperationRequest("req", user, device, OperationClassification.WRITE, "apply_config", command="/interface set 0 disabled=yes", approved=False, approval_token="external-approval", execution_mode=ExecutionMode.DRY_RUN)
        expected = SecurityPolicyEngine._canonical_diff_hash(request)
        verifier = mock.Mock(return_value=ApprovalVerificationResult(
            approved=True, requester="policy-user", target_id="RTR-CORE-01", classification="WRITE",
            request_id="req", diff_hash=expected, approver_ids=frozenset({"supervisor"}),
            expires_at="2099-01-01T00:00:00Z",
        ))
        policy = SecurityPolicyEngine(approval_verifier=verifier)
        with mock.patch("engine.policy.security_policy.is_production_identity", return_value=True):
            valid, _ = policy.validate_request(request)
        self.assertTrue(valid)
        verifier.assert_called_once_with(token="external-approval", requester="policy-user", target_id="RTR-CORE-01", classification="WRITE", request_id="req", diff_hash=expected)

    def test_approval_claim_mismatch_rejected(self):
        from types import SimpleNamespace
        user = SimpleNamespace(username="requester", role="test", authorized_scopes=frozenset({"WRITE"}), has_scope=lambda scope: True, can_access_device=lambda _id: True)
        device = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", device_category="router", environment="SIMULATED")
        request = OperationRequest("req", user, device, OperationClassification.WRITE, "apply_config", command="/interface set 0 disabled=yes", approval_token="token")
        expected_hash = SecurityPolicyEngine._canonical_diff_hash(request)
        verifier = mock.Mock(return_value=ApprovalVerificationResult(approved=True, requester="requester", target_id="SW-AGG-01", classification="WRITE", request_id="req", diff_hash=expected_hash, approver_ids=frozenset({"supervisor"}), expires_at="2099-01-01T00:00:00Z"))
        with mock.patch("engine.policy.security_policy.is_production_identity", return_value=True):
            valid, reason = SecurityPolicyEngine(verifier).validate_request(request)
        self.assertFalse(valid)
        self.assertIn("claims", reason)

    def test_critical_requires_two_distinct_approvers(self):
        from types import SimpleNamespace
        user = SimpleNamespace(username="requester", role="test", authorized_scopes=frozenset({"CRITICAL"}), has_scope=lambda scope: True, can_access_device=lambda _id: True)
        device = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", device_category="router", environment="SIMULATED")
        request = OperationRequest("req", user, device, OperationClassification.CRITICAL, "reboot", command="/system reboot", approval_token="token")
        diff_hash = SecurityPolicyEngine._canonical_diff_hash(request)
        evidence = ApprovalVerificationResult(approved=True, requester="requester", target_id="RTR-CORE-01", classification="CRITICAL", request_id="req", diff_hash=diff_hash, approver_ids=frozenset({"supervisor1"}), expires_at="2099-01-01T00:00:00Z")
        with mock.patch("engine.policy.security_policy.is_production_identity", return_value=True):
            valid, reason = SecurityPolicyEngine(lambda **_: evidence).validate_request(request)
        self.assertFalse(valid)
        self.assertIn("two distinct approvers", reason)


if __name__ == "__main__":
    unittest.main()
