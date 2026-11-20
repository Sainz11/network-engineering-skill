import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from engine.adapters.factory import AdapterFactory
from engine.connectors.mock_connector import MockConnector
from engine.discovery.models import DiscoveredDevice, DiscoveredNeighbor, DiscoverySource, LinkConfidence
from engine.execution.module_workflow import execute_authorized_module_workflow
from engine.execution.operations_engine import OperationsEngine
from engine.evidence_manager import OperationEvidenceManager, EvidenceRegistryError
from engine.approval_manager import ApprovalManager
from engine.inventory.inventory_manager import DeviceInventoryManager
from engine.policy.security_policy import SecurityPolicyEngine
from engine.policy.types import OperationClassification, OperationRequest, ExecutionMode, TargetDevice
from engine.topology.topology_engine import TopologyEngine
from engine.topology.visualizer import TopologyVisualizer
from engine.winbox.adapter import WinboxAdapter
from engine.winbox.ui_automation import WindowsUIAWrapper
from scripts.qc_engine import QCTestEngine, DeviceIdentity, DecisionEngine, TestResult, TestStatus, FinalQCStatus, QCHistoryManager
from scripts.acs_integration.mock_connector import MockACSConnector
from scripts.acs_integration.provisioning_workflow import ISPProvisioningSimulationService
from engine.discovery.collector import DiscoveryCollector
from engine.troubleshoot.engine import TroubleshootEngine, COMMAND_CATALOG
from tests.helpers.auth_test_helper import create_test_context


class TestP0Remediation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="network-remediation-test-")

    def test_topology_html_and_svg_escape_network_data(self):
        payload = '</text><script>alert("xss")</script><img src=x onerror=alert(1)>'
        data = {
            "devices": [{
                "device_id": payload, "hostname": payload, "management_ip": payload,
                "vendor": payload, "model": payload, "role": payload,
                "health_status": payload, "health_metrics": {payload: payload},
            }],
            "links": [{
                "link_id": payload, "source": payload, "source_interface": payload,
                "target": payload, "target_interface": payload, "confidence": "UNKNOWN",
                "evidence_sources": [payload], "status": payload,
                "metrics": {"hostile": payload},
            }],
        }
        svg_path = os.path.join(self.temp_dir, "topology.svg")
        html_path = os.path.join(self.temp_dir, "topology.html")
        visualizer = TopologyVisualizer(data)
        visualizer.generate_svg(svg_path)
        visualizer.generate_html_viewer(html_path)
        svg = Path(svg_path).read_text(encoding="utf-8")
        html = Path(html_path).read_text(encoding="utf-8")
        for output in (svg, html):
            self.assertNotIn("<script>alert", output)
            self.assertNotIn('<img src=x', output)
            self.assertIn('&lt;img', output)
            self.assertIn("&lt;script&gt;", output)
        self.assertNotIn(">HEALTHY</b>", html)
        self.assertIn("Reported Health", html)

    def test_critical_command_variants_classified_conservatively(self):
        policy = SecurityPolicyEngine()
        variants = [
            "system reset-configuration",
            "reset-configuration",
            "/system reset-configuration",
            "delete flash:config.text",
            "erase startup-config",
            "write erase",
            "firmware upgrade",
            "install os",
            "request platform software package install",
            "/system/routerboard/upgrade",
            "copy startup-config running-config",
            "request system zeroize",
        ]
        for command in variants:
            with self.subTest(command=command):
                self.assertEqual(policy.classify_command(command), OperationClassification.CRITICAL)

    def test_unknown_clear_configuration_command_is_denied(self):
        policy = SecurityPolicyEngine()
        user = create_test_context("policy-clear", "ignored", frozenset({"READ_ONLY", "DIAGNOSTIC"}))
        target = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", environment="SIMULATED")
        request = OperationRequest(
            "SEC-UNKNOWN-CLEAR", user, target, OperationClassification.CRITICAL,
            "raw", command="vendor clear configuration all", execution_mode=ExecutionMode.SIMULATED,
        )
        valid, reason = policy.validate_request(request)
        self.assertFalse(valid)
        self.assertIn("Unrecognized potentially destructive", reason)

    def test_unknown_destructive_command_form_is_denied(self):
        policy = SecurityPolicyEngine()
        user = create_test_context("policy-test", "ignored", frozenset({"READ_ONLY", "DIAGNOSTIC"}))
        target = TargetDevice("RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004", environment="SIMULATED")
        request = OperationRequest(
            "SEC-UNKNOWN-DESTRUCTIVE", user, target, OperationClassification.CRITICAL,
            "raw", command="vendor magic wipe storage", execution_mode=ExecutionMode.SIMULATED,
        )
        valid, reason = policy.validate_request(request)
        self.assertFalse(valid)
        self.assertIn("Unrecognized potentially destructive", reason)

    def test_vendor_factory_uses_exact_aliases(self):
        connector = MockConnector(vendor="cisco")
        self.assertEqual(type(AdapterFactory.get_adapter("Cisco", connector)).__name__, "CiscoAdapter")
        for invalid in ("notcisco", "super-huawei-compatible", "mikrotik-ish"):
            with self.subTest(vendor=invalid):
                with self.assertRaises(ValueError):
                    AdapterFactory.get_adapter(invalid, connector)

    def test_qc_mandatory_pass_requires_valid_evidence_status(self):
        results = [
            TestResult("T-1", "Physical check", "physical", TestStatus.PASS, True),
            TestResult("T-2", "Link check", "network", TestStatus.PASS, True, evidence_status="INVALID"),
        ]
        status, _, findings = DecisionEngine.evaluate(results)
        self.assertEqual(status, FinalQCStatus.NEEDS_REVIEW)
        self.assertEqual(len(findings), 2)

    def test_qc_decision_requires_reference_hash_or_distinct_manual_attestation(self):
        marker_only = TestResult(
            "T-MARKER", "Marker only", "physical", TestStatus.PASS, True,
            evidence_type="MANUAL_ARTIFACT", evidence_status="ARTIFACT_VERIFIED",
        )
        status, _, _ = DecisionEngine.evaluate([marker_only])
        self.assertEqual(status, FinalQCStatus.NEEDS_REVIEW)

        manual = TestResult(
            "T-MANUAL", "Manual visual check", "physical", TestStatus.PASS, True,
            evidence_reference="manual-attestation:technician-1",
            evidence_type="MANUAL_ATTESTATION", evidence_status="MANUAL_ATTESTATION",
            evidence_attestation="Visual inspection completed by technician.",
        )
        status, _, _ = DecisionEngine.evaluate([manual])
        self.assertEqual(status, FinalQCStatus.PASS)

        instrument_without_id = TestResult(
            "T-INSTR", "Optical reading", "optical", TestStatus.PASS, True,
            evidence_reference="meter.txt", evidence_type="INSTRUMENT",
            evidence_status="ARTIFACT_VERIFIED", evidence_sha256="a" * 64,
        )
        status, _, _ = DecisionEngine.evaluate([instrument_without_id])
        self.assertEqual(status, FinalQCStatus.NEEDS_REVIEW)

    def test_qc_engine_rejects_missing_and_unresolvable_evidence(self):
        history_root = os.path.join(self.temp_dir, "history")
        evidence_root = os.path.join(self.temp_dir, "evidence")
        engine = QCTestEngine(
            history_file=os.path.join(history_root, "sessions.json"),
            history_root=history_root,
            evidence_dir=evidence_root,
        )
        device = DeviceIdentity("MikroTik", "RB750Gr3", "SN-TEST", device_category="router")
        measurements = {
            item.id: {"value": "PASS", "evidence_ref": "does-not-exist.bin"}
            for item in engine.catalog.get_applicable_tests("router", engine.profile_loader.get_profile("MikroTik", "RB750Gr3"))
        }
        report = engine.run_qc_session(device, measurements, technician="tester")
        self.assertNotEqual(report.final_status, FinalQCStatus.PASS)
        self.assertTrue(any("Invalid evidence reference" in r.notes for r in report.results if r.status == TestStatus.NEEDS_REVIEW))

    def test_qc_history_rejects_symlink_and_path_escape(self):
        approved = Path(self.temp_dir) / "approved"
        outside = Path(self.temp_dir) / "outside.json"
        approved.mkdir()
        outside.write_text("[]", encoding="utf-8")
        link = approved / "sessions.json"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this platform")
        with self.assertRaises(PermissionError):
            QCHistoryManager(str(link), allowed_root=str(approved))
        with self.assertRaises(PermissionError):
            QCHistoryManager(str(approved / ".." / "outside.json"), allowed_root=str(approved))

    def test_qc_history_concurrent_writes_remain_valid_and_complete(self):
        root = os.path.join(self.temp_dir, "history")
        manager = QCHistoryManager(os.path.join(root, "sessions.json"), allowed_root=root)
        threads = [
            threading.Thread(target=manager.record_session, args=({
                "session_id": f"QC-{index}", "final_status": "NEEDS_REVIEW", "device": {}
            },))
            for index in range(25)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        sessions = manager.load_all()
        self.assertEqual(len(sessions), 25)
        self.assertEqual(len({s["session_id"] for s in sessions}), 25)
        json.loads(Path(manager.history_path).read_text(encoding="utf-8"))

    def test_topology_conflicting_reciprocal_interfaces_not_verified(self):
        device_a = DiscoveredDevice(
            "A", "10.0.0.1", "A", "MikroTik",
            neighbors=[DiscoveredNeighbor("ether1", "B", "ether9", discovery_protocol=DiscoverySource.LLDP)],
        )
        device_b = DiscoveredDevice(
            "B", "10.0.0.2", "B", "Cisco",
            neighbors=[DiscoveredNeighbor("ether2", "A", "ether8", discovery_protocol=DiscoverySource.LLDP)],
        )
        _, links = TopologyEngine().build_topology([device_a, device_b])
        self.assertEqual(len(links), 1)
        self.assertNotEqual(links[0].confidence, LinkConfidence.VERIFIED)
        self.assertEqual(links[0].status, "CONFLICT")
        self.assertIn("interface_conflict", links[0].metrics)
        self.assertEqual(len(links[0].metrics["observations"]), 2)

    def test_topology_consistent_reciprocal_interfaces_remain_verified(self):
        device_a = DiscoveredDevice(
            "A", "10.0.0.1", "A", "MikroTik",
            neighbors=[DiscoveredNeighbor("ether1", "B", "ether9", discovery_protocol=DiscoverySource.LLDP)],
        )
        device_b = DiscoveredDevice(
            "B", "10.0.0.2", "B", "Cisco",
            neighbors=[DiscoveredNeighbor("ether9", "A", "ether1", discovery_protocol=DiscoverySource.LLDP)],
        )
        _, links = TopologyEngine().build_topology([device_a, device_b])
        self.assertEqual(links[0].confidence, LinkConfidence.VERIFIED)

    def test_operations_engine_uses_authorized_request_snapshot(self):
        inventory = DeviceInventoryManager()
        engine = OperationsEngine(audit_log_path=os.path.join(self.temp_dir, "snapshot-audit.jsonl"), inventory_manager=inventory)
        user = create_test_context("snapshot-user", "ignored", frozenset({"READ_ONLY", "DIAGNOSTIC"}))
        request = OperationRequest(
            "OPS-SNAPSHOT", user, inventory.get_device("RTR-CORE-01"),
            OperationClassification.READ_ONLY, "system_info", execution_mode=ExecutionMode.SIMULATED,
        )
        original_validate = engine.policy_engine.validate_request
        def mutate_caller_after_snapshot(snapshot):
            self.assertIsNot(snapshot, request)
            request.action = "totally_unknown_action"
            return original_validate(snapshot)
        engine.policy_engine.validate_request = mutate_caller_after_snapshot
        result = engine.execute(request)
        self.assertTrue(result.success)
        self.assertEqual(result.status, "SIMULATED")
        self.assertEqual(request.action, "totally_unknown_action")

    def test_operations_engine_uses_fail_closed_approval_manager(self):
        engine = OperationsEngine(audit_log_path=os.path.join(self.temp_dir, "approval-audit.jsonl"))
        self.assertFalse(engine.approval_manager.is_configured)
        self.assertIsNone(engine.policy_engine.approval_verifier)
        with self.assertRaises(TypeError):
            ApprovalManager(provider=object())

    def test_unknown_operations_engine_action_is_unsupported(self):
        root = tempfile.mkdtemp(prefix="inventory-")
        inventory_path = os.path.join(root, "devices.json")
        Path(inventory_path).write_text(json.dumps([{
            "device_id": "RTR-CORE-01", "hostname": "core-rtr01.isp.net", "ip_address": "10.0.0.1",
            "vendor": "MikroTik", "model": "CCR2004", "port": 22, "protocol": "ssh", "environment": "SIMULATED"
        }]), encoding="utf-8")
        inventory = DeviceInventoryManager(inventory_path)
        engine = OperationsEngine(audit_log_path=os.path.join(root, "audit.jsonl"), inventory_manager=inventory)
        user = create_test_context("unknown-op", "ignored", frozenset({"READ_ONLY", "DIAGNOSTIC"}))
        request = OperationRequest(
            "OPS-UNKNOWN", user, inventory.get_device("RTR-CORE-01"), OperationClassification.READ_ONLY,
            "totally_unknown_action", execution_mode=ExecutionMode.SIMULATED,
        )
        with mock.patch("engine.execution.operations_engine.MockConnector") as connector:
            result = engine.execute(request)
        self.assertFalse(result.success)
        self.assertEqual(result.status, "UNSUPPORTED")
        self.assertEqual(result.output["status"], "UNSUPPORTED")
        connector.assert_not_called()

    def test_live_winbox_process_without_router_window_is_not_session_success(self):
        class FakeProcess:
            pid = 123
            def poll(self): return None
            def terminate(self): pass
            def wait(self, timeout=None): return 0
            def kill(self): pass
        class FakeUI:
            def detect_dialog_error(self, parent): return None
            def list_windows_by_title(self, pattern): return []
        class FakeContext:
            username = "operator"
            is_dev_mode = False
            def has_scope(self, scope): return scope == "READ_ONLY"
            def can_access_device(self, device_id): return True
        canonical = TargetDevice(
            "RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004",
            protocol="winbox", port=8291, credentials_ref="vault://router", environment="PRODUCTION",
        )
        class Inventory:
            def get_device(self, key): return canonical if key == canonical.device_id else None
        class Credentials:
            def get_credentials(self, ref, device): return {"username": "operator", "password": "not-logged", "device_enforced_read_only": True}
        engine = OperationsEngine(audit_log_path=os.path.join(self.temp_dir, "winbox-audit.jsonl"), inventory_manager=Inventory())
        adapter = WinboxAdapter(winbox_path="C:/Winbox/winbox.exe", connection_timeout=1, max_retries=0,
                                user_ctx=FakeContext(), credential_provider=Credentials(), operations_engine=engine)
        adapter.ui = FakeUI()
        with mock.patch("engine.winbox.adapter.verify_issued_context", return_value=True), \
             mock.patch("engine.winbox.adapter.os.path.isfile", return_value=True), \
             mock.patch("engine.winbox.adapter.subprocess.Popen", return_value=FakeProcess()):
            with self.assertRaises(TimeoutError):
                adapter.open_session("RTR-CORE-01")
        self.assertIsNone(adapter.active_session)

    def test_winbox_login_window_named_for_target_is_not_an_authenticated_session(self):
        class FakeProcess:
            pid = 321
            def poll(self): return None
            def terminate(self): pass
            def wait(self, timeout=None): return 0
            def kill(self): pass
        class FakeUI:
            def detect_dialog_error(self, parent): return None
            def list_windows_by_title(self, pattern):
                if pattern.casefold() == "winbox":
                    return [{"hwnd": 99, "title": "Winbox - 10.0.0.1"}]
                return []
            def enumerate_child_controls(self, hwnd): return []
        class FakeContext:
            username = "operator"
            is_dev_mode = False
            def has_scope(self, scope): return scope == "READ_ONLY"
            def can_access_device(self, device_id): return True
        canonical = TargetDevice(
            "RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004",
            protocol="winbox", port=8291, credentials_ref="vault://router", environment="PRODUCTION",
        )
        class Inventory:
            def get_device(self, key): return canonical if key == canonical.device_id else None
        class Credentials:
            def get_credentials(self, ref, device): return {"username": "operator", "password": "not-logged", "device_enforced_read_only": True}
        engine = OperationsEngine(audit_log_path=os.path.join(self.temp_dir, "winbox-audit.jsonl"), inventory_manager=Inventory())
        adapter = WinboxAdapter(winbox_path="C:/Winbox/winbox.exe", connection_timeout=1, max_retries=0,
                                user_ctx=FakeContext(), credential_provider=Credentials(), operations_engine=engine)
        adapter.ui = FakeUI()
        with mock.patch("engine.winbox.adapter.verify_issued_context", return_value=True), \
             mock.patch("engine.winbox.adapter.os.path.isfile", return_value=True), \
             mock.patch("engine.winbox.adapter.subprocess.Popen", return_value=FakeProcess()):
            with self.assertRaises(TimeoutError):
                adapter.open_session("RTR-CORE-01")
        self.assertIsNone(adapter.active_session)

    def test_winbox_live_access_requires_shared_engine_and_read_only_credential_attestation(self):
        class FakeContext:
            username = "operator"
            is_dev_mode = False
            def has_scope(self, scope): return scope == "READ_ONLY"
            def can_access_device(self, device_id): return True
        canonical = TargetDevice(
            "RTR-CORE-01", "core-rtr01.isp.net", "10.0.0.1", "MikroTik", "CCR2004",
            protocol="winbox", port=8291, credentials_ref="vault://router", environment="PRODUCTION",
        )
        class Inventory:
            def get_device(self, key): return canonical if key == canonical.device_id else None
        class Credentials:
            def get_credentials(self, ref, device): return {"username": "operator", "password": "not-logged"}
        inventory = Inventory()
        credentials = Credentials()
        adapter_without_engine = WinboxAdapter(
            winbox_path="C:/Winbox/winbox.exe", user_ctx=FakeContext(),
            inventory_manager=inventory, credential_provider=credentials,
        )
        with mock.patch("engine.winbox.adapter.verify_issued_context", return_value=True):
            with self.assertRaisesRegex(PermissionError, "OperationsEngine"):
                adapter_without_engine.open_session("RTR-CORE-01")

        engine = OperationsEngine(audit_log_path=os.path.join(self.temp_dir, "winbox-readonly-gate.jsonl"), inventory_manager=inventory)
        adapter = WinboxAdapter(
            winbox_path="C:/Winbox/winbox.exe", user_ctx=FakeContext(),
            credential_provider=credentials, operations_engine=engine,
        )
        with mock.patch("engine.winbox.adapter.verify_issued_context", return_value=True), \
             mock.patch("engine.winbox.adapter.os.path.isfile", return_value=True), \
             mock.patch("engine.winbox.adapter.subprocess.Popen") as popen:
            with self.assertRaisesRegex(PermissionError, "device account is enforced READ_ONLY"):
                adapter.open_session("RTR-CORE-01")
        popen.assert_not_called()

    def test_winbox_navigation_without_verified_window_fails(self):
        class FakeContext:
            username = "operator"
            def has_scope(self, scope): return scope == "READ_ONLY"
        class FakeProcess:
            def poll(self): return None
        class FakeUI:
            def list_windows_by_title(self, pattern): return []
        class Inventory:
            def get_device(self, key): return None
        engine = OperationsEngine(audit_log_path=os.path.join(self.temp_dir, "winbox-nav-audit.jsonl"), inventory_manager=Inventory())
        adapter = WinboxAdapter(winbox_path="unused", user_ctx=FakeContext(), operations_engine=engine)
        adapter.current_process = FakeProcess()
        adapter.ui = FakeUI()
        adapter.active_session = {"target": "10.0.0.1", "device_id": "RTR-CORE-01", "hwnd": 44, "device_enforced_read_only": True}
        with mock.patch("engine.winbox.adapter.verify_issued_context", return_value=True):
            result = adapter.navigate_menu("interfaces")
        self.assertFalse(result["success"])


class TestWinboxNavigationEvidence(unittest.TestCase):
    def test_menu_click_without_distinct_destination_window_fails(self):
        ui = WindowsUIAWrapper()
        ui.is_windows = True
        ui.user32 = type("User32", (), {"IsWindow": staticmethod(lambda hwnd: True), "IsWindowVisible": staticmethod(lambda hwnd: True)})()
        controls = [
            [{"hwnd": 10, "text": "System", "is_visible": True, "is_enabled": True}],
            [{"hwnd": 11, "text": "Resources", "is_visible": True, "is_enabled": True}],
        ]
        ui.enumerate_child_controls = mock.Mock(side_effect=controls)
        ui.send_click_to_control = mock.Mock(return_value=True)
        ui.list_windows_by_title = mock.Mock(return_value=[])
        self.assertFalse(ui.navigate_menu_path(1, "System -> Resources", timeout=0.1))

    def test_menu_click_with_distinct_destination_window_is_verified(self):
        ui = WindowsUIAWrapper()
        ui.is_windows = True
        ui.user32 = type("User32", (), {"IsWindow": staticmethod(lambda hwnd: True), "IsWindowVisible": staticmethod(lambda hwnd: True)})()
        ui.enumerate_child_controls = mock.Mock(side_effect=[
            [{"hwnd": 10, "text": "System", "is_visible": True, "is_enabled": True}],
            [{"hwnd": 11, "text": "Resources", "is_visible": True, "is_enabled": True}],
        ])
        ui.send_click_to_control = mock.Mock(return_value=True)
        ui.list_windows_by_title = mock.Mock(return_value=[{"hwnd": 55, "title": "Resources"}])
        self.assertTrue(ui.navigate_menu_path(1, "System -> Resources", timeout=0.1))


class TestSharedModuleIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="shared-module-integration-")
        self.user = create_test_context("shared-module-user", "ignored", frozenset({"READ_ONLY", "DIAGNOSTIC"}))
        self.engine = OperationsEngine(evidence_manager=OperationEvidenceManager(os.path.join(self.temp_dir, "engine-evidence")))

    def test_troubleshoot_engine_routes_vendor_catalog_through_shared_gateway(self):
        troubleshoot = TroubleshootEngine(self.user, operations_engine=self.engine)
        troubleshoot.incident_id = "INC-TEST-SHARED"
        connector = MockConnector(host="10.0.0.1", vendor="mikrotik")
        troubleshoot._build_connector = lambda conn_type, device: connector
        with mock.patch(
            "engine.troubleshoot.engine.store_raw_output",
            return_value=(Path("/tmp/fake-evidence.enc"), "evidence-sha256"),
        ):
            steps = troubleshoot._collect_device_steps({"id": "RTR-CORE-01"})
        self.assertEqual(len(steps), len(COMMAND_CATALOG["mikrotik"]))
        self.assertEqual(connector.command_history, COMMAND_CATALOG["mikrotik"])
        self.assertFalse(connector.is_connected)
        self.assertTrue(all(step.device_id == "RTR-CORE-01" for step in steps))
        self.assertTrue(all(step.raw_output_hash == "evidence-sha256" for step in steps))
        self.assertTrue(all(step.raw_output.strip() for step in steps))
        self.assertTrue(all("[MOCK MIKROTIK]" in step.raw_output or "uptime:" in step.raw_output or "Flags:" in step.raw_output or "SEQ HOST" in step.raw_output for step in steps))
        self.assertEqual(len(list(self.engine.evidence_manager.root.glob("EV-*.json"))), len(steps))

    def test_catalogued_routeros_read_only_commands_are_not_misclassified(self):
        policy = SecurityPolicyEngine()
        for command in COMMAND_CATALOG["mikrotik"]:
            with self.subTest(command=command):
                classification = policy.classify_command(command)
                self.assertIn(classification, {OperationClassification.READ_ONLY, OperationClassification.DIAGNOSTIC})

    def test_shared_workflow_gateway_audits_local_simulation(self):
        result = execute_authorized_module_workflow(
            operations_engine=self.engine,
            user_ctx=self.user,
            device_id="RTR-CORE-01",
            module="advanced_network_operations",
            workflow="diagnostic_execution",
            classification=OperationClassification.DIAGNOSTIC,
            parameters={"command": "show version"},
            command="show version",
            handler=lambda canonical, parameters: {"device": canonical.device_id, "executed": parameters["command"]},
        )
        self.assertTrue(result.success)
        self.assertEqual(result.status, "SIMULATED")
        self.assertTrue(result.output["simulation"])
        self.assertEqual(result.output["result"]["device"], "RTR-CORE-01")
        evidence = result.output["evidence"]
        self.assertEqual(evidence["execution_status"], "SIMULATED")
        self.assertFalse(evidence["is_hardware_evidence"])
        record = self.engine.evidence_manager.read_record(evidence["reference"])
        self.assertEqual(record["device_id"], "RTR-CORE-01")
        self.assertEqual(record["module"], "advanced_network_operations")

    def test_shared_evidence_registry_records_digest_without_raw_result(self):
        root = os.path.join(self.temp_dir, "shared-evidence")
        registry = OperationEvidenceManager(root)
        result = registry.record_workflow_result(
            request_id="EV-TEST-1", module="advanced_device_quality_control",
            workflow="qc_assessment", device_id="RTR-CORE-01",
            result={"status": "PASS", "password": "must-not-be-written"},
        )
        record = registry.read_record(result["reference"])
        self.assertEqual(record["result_sha256"], result["result_sha256"])
        self.assertFalse(record["is_hardware_evidence"])
        serialized = Path(root, result["reference"]).read_text(encoding="utf-8")
        self.assertNotIn("must-not-be-written", serialized)
        with self.assertRaises(EvidenceRegistryError):
            registry.read_record("../outside.json")

    def test_shared_evidence_registry_rejects_symlink_root(self):
        root = Path(self.temp_dir) / "shared-evidence-real"
        root.mkdir()
        link = Path(self.temp_dir) / "shared-evidence-link"
        try:
            link.symlink_to(root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this platform")
        with self.assertRaises(EvidenceRegistryError):
            OperationEvidenceManager(str(link))

    def test_module_workflow_minimum_classification_cannot_be_downgraded(self):
        called = []
        result = execute_authorized_module_workflow(
            operations_engine=self.engine,
            user_ctx=self.user,
            device_id="RTR-CORE-01",
            module="isp_provisioning_remote_management",
            workflow="acs_mock_configuration",
            classification=OperationClassification.READ_ONLY,
            parameters={"setting": "SSID"},
            handler=lambda canonical, payload: called.append(True),
        )
        self.assertFalse(result.success)
        self.assertEqual(result.status, "DENIED")
        self.assertEqual(called, [])

    def test_isp_provisioning_request_uses_shared_engine_and_is_simulation_only(self):
        service = ISPProvisioningSimulationService(self.engine, self.user)
        result = service.simulate_request("RTR-CORE-01", "VLAN", {"vlan_id": 220, "service_name": "residential"})
        self.assertTrue(result.success)
        self.assertEqual(result.status, "SIMULATED")
        payload = result.output["result"]
        self.assertEqual(payload["workflow_status"], "SIMULATED_NOT_APPLIED")
        self.assertFalse(payload["applied"])
        self.assertFalse(payload["real_integration"])
        self.assertFalse(result.output["evidence"]["is_hardware_evidence"])
        with self.assertRaises(ValueError):
            service.simulate_request("RTR-CORE-01", "PPPOE", {"pppoe_password": "do-not-store"})

    def test_discovery_ingestion_uses_shared_authorization_lifecycle(self):
        collector = DiscoveryCollector(
            operations_engine=self.engine, user_ctx=self.user, authorization_device_id="RTR-CORE-01"
        )
        observed = DiscoveredDevice("NEW-AP", "10.0.0.22", "new-ap", "Ruijie", discovery_sources=[DiscoverySource.MANUAL])
        self.assertTrue(collector.ingest_device(observed))
        self.assertEqual(collector.last_ingestion_mode, "AUTHORIZED_SIMULATED")
        self.assertIn("NEW-AP", collector.discovered_devices)
        self.assertEqual(len(list(self.engine.evidence_manager.root.glob("EV-*.json"))), 1)
        devices, links = collector.build_topology()
        self.assertEqual(len(devices), 1)
        self.assertEqual(len(links), 0)

    def test_qc_can_run_through_shared_authorization_lifecycle(self):
        temp = tempfile.mkdtemp(prefix="qc-integrated-")
        qc = QCTestEngine(
            history_file=os.path.join(temp, "history", "sessions.json"),
            history_root=os.path.join(temp, "history"),
            evidence_dir=os.path.join(temp, "evidence"),
            operations_engine=self.engine,
            user_ctx=self.user,
        )
        device = DeviceIdentity("MikroTik", "CCR2004-16G-2S+", "SN-QC", device_id="RTR-CORE-01")
        report = qc.run_qc_session(device, {}, technician="operator")
        self.assertEqual(report.workflow_status, "AUTHORIZED_SIMULATED")
        self.assertEqual(len(list(self.engine.evidence_manager.root.glob("EV-*.json"))), 1)

    def test_mock_acs_read_workflow_uses_shared_engine_and_write_fails_closed(self):
        acs = MockACSConnector(
            operations_engine=self.engine,
            user_ctx=self.user,
            inventory_device_id="RTR-CORE-01",
        )
        self.assertTrue(acs.authenticate())
        self.assertGreaterEqual(len(acs.discover_devices()), 1)
        self.assertGreaterEqual(len(list(self.engine.evidence_manager.root.glob("EV-*.json"))), 1)
        with self.assertRaises(PermissionError):
            acs.set_parameter_values("HWTC12345678", {"Device.WiFi.SSID.1.SSID": "Unauthorized"})
        current = acs.get_parameter_values("HWTC12345678", ["Device.WiFi.SSID.1.SSID"])
        self.assertEqual(current["Device.WiFi.SSID.1.SSID"], "ISP_FiberHome_2.4G")

    def test_mock_acs_has_no_embedded_or_accepted_api_credential(self):
        with self.assertRaises(ValueError):
            MockACSConnector(api_key="placeholder-secret")
        acs = MockACSConnector()
        self.assertTrue(acs.authenticate())
        self.assertIsNone(acs.api_key)
        self.assertEqual(acs.audit_log[-1]["action"], "MOCK_AUTHENTICATED")
        self.assertFalse(acs.audit_log[-1]["details"]["live_authentication"])

    def test_mock_acs_mutation_without_authorizer_fails_closed(self):
        acs = MockACSConnector()
        self.assertTrue(acs.authenticate())
        with self.assertRaises(PermissionError):
            acs.set_parameter_values("HWTC12345678", {"Device.WiFi.SSID.1.SSID": "Unauthorized"})


if __name__ == "__main__":
    unittest.main()
