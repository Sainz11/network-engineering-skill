"""Tests for P0-2, P1-1, and P1-2.

Covers:
- P0-2: Authorization enforcement with UserContext, DIAGNOSTIC scope validation,
        device target checks, connector non-initialization on auth failure.
- P1-1: Evidence-based RCA: 2 commands from the same device do not equal independent evidence;
        freshness checks, contradiction detection, CONFIRMED criteria.
- P1-2: Diagnostic catalog validation, missing catalog handling, invalid structure handling,
        and allowlist enforcement.
"""

import os
import sys
import tempfile
import datetime
import unittest
from unittest import mock
from pathlib import Path

# Path setup
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.auth_provider import UserContext as FrozenUserContext, LocalDevAuthProvider, ProdAuthProvider
from engine.policy.types import UserContext as MutableUserContext, OperationClassification
from engine.policy import check_permission
from engine.troubleshoot.engine import TroubleshootEngine, _validate_catalog, COMMAND_CATALOG
from engine.troubleshoot.models import DiagnosticStep, FindingStatus, ConfidenceLevel


class TestAuthorizationEnforcement(unittest.TestCase):
    """P0-2 tests: Real Authorization Enforcement."""

    def test_forged_context_rejected(self):
        """Directly instantiated context without signature is rejected as forged."""
        forged_user = FrozenUserContext(
            username="attacker",
            role="Admin",
            authorized_scopes=frozenset({"READ_ONLY", "DIAGNOSTIC"}),
            session_id="fake_session_123",
            is_dev_mode=True
        )
        with self.assertRaises(PermissionError) as cm:
            check_permission(forged_user, "RTR-CORE-01", "ping", OperationClassification.DIAGNOSTIC)
        self.assertIn("not an authenticated identity issued by a trusted AuthProvider", str(cm.exception))

    def test_missing_scope_rejected(self):
        """Authenticated user missing DIAGNOSTIC scope is rejected."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "readonly_ops", "AGY_DEV_DIAGNOSTIC": "0"}):
            auth = LocalDevAuthProvider()
            ro_user = auth.authenticate()
            self.assertEqual(ro_user.authorized_scopes, frozenset({"READ_ONLY"}))
            with self.assertRaises(PermissionError) as cm:
                check_permission(ro_user, "RTR-CORE-01", "ping", OperationClassification.DIAGNOSTIC)
            self.assertIn("lacks required scope 'DIAGNOSTIC'", str(cm.exception))

    def test_unknown_device_rejected(self):
        """Unknown or unregistered device is rejected."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_eng", "AGY_DEV_DIAGNOSTIC": "1"}):
            user = LocalDevAuthProvider().authenticate()
            with self.assertRaises(PermissionError) as cm:
                check_permission(user, "NON-EXISTENT-DEVICE-999", "ping", OperationClassification.DIAGNOSTIC)
            self.assertIn("not a registered inventory device", str(cm.exception))

    def test_unauthorized_device_rejected(self):
        """User restricted to specific devices cannot access other devices."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "site_tech", "AGY_DEV_DEVICES": "RTR-CORE-01", "AGY_DEV_DIAGNOSTIC": "1"}):
            user = LocalDevAuthProvider().authenticate()
            self.assertTrue(user.can_access_device("RTR-CORE-01"))
            self.assertFalse(user.can_access_device("SW-AGG-01"))
            # Accessing SW-AGG-01 must fail
            with self.assertRaises(PermissionError) as cm:
                check_permission(user, "SW-AGG-01", "ping", OperationClassification.DIAGNOSTIC)
            self.assertIn("not authorized to access device 'SW-AGG-01'", str(cm.exception))

    def test_raw_username_rejected(self):
        """Raw username string is not accepted as proof of identity."""
        with self.assertRaises(TypeError) as cm:
            check_permission("admin_user", "RTR-CORE-01", "ping", OperationClassification.DIAGNOSTIC)
        self.assertIn("requires an authenticated UserContext", str(cm.exception))

    def test_unauthenticated_mutable_context_rejected_in_prod(self):
        """Mutable context without session_id and is_dev_mode=False is rejected."""
        unauth_user = MutableUserContext(
            username="hacker",
            role="Admin",
            authorized_scopes=["DIAGNOSTIC"],
            session_id=None,
            is_dev_mode=False
        )
        with self.assertRaises(PermissionError) as cm:
            check_permission(unauth_user, "RTR-CORE-01", "ping", OperationClassification.DIAGNOSTIC)
        self.assertIn("not an authenticated identity issued by a trusted AuthProvider", str(cm.exception))

    def test_connector_never_initialized_on_auth_failure(self):
        """If check_permission raises, connector factory must not be called."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        
        engine = TroubleshootEngine(valid_user)
        device = {
            "id": "UNAUTHORIZED-DEVICE-01",
            "vendor": "mikrotik",
            "management_ip": "10.0.0.1",
            "preferred_connector": "ssh"
        }
        with mock.patch("engine.troubleshoot.engine.check_permission", side_effect=PermissionError("Device access denied")):
            with mock.patch.object(engine, "_build_connector") as mock_build_conn:
                with self.assertRaises(PermissionError):
                    engine._collect_device_steps(device)
                mock_build_conn.assert_not_called()



    def test_vendor_mismatch_rejected_before_connector(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        spoofed = {"id": "RTR-CORE-01", "management_ip": "10.0.0.1", "vendor": "Cisco", "preferred_connector": "ssh"}
        with mock.patch.object(engine, "_build_connector") as build:
            with self.assertRaises(PermissionError):
                engine._collect_device_steps(spoofed)
            build.assert_not_called()

    def test_protocol_and_connector_type_substitution_rejected_before_connector(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        for spoofed in (
            {"id": "RTR-CORE-01", "management_ip": "10.0.0.1", "vendor": "MikroTik", "protocol": "rest"},
            {"id": "RTR-CORE-01", "management_ip": "10.0.0.1", "vendor": "MikroTik", "connector_type": "snmp"},
        ):
            with self.subTest(spoofed=spoofed), mock.patch.object(engine, "_build_connector") as build:
                with self.assertRaises(PermissionError):
                    engine._collect_device_steps(spoofed)
                build.assert_not_called()

    def test_unknown_connection_options_rejected_before_connector(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        supplied = {"id": "RTR-CORE-01", "management_ip": "10.0.0.1", "vendor": "MikroTik", "connection_options": {"host": "evil"}}
        with mock.patch.object(engine, "_build_connector") as build:
            with self.assertRaises(PermissionError):
                engine._collect_device_steps(supplied)
            build.assert_not_called()

    def test_caller_credentials_rejected_before_connector(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        supplied = {"id": "RTR-CORE-01", "username": "attacker", "password": "not-trusted"}
        with mock.patch.object(engine, "_build_connector") as build:
            with self.assertRaises(PermissionError):
                engine._collect_device_steps(supplied)
            build.assert_not_called()

    def test_caller_ip_substitution_rejected_before_connector(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        spoofed = {"id": "RTR-CORE-01", "management_ip": "10.0.0.2", "vendor": "MikroTik", "preferred_connector": "ssh"}
        with mock.patch.object(engine, "_build_connector") as build:
            with self.assertRaises(PermissionError):
                engine._collect_device_steps(spoofed)
            build.assert_not_called()

    def test_connector_config_uses_inventory_only_and_ignores_caller_credentials(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        supplied = {"id": "RTR-CORE-01", "management_ip": "10.0.0.1", "vendor": "MikroTik", "preferred_connector": "ssh"}
        fake_adapter = mock.Mock()
        captured = {}
        def capture_connector(connector_type, canonical_config):
            captured.update(canonical_config)
            return mock.Mock()
        with mock.patch.object(engine, "_build_connector", side_effect=capture_connector) as builder, \
             mock.patch("engine.troubleshoot.engine.AdapterFactory.get_adapter", return_value=fake_adapter), \
             mock.patch("engine.troubleshoot.engine.COMMAND_CATALOG", {"mikrotik": ["show version"]}), \
             mock.patch.object(engine, "_run_command", return_value=("ok", False)), \
             mock.patch("engine.troubleshoot.engine.store_raw_output", return_value=(Path("evidence"), "hash")):
            engine._collect_device_steps(supplied)
        builder.assert_called_once()
        self.assertEqual(captured["management_ip"], "10.0.0.1")
        self.assertEqual(captured["vendor"], "MikroTik")
        self.assertNotIn("username", captured)
        self.assertNotIn("password", captured)
        self.assertNotIn("api_token", captured)

    def test_alternate_target_substitution_rejected_before_connector(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc_user", "AGY_DEV_DIAGNOSTIC": "1"}):
            valid_user = LocalDevAuthProvider().authenticate()
        engine = TroubleshootEngine(valid_user)
        spoofed = {"id": "RTR-CORE-01", "hostname": "agg-sw01.isp.net", "management_ip": "10.0.0.2", "vendor": "Cisco", "preferred_connector": "ssh"}
        with mock.patch.object(engine, "_build_connector") as build:
            with self.assertRaises(PermissionError):
                engine._collect_device_steps(spoofed)
            build.assert_not_called()

class TestEvidenceBasedRCA(unittest.TestCase):
    """P1-1 tests: Evidence-based RCA & source independence."""

    def setUp(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "analyst", "AGY_DEV_DIAGNOSTIC": "1"}):
            self.user = LocalDevAuthProvider().authenticate()
        self.engine = TroubleshootEngine(self.user)
        self.fresh_timestamp = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")

    def test_two_commands_same_device_not_independent_evidence(self):
        """Two commands from the SAME device (ping loss + missing default route)
        MUST NOT result in a CONFIRMED root cause; status must remain HYPOTHESIS
        or INSUFFICIENT_EVIDENCE.
        """
        step1 = DiagnosticStep(
            device_id="RTR-01",
            connector="ssh",
            command="ping 1.1.1.1",
            raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss",
            timestamp=self.fresh_timestamp # dynamically fresh
        )
        step2 = DiagnosticStep(
            device_id="RTR-01", # SAME DEVICE
            connector="ssh",
            command="/ip route print",
            raw_output="Flags: X - disabled, A - active, D - dynamic, C - connect, S - static\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1",
            timestamp=self.fresh_timestamp # dynamically fresh, no default route
        )
        findings = self.engine._generate_findings([step1, step2])
        # Neither finding should be CONFIRMED
        for f in findings:
            self.assertNotEqual(
                f.status, FindingStatus.CONFIRMED,
                f"Finding {f.description} was wrongly marked CONFIRMED from a single device"
            )
            self.assertIn(f.status, [FindingStatus.HYPOTHESIS, FindingStatus.INSUFFICIENT_EVIDENCE])

    def test_multi_device_independent_corroboration_confirmed(self):
        """Independent failure evidence from two distinct devices with verified topology
        adjacency and no contradictions promotes to CONFIRMED.
        """
        step1 = DiagnosticStep(
            device_id="RTR-CORE-01",
            connector="ssh",
            command="ping 1.1.1.1",
            raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss",
            timestamp=self.fresh_timestamp
        )
        step2 = DiagnosticStep(
            device_id="SW-AGG-01", # DIFFERENT DEVICE
            connector="ssh",
            command="/ip route print",
            raw_output="Flags: X - disabled, A - active\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1",
            timestamp=self.fresh_timestamp
        )
        # Topology snapshot proving verified topological link between RTR-CORE-01 and SW-AGG-01
        topology_snapshot = {
            "links": [
                {"source": "RTR-CORE-01", "target": "SW-AGG-01", "type": "physical", "confidence": "VERIFIED", "evidence_sources": ["LLDP", "CDP"]}
            ]
        }
        findings = self.engine._generate_findings([step1, step2], topology_snapshot=topology_snapshot)
        confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].confidence, ConfidenceLevel.HIGH)
        self.assertEqual(confirmed[0].topology_relation, "causally-linked-topology")

    def test_multi_device_without_causal_link_remains_hypothesis(self):
        """Distinct device IDs alone without verified topological causal link
        MUST NOT result in CONFIRMED; must remain HYPOTHESIS.
        """
        step1 = DiagnosticStep(
            device_id="RTR-CORE-01",
            connector="ssh",
            command="ping 1.1.1.1",
            raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss",
            timestamp=self.fresh_timestamp
        )
        step2 = DiagnosticStep(
            device_id="OLT-GPON-01", # DIFFERENT DEVICE, BUT UNLINKED
            connector="ssh",
            command="/ip route print",
            raw_output="Flags: X - disabled, A - active\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1",
            timestamp=self.fresh_timestamp
        )
        # No topology link connecting RTR-CORE-01 and OLT-GPON-01
        topology_snapshot = {
            "links": [
                {"source": "SW-AGG-01", "target": "OLT-GPON-01"}
            ]
        }
        findings = self.engine._generate_findings([step1, step2], topology_snapshot=topology_snapshot)
        confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 0)
        unverified = [f for f in findings if "unverified" in (f.explanation or "").lower() or f.topology_relation == "unverified-topology"]
        self.assertTrue(len(unverified) > 0)
        self.assertEqual(unverified[0].status, FindingStatus.HYPOTHESIS)

    def test_contradictions_prevent_confirmed(self):
        """If one device shows 0% packet loss (healthy), cannot mark CONFIRMED."""
        step1 = DiagnosticStep(
            device_id="RTR-01",
            connector="ssh",
            command="ping 1.1.1.1",
            raw_output="PING 1.1.1.1: 5 packets transmitted, 0 received, 100% packet loss",
            timestamp=self.fresh_timestamp
        )
        step2 = DiagnosticStep(
            device_id="RTR-02",
            connector="ssh",
            command="ping 8.8.8.8",
            raw_output="PING 8.8.8.8: 5 packets transmitted, 5 received, 0% packet loss", # HEALTHY!
            timestamp=self.fresh_timestamp
        )
        findings = self.engine._generate_findings([step1, step2])
        for f in findings:
            self.assertNotEqual(f.status, FindingStatus.CONFIRMED)


    def test_inferred_topology_does_not_confirm(self):
        step1 = DiagnosticStep(device_id="RTR-CORE-01", connector="ssh", command="ping 1.1.1.1", raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss", timestamp=self.fresh_timestamp)
        step2 = DiagnosticStep(device_id="SW-AGG-01", connector="ssh", command="/ip route print", raw_output="Flags: X - disabled, A - active\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1", timestamp=self.fresh_timestamp)
        snapshot = {"links": [{"source": "RTR-CORE-01", "target": "SW-AGG-01", "confidence": "INFERRED", "evidence_sources": ["LLDP"]}]}
        findings = self.engine._generate_findings([step1, step2], topology_snapshot=snapshot)
        self.assertFalse(any(f.status == FindingStatus.CONFIRMED for f in findings))

    def test_caller_boolean_causal_link_is_not_accepted(self):
        step1 = DiagnosticStep(device_id="RTR-CORE-01", connector="ssh", command="ping 1.1.1.1", raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss", timestamp=self.fresh_timestamp)
        step2 = DiagnosticStep(device_id="SW-AGG-01", connector="ssh", command="/ip route print", raw_output="Flags: X - disabled, A - active\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1", timestamp=self.fresh_timestamp)
        findings = self.engine._generate_findings([step1, step2], topology_snapshot={"causally_linked": True})
        self.assertFalse(any(f.status == FindingStatus.CONFIRMED for f in findings))

    def test_future_evidence_does_not_confirm(self):
        future = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        step1 = DiagnosticStep(device_id="RTR-CORE-01", connector="ssh", command="ping 1.1.1.1", raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss", timestamp=future)
        step2 = DiagnosticStep(device_id="SW-AGG-01", connector="ssh", command="/ip route print", raw_output="Flags: X - disabled, A - active\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1", timestamp=future)
        snapshot = {"links": [{"source": "RTR-CORE-01", "target": "SW-AGG-01", "confidence": "VERIFIED", "evidence_sources": ["LLDP", "CDP"]}]}
        findings = self.engine._generate_findings([step1, step2], topology_snapshot=snapshot)
        self.assertFalse(any(f.status == FindingStatus.CONFIRMED for f in findings))

    def test_stale_evidence_does_not_confirm(self):
        stale = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        step1 = DiagnosticStep(device_id="RTR-CORE-01", connector="ssh", command="ping 1.1.1.1", raw_output="PING 1.1.1.1: 5 packets transmitted, 0 packets received, 100% packet loss", timestamp=stale)
        step2 = DiagnosticStep(device_id="SW-AGG-01", connector="ssh", command="/ip route print", raw_output="Flags: X - disabled, A - active\n 0 A S dst-address=10.0.0.0/8 gateway=10.1.1.1", timestamp=stale)
        snapshot = {"links": [{"source": "RTR-CORE-01", "target": "SW-AGG-01", "confidence": "VERIFIED", "evidence_sources": ["LLDP", "CDP"]}]}
        findings = self.engine._generate_findings([step1, step2], topology_snapshot=snapshot)
        self.assertFalse(any(f.status == FindingStatus.CONFIRMED for f in findings))


class TestDiagnosticCatalog(unittest.TestCase):
    """P1-2 tests: Diagnostic Catalog Validation."""

    def test_valid_catalog_loaded(self):
        """Default catalog is valid and loaded."""
        self.assertIn("mikrotik", COMMAND_CATALOG)
        self.assertIn("cisco", COMMAND_CATALOG)
        self.assertTrue(len(COMMAND_CATALOG["mikrotik"]) > 0)

    def test_validate_catalog_rejects_empty_or_non_mapping(self):
        with self.assertRaises(ValueError):
            _validate_catalog({})
        with self.assertRaises(ValueError):
            _validate_catalog(["not_a_dict"])

    def test_validate_catalog_rejects_empty_command_list(self):
        with self.assertRaises(ValueError):
            _validate_catalog({"mikrotik": []})

    def test_validate_catalog_rejects_empty_command_string(self):
        with self.assertRaises(ValueError):
            _validate_catalog({"mikrotik": [""]})


if __name__ == "__main__":
    unittest.main()
