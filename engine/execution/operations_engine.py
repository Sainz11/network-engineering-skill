import time
import uuid
import copy
import datetime
from typing import Dict, Any, Optional
from ..policy.types import OperationRequest, ExecutionResult, OperationClassification, ExecutionMode
from ..policy.security_policy import SecurityPolicyEngine
from ..policy.audit import AuditLogger
from ..approval_manager import ApprovalManager
from ..evidence_manager import OperationEvidenceManager
from ..connectors.base import BaseConnector
from ..connectors.mock_connector import MockConnector
from ..connectors.ssh_connector import SSHConnector
from ..connectors.rest_connector import RESTConnector
from ..connectors.snmp_connector import SNMPConnector
from ..adapters.factory import AdapterFactory
from scripts.redact import redact_sensitive_data
from ..inventory.inventory_manager import DeviceInventoryManager

class OperationsEngine:
    def __init__(self, audit_log_path: Optional[str] = None, inventory_manager: Optional[DeviceInventoryManager] = None, approval_verifier=None, credential_provider=None, approval_provider=None, evidence_manager: Optional[OperationEvidenceManager] = None):
        self.approval_manager = ApprovalManager(provider=approval_provider, verifier=approval_verifier)
        self.policy_engine = SecurityPolicyEngine(
            approval_verifier=self.approval_manager.verify if self.approval_manager.is_configured else None
        )
        self.audit_logger = AuditLogger(audit_log_path)
        self.inventory_manager = inventory_manager or DeviceInventoryManager()
        self.evidence_manager = evidence_manager or OperationEvidenceManager()
        self.credential_provider = credential_provider

    @staticmethod
    def _redact_output(value):
        if isinstance(value, dict):
            return {str(k): ("***REDACTED***" if str(k).lower().replace("-", "_") in {"password", "passwd", "secret", "token", "api_key", "api_token", "community", "credential", "private_key"} else OperationsEngine._redact_output(v)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [OperationsEngine._redact_output(v) for v in value]
        if isinstance(value, str):
            return redact_sensitive_data(value)
        return value

    MODULE_WORKFLOWS = {
        "advanced_network_operations": {"diagnostic_execution", "rca_analysis"},
        "isp_provisioning_remote_management": {"acs_mock_read", "acs_mock_configuration", "acs_mock_connection_request", "acs_mock_reboot", "provisioning_simulation"},
        "advanced_device_quality_control": {"qc_assessment", "qc_report"},
        "network_discovery_topology": {"discovery_ingestion", "topology_build"},
    }
    MODULE_WORKFLOW_MINIMUM_CLASSIFICATION = {
        "advanced_network_operations": {
            "diagnostic_execution": OperationClassification.DIAGNOSTIC,
            "rca_analysis": OperationClassification.READ_ONLY,
        },
        "isp_provisioning_remote_management": {
            "acs_mock_read": OperationClassification.READ_ONLY,
            "acs_mock_configuration": OperationClassification.WRITE,
            "acs_mock_connection_request": OperationClassification.DIAGNOSTIC,
            "acs_mock_reboot": OperationClassification.CRITICAL,
            "provisioning_simulation": OperationClassification.DIAGNOSTIC,
        },
        "advanced_device_quality_control": {
            "qc_assessment": OperationClassification.READ_ONLY,
            "qc_report": OperationClassification.READ_ONLY,
        },
        "network_discovery_topology": {
            "discovery_ingestion": OperationClassification.DIAGNOSTIC,
            "topology_build": OperationClassification.READ_ONLY,
        },
    }

    def run_module_workflow(self, request: OperationRequest, module: str, workflow: str, handler) -> ExecutionResult:
        """Authorize, execute, and audit a local/simulated module workflow.

        This lifecycle deliberately never opens a network connector. Live device
        operations must use ``execute`` and its credential/approval/provider gates.
        The request is snapshotted before authorization so caller mutation cannot
        change the target or parameters after policy validation.
        """
        started = time.time()
        try:
            request = copy.deepcopy(request)
        except Exception:
            reason = "Module workflow request could not be safely snapshotted."
            self.audit_logger.log_event(
                "MODULE_WORKFLOW_SNAPSHOT_REJECTION",
                getattr(getattr(request, "user", None), "username", "UNKNOWN"),
                getattr(getattr(request, "device", None), "device_id", "UNKNOWN"),
                str(workflow), {"request_id": str(getattr(request, "request_id", "UNKNOWN")), "reason": reason}, "DENIED",
            )
            return ExecutionResult(request_id=str(getattr(request, "request_id", "UNKNOWN")), success=False, classification=getattr(request, "classification", OperationClassification.READ_ONLY), mode=getattr(request, "execution_mode", ExecutionMode.DRY_RUN), output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")
        allowed = self.MODULE_WORKFLOWS.get(module)
        if not allowed or workflow not in allowed:
            reason = f"Unsupported module workflow {module!r}/{workflow!r}."
            self.audit_logger.log_event("MODULE_WORKFLOW_REJECTION", getattr(request.user, "username", "UNKNOWN"), getattr(request.device, "device_id", "UNKNOWN"), workflow, {"reason": reason}, "UNSUPPORTED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "UNSUPPORTED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="UNSUPPORTED")
        minimum = self.MODULE_WORKFLOW_MINIMUM_CLASSIFICATION[module][workflow]
        severity_order = {
            OperationClassification.READ_ONLY: 1,
            OperationClassification.DIAGNOSTIC: 2,
            OperationClassification.WRITE: 3,
            OperationClassification.CRITICAL: 4,
        }
        if severity_order[request.classification] < severity_order[minimum]:
            reason = f"Workflow {module}/{workflow} requires at least {minimum.value} authorization."
            self.audit_logger.log_event("MODULE_WORKFLOW_SCOPE_REJECTION", getattr(request.user, "username", "UNKNOWN"), getattr(request.device, "device_id", "UNKNOWN"), workflow, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")
        if request.action != "module_workflow":
            reason = "Module workflow requests must use the module_workflow action type."
            self.audit_logger.log_event("MODULE_WORKFLOW_ACTION_REJECTION", request.user.username, request.device.device_id, workflow, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")
        if request.execution_mode not in (ExecutionMode.SIMULATED, ExecutionMode.DRY_RUN):
            reason = "Local module workflows cannot be represented as LIVE device operations."
            self.audit_logger.log_event("MODULE_WORKFLOW_REJECTION", getattr(request.user, "username", "UNKNOWN"), getattr(request.device, "device_id", "UNKNOWN"), workflow, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")
        valid, reason = self.policy_engine.validate_request(request)
        if not valid:
            self.audit_logger.log_event("MODULE_WORKFLOW_POLICY_REJECTION", getattr(request.user, "username", "UNKNOWN"), getattr(request.device, "device_id", "UNKNOWN"), workflow, {"module": module, "reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")

        canonical = self.inventory_manager.get_device(request.device.device_id)
        if canonical is None:
            reason = "Module workflow target is not registered in canonical inventory."
            self.audit_logger.log_event("MODULE_WORKFLOW_TARGET_REJECTION", request.user.username, request.device.device_id, workflow, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")
        fields = ("device_id", "hostname", "ip_address", "vendor", "model", "device_category", "port", "protocol", "credentials_ref", "firmware_version", "environment")
        mismatches = [field for field in fields if getattr(request.device, field, None) != getattr(canonical, field, None)]
        if mismatches:
            reason = "Module workflow target differs from canonical inventory: " + ", ".join(mismatches)
            self.audit_logger.log_event("MODULE_WORKFLOW_TARGET_REJECTION", request.user.username, canonical.device_id, workflow, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")
        if not request.user.can_access_device(canonical.device_id):
            reason = "User is not authorized for the canonical module workflow target."
            self.audit_logger.log_event("MODULE_WORKFLOW_DEVICE_REJECTION", request.user.username, canonical.device_id, workflow, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output={"status": "DENIED", "reason": reason}, error=reason, execution_time_ms=(time.time() - started) * 1000.0, status="DENIED")

        try:
            result = handler(canonical, dict(request.parameters or {}))
            redacted_result = self._redact_output(result)
            evidence = self.evidence_manager.record_workflow_result(
                request_id=request.request_id, module=module, workflow=workflow,
                device_id=canonical.device_id, result=redacted_result,
                execution_status="SIMULATED",
            )
            output = {
                "status": "SIMULATED",
                "module": module,
                "workflow": workflow,
                "device_id": canonical.device_id,
                "simulation": True,
                "evidence": evidence,
                "result": redacted_result,
            }
            self.audit_logger.log_event("MODULE_WORKFLOW_COMPLETED", request.user.username, canonical.device_id, workflow, {"module": module, "execution_mode": request.execution_mode.value, "evidence_id": evidence["evidence_id"], "result_sha256": evidence["result_sha256"]}, "SIMULATED")
            return ExecutionResult(request_id=request.request_id, success=True, classification=request.classification, mode=request.execution_mode, output=output, execution_time_ms=(time.time() - started) * 1000.0, status="SIMULATED")
        except Exception as exc:
            safe_error = redact_sensitive_data(str(exc))
            self.audit_logger.log_event("MODULE_WORKFLOW_FAILED", request.user.username, canonical.device_id, workflow, {"module": module, "error": safe_error}, "FAILED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=f"Module workflow failed: {safe_error}", execution_time_ms=(time.time() - started) * 1000.0, status="FAILED")

    def execute(self, request: OperationRequest, credentials: Optional[Dict[str, Any]] = None) -> ExecutionResult:
        start_time = time.time()
        creds: Dict[str, Any] = {}
        try:
            request = copy.deepcopy(request)
        except Exception:
            reason = "Operation request could not be safely snapshotted."
            self.audit_logger.log_event(
                "REQUEST_SNAPSHOT_REJECTION",
                getattr(getattr(request, "user", None), "username", "UNKNOWN"),
                getattr(getattr(request, "device", None), "device_id", "UNKNOWN"),
                str(getattr(request, "action", "UNKNOWN")),
                {"request_id": str(getattr(request, "request_id", "UNKNOWN")), "reason": reason}, "DENIED",
            )
            return ExecutionResult(
                request_id=str(getattr(request, "request_id", "UNKNOWN")), success=False,
                classification=getattr(request, "classification", OperationClassification.READ_ONLY),
                mode=getattr(request, "execution_mode", ExecutionMode.DRY_RUN),
                output={"status": "DENIED", "reason": reason}, error=reason,
                execution_time_ms=(time.time() - start_time) * 1000.0, status="DENIED",
            )

        # Strict action allowlist: unknown actions must never fall through to a
        # success-shaped placeholder response or connector initialization.
        supported_actions = {"system_info", "interfaces", "backup_config", "ping", "apply_config", "raw"}
        action = request.action if isinstance(request.action, str) else ""
        if action not in supported_actions or (action == "raw" and not request.command):
            reason = f"Unsupported operation action {action!r}; no execution handler is registered."
            self.audit_logger.log_event(
                event_type="UNSUPPORTED_OPERATION", user=getattr(request.user, "username", "UNKNOWN"),
                device_id=getattr(request.device, "device_id", "UNKNOWN"), action=action,
                details={"reason": reason}, status="UNSUPPORTED"
            )
            return ExecutionResult(
                request_id=request.request_id, success=False, classification=request.classification,
                mode=request.execution_mode, output={"status": "UNSUPPORTED", "action": action, "reason": reason},
                error=reason, execution_time_ms=(time.time() - start_time) * 1000.0, status="UNSUPPORTED"
            )

        # Step 1: Security & Authorization Check
        valid, reason = self.policy_engine.validate_request(request)
        if not valid:
            self.audit_logger.log_event(
                event_type="POLICY_REJECTION",
                user=request.user.username,
                device_id=request.device.device_id,
                action=request.action,
                details={"reason": reason, "command": request.command},
                status="DENIED"
            )
            return ExecutionResult(
                request_id=request.request_id,
                success=False,
                classification=request.classification,
                mode=request.execution_mode,
                output=None,
                error=f"Policy Check Failed: {reason}",
                execution_time_ms=(time.time() - start_time) * 1000.0,
                status="DENIED"
            )

        # Resolve and compare the exact canonical inventory target before any connector.
        canonical_device = self.inventory_manager.get_device(request.device.device_id)
        if canonical_device is None:
            reason = "Target device is not registered in trusted inventory."
            self.audit_logger.log_event("TARGET_REJECTION", request.user.username, request.device.device_id, request.action, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
        relevant_fields = ("device_id", "hostname", "ip_address", "vendor", "model", "device_category", "port", "protocol", "credentials_ref", "firmware_version", "environment")
        mismatches = [field for field in relevant_fields if getattr(request.device, field, None) != getattr(canonical_device, field, None)]
        if mismatches:
            reason = "Caller target does not match canonical inventory fields: " + ", ".join(mismatches)
            self.audit_logger.log_event("TARGET_REJECTION", request.user.username, request.device.device_id, request.action, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
        if request.execution_mode == ExecutionMode.LIVE and str(canonical_device.environment).upper() in {"SIMULATED", "LAB_MOCK"}:
            reason = "LIVE mode cannot target inventory devices marked SIMULATED or LAB_MOCK."
            self.audit_logger.log_event("LIVE_SIMULATION_REJECTION", request.user.username, canonical_device.device_id, request.action, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
        if request.execution_mode == ExecutionMode.LIVE and getattr(request.user, "is_dev_mode", False):
            reason = "Live device operations are unavailable with development identities."
            self.audit_logger.log_event("LIVE_MODE_REJECTION", request.user.username, canonical_device.device_id, request.action, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
        # From here onward, connector selection uses only canonical inventory.
        device = canonical_device
        if request.execution_mode == ExecutionMode.LIVE:
            if credentials is not None:
                reason = "Caller-supplied credentials are not accepted for live operations."
                self.audit_logger.log_event("CREDENTIAL_REJECTION", request.user.username, device.device_id, request.action, {"reason": reason}, "DENIED")
                return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
            if not device.credentials_ref or self.credential_provider is None:
                reason = "Trusted credential provider is not configured for this inventory device; live connection fails closed."
                self.audit_logger.log_event("LIVE_CREDENTIAL_REJECTION", request.user.username, device.device_id, request.action, {"reason": reason}, "DENIED")
                return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
            try:
                creds = self.credential_provider.get_credentials(device.credentials_ref, device)
            except Exception:
                reason = "Trusted credential retrieval failed; no connector was initialized."
                self.audit_logger.log_event("CREDENTIAL_PROVIDER_ERROR", request.user.username, device.device_id, request.action, {"reason": reason}, "FAILED")
                return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
            if not isinstance(creds, dict) or not creds:
                reason = "Trusted credential provider returned no usable credentials."
                self.audit_logger.log_event("CREDENTIAL_PROVIDER_REJECTION", request.user.username, device.device_id, request.action, {"reason": reason}, "DENIED")
                return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
        else:
            # Credentials are deliberately not accepted/forwarded in simulation.
            creds = {"username": "simulation"}

        # Step 2: Dry Run Check
        if request.execution_mode == ExecutionMode.DRY_RUN:
            self.audit_logger.log_event(
                event_type="DRY_RUN_EXECUTION",
                user=request.user.username,
                device_id=device.device_id,
                action=request.action,
                details={"command": request.command},
                status="SIMULATED"
            )
            return ExecutionResult(
                request_id=request.request_id,
                success=True,
                classification=request.classification,
                mode=ExecutionMode.DRY_RUN,
                output={"status": "VALIDATED", "message": "Dry-run completed successfully without device state alteration."},
                execution_time_ms=(time.time() - start_time) * 1000.0,
                rollback_plan="No state changed; rollback not required."
            )

        # Step 3: Select Connector based on Mode and Protocol
        connector: BaseConnector
        if request.execution_mode == ExecutionMode.SIMULATED or device.environment in ["SIMULATED", "LAB_MOCK"]:
            connector = MockConnector(host=device.ip_address, port=device.port, vendor=device.vendor)
        elif device.protocol not in {"ssh", "rest", "snmp"}:
            reason = f"Unsupported connector protocol {device.protocol!r} in trusted inventory."
            self.audit_logger.log_event("CONNECTOR_REJECTION", request.user.username, device.device_id, request.action, {"reason": reason}, "DENIED")
            return ExecutionResult(request_id=request.request_id, success=False, classification=request.classification, mode=request.execution_mode, output=None, error=reason, execution_time_ms=(time.time() - start_time) * 1000.0)
        elif device.protocol == "rest":
            connector = RESTConnector(host=device.ip_address, port=device.port)
        elif device.protocol == "snmp":
            connector = SNMPConnector(host=device.ip_address, port=device.port)
        else:
            connector = SSHConnector(host=device.ip_address, port=device.port)

        # Connector-level command restrictions are defense in depth. WRITE and
        # CRITICAL flags are set only after policy/approval validation above.
        if isinstance(connector, SSHConnector):
            connector.allow_write_commands = request.classification in (OperationClassification.WRITE, OperationClassification.CRITICAL)
            connector.allow_critical_commands = request.classification == OperationClassification.CRITICAL
        if isinstance(connector, RESTConnector):
            connector.allow_write = request.classification in (OperationClassification.WRITE, OperationClassification.CRITICAL)

        # Step 4: Execute within Adapter Context
        try:
            connector.connect(creds)
            adapter = AdapterFactory.get_adapter(device.vendor, connector)

            raw_out = None
            structured_out = None

            if request.action == "system_info":
                structured_out = adapter.get_system_info()
            elif request.action == "interfaces":
                structured_out = adapter.get_interfaces()
            elif request.action == "backup_config":
                raw_out = adapter.backup_configuration()
                structured_out = {"backup_length_chars": len(raw_out), "configuration": redact_sensitive_data(raw_out)}
            elif request.action == "ping":
                target = request.parameters.get("target", "8.8.8.8")
                count = int(request.parameters.get("count", 4))
                structured_out = adapter.run_diagnostic_ping(target, count)
            elif request.action == "apply_config":
                cmds = request.parameters.get("commands", [request.command] if request.command else [])
                structured_out = adapter.apply_configuration(cmds, dry_run=False)
            elif request.command:
                raw_out = connector.execute_command(request.command)
                structured_out = {"raw": raw_out}
            else:
                raise ValueError(f"No execution handler exists for action {request.action!r}.")

            connector.disconnect()

            elapsed = (time.time() - start_time) * 1000.0
            operation_status = "SIMULATED" if request.execution_mode == ExecutionMode.SIMULATED else "SUCCESS"
            self.audit_logger.log_event(
                event_type="OPERATION_SUCCESS",
                user=request.user.username,
                device_id=device.device_id,
                action=request.action,
                details={"execution_time_ms": elapsed, "action": request.action, "execution_mode": request.execution_mode.value},
                status=operation_status
            )

            return ExecutionResult(
                request_id=request.request_id,
                success=True,
                classification=request.classification,
                mode=request.execution_mode,
                output=self._redact_output(structured_out),
                raw_output=redact_sensitive_data(raw_out) if raw_out else None,
                execution_time_ms=elapsed,
                status=operation_status,
            )

        except Exception as e:
            if connector.is_connected:
                connector.disconnect()
            elapsed = (time.time() - start_time) * 1000.0
            self.audit_logger.log_event(
                event_type="OPERATION_ERROR",
                user=request.user.username,
                device_id=device.device_id,
                action=request.action,
                details={"error": str(e)},
                status="FAILED"
            )
            return ExecutionResult(
                request_id=request.request_id,
                success=False,
                classification=request.classification,
                mode=request.execution_mode,
                output=None,
                error=f"Execution Failed: {redact_sensitive_data(str(e))}",
                execution_time_ms=elapsed
            )
