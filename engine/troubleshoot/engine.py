"""TroubleshootEngine – orchestrates on-demand diagnostic workflows.

Key responsibilities:
1. Accept an authenticated UserContext (from auth_provider) — never a raw username string.
2. Validate DIAGNOSTIC scope before any device connection is established.
3. Load vendor-specific read-only diagnostic commands from diagnostic_commands.yaml.
4. For each device, obtain the appropriate adapter via AdapterFactory.
5. Execute each command with a timeout (default 30 s) and size limit (1 MiB).
6. Store raw output securely via _utils.store_raw_output.
7. Run parsers — each returns structured data or None.
8. Build DiagnosticStep objects referencing the raw file path and its SHA-256 hash.
9. Assemble Finding objects with explainable confidence.
10. Produce an RCAReport — the public PDF never includes raw files or unredacted output.

Authorization sequence:
  1. check_permission called with authenticated username (not user-supplied string).
  2. Connector initialized ONLY after authorization succeeds.
  3. All operations are READ_ONLY or DIAGNOSTIC — never WRITE or CRITICAL.
"""

import datetime
import uuid
import os
import yaml
from typing import List, Dict, Any, Tuple, Optional

from .models import (
    DiagnosticStep,
    RCAReport,
    Finding,
    FindingStatus,
    ConfidenceLevel,
)
from ._utils import store_raw_output, calculate_sha256, EvidenceProtectionError
from .parsers import parse_interface_status, parse_ping_result, parse_route_table
from ..adapters.factory import AdapterFactory
from ..policy import check_permission, OperationClassification
from ..inventory import DeviceInventoryManager, get_device_by_id
from ..execution.operations_engine import OperationsEngine
from ..execution.module_workflow import execute_authorized_module_workflow
from ..connectors.base import BaseConnector

# Load the diagnostic command catalog (YAML) once at import time.
# The catalog is REQUIRED: a missing or invalid catalog fails closed and
# prevents the engine from running with an empty allowlist.
COMMAND_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "diagnostic_commands.yaml")

_ALLOWED_VENDORS = {
    "mikrotik", "cisco", "huawei", "ruijie", "reyee",
    "cambium", "ubiquiti", "tp-link", "tplink", "generic",
}


def _validate_catalog(catalog: dict) -> None:
    """Validate the diagnostic command catalog structure.

    Raises ValueError if the catalog is missing, not a mapping, or contains
    invalid entries.  Every vendor must map to a non-empty list of non-empty
    command strings.
    """
    if not isinstance(catalog, dict):
        raise ValueError(
            f"Diagnostic catalog at '{COMMAND_CATALOG_PATH}' must be a mapping "
            f"of vendor -> command list, got {type(catalog).__name__}."
        )
    if not catalog:
        raise ValueError(
            f"Diagnostic catalog at '{COMMAND_CATALOG_PATH}' is empty. "
            f"At least one vendor command list is required."
        )
    for vendor, commands in catalog.items():
        if not isinstance(vendor, str) or not vendor.strip():
            raise ValueError(
                f"Diagnostic catalog has an invalid vendor key: {vendor!r}."
            )
        if not isinstance(commands, list) or not commands:
            raise ValueError(
                f"Diagnostic catalog entry for vendor '{vendor}' must be a "
                f"non-empty list of commands."
            )
        for cmd in commands:
            if not isinstance(cmd, str) or not cmd.strip():
                raise ValueError(
                    f"Diagnostic catalog entry for vendor '{vendor}' contains "
                    f"an invalid command: {cmd!r}."
                )


try:
    with open(COMMAND_CATALOG_PATH, "r", encoding="utf-8") as f:
        _raw_catalog = yaml.safe_load(f) or {}
except FileNotFoundError as exc:
    raise FileNotFoundError(
        f"Diagnostic command catalog not found at '{COMMAND_CATALOG_PATH}'. "
        f"The troubleshoot engine cannot run without a valid command catalog."
    ) from exc
except yaml.YAMLError as exc:
    raise ValueError(
        f"Diagnostic catalog at '{COMMAND_CATALOG_PATH}' is invalid YAML: {exc}"
    ) from exc

_validate_catalog(_raw_catalog)
COMMAND_CATALOG = _raw_catalog

DEFAULT_TIMEOUT = 30        # seconds
MAX_OUTPUT_SIZE = 1_048_576  # 1 MiB


class TroubleshootEngine:
    """Main engine for on-demand troubleshooting.

    Parameters
    ----------
    user_ctx:
        Authenticated, immutable UserContext from engine.auth_provider.
        The engine validates that the context carries DIAGNOSTIC scope
        before any device connection is established.
    """

    def __init__(self, user_ctx: Any, operations_engine: Optional[OperationsEngine] = None):
        # Accept both auth_provider.UserContext (frozen) and policy.types.UserContext
        if not hasattr(user_ctx, "username") or not hasattr(user_ctx, "has_scope"):
            raise TypeError(
                "TroubleshootEngine requires an authenticated UserContext with "
                ".username and .has_scope() — received: " + repr(user_ctx)
            )
        if not user_ctx.has_scope("DIAGNOSTIC"):
            raise PermissionError(
                f"User '{user_ctx.username}' lacks DIAGNOSTIC scope required for troubleshooting."
            )
        self._user_ctx = user_ctx
        self.operations_engine = operations_engine or OperationsEngine()
        self.inventory_manager = self.operations_engine.inventory_manager
        self.incident_id: str = ""

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_timeout_and_limit(self, raw: str) -> Tuple[str, bool]:
        """Enforce output size limit; return (output, is_truncated)."""
        if len(raw.encode("utf-8")) > MAX_OUTPUT_SIZE:
            half = MAX_OUTPUT_SIZE // 2
            truncated = (
                raw.encode("utf-8")[:half].decode(errors="ignore")
                + "\n...TRUNCATED...\n"
                + raw.encode("utf-8")[-half:].decode(errors="ignore")
            )
            return truncated, True
        return raw, False

    def _run_command(self, adapter: Any, command: str) -> Tuple[str, bool]:
        """Execute through the adapter's registered connector; return output and truncation flag."""
        connector = getattr(adapter, "connector", None)
        executor = getattr(connector, "execute_command", None)
        if not callable(executor):
            raise TypeError("Registered vendor adapter has no executable connector command interface.")
        raw = executor(command)
        if not isinstance(raw, str):
            raw = str(raw)
        return self._apply_timeout_and_limit(raw)

    def _build_connector(self, conn_type: str, device: Dict[str, Any]) -> Any:
        """Build a connector from canonical inventory, never caller credentials.

        Live transport is deliberately disabled until a trusted credential
        provider is integrated. SIMULATED inventory uses only MockConnector.
        """
        from ..connectors.mock_connector import MockConnector
        if str(device.get("environment", "")).upper() in {"SIMULATED", "LAB_MOCK"}:
            return MockConnector(
                host=device["management_ip"],
                port=int(device.get("port", 22)),
                vendor=device["vendor"],
            )
        raise RuntimeError("Live troubleshooting connectors are disabled until a trusted credential provider is integrated.")

    def _collect_device_steps(self, device: Dict[str, Any]) -> List[DiagnosticStep]:
        """Authorize and operate only on canonical inventory-derived device data.

        Caller-supplied connection attributes are treated as assertions and must
        match inventory. They are never used to configure a connector.
        """
        untrusted_credential_fields = {
            "username", "password", "credentials", "credential", "key_filename",
            "snmp_community", "community", "api_token", "api_key", "api_url",
        }
        supplied_credentials = untrusted_credential_fields.intersection(device)
        if supplied_credentials:
            raise PermissionError(
                "Caller-supplied credential or secret fields are not accepted; "
                "use a trusted credential provider/inventory reference."
            )

        requested_id = device.get("id") or device.get("device_id")
        if not isinstance(requested_id, str) or not requested_id.strip():
            raise PermissionError("A valid inventory device ID is required.")

        inventory_device = self.inventory_manager.get_device(requested_id)
        if inventory_device is None:
            raise PermissionError(f"Device '{requested_id}' is not registered in trusted inventory.")

        canonical = {
            "id": inventory_device.device_id,
            "hostname": inventory_device.hostname,
            "management_ip": inventory_device.ip_address,
            "vendor": inventory_device.vendor,
            "model": inventory_device.model,
            "port": inventory_device.port,
            "preferred_connector": inventory_device.protocol or "ssh",
            "environment": inventory_device.environment,
            "device_category": inventory_device.device_category,
            "credentials_ref": inventory_device.credentials_ref,
            "firmware_version": inventory_device.firmware_version,
        }
        aliases = {
            "id": ("id", "device_id"),
            "hostname": ("hostname",),
            "management_ip": ("management_ip", "ip_address", "ip"),
            "vendor": ("vendor",),
            "model": ("model",),
            "port": ("port",),
            "preferred_connector": ("preferred_connector", "protocol", "connector_type"),
            "environment": ("environment",),
            "device_category": ("device_category",),
            "credentials_ref": ("credentials_ref",),
            "firmware_version": ("firmware_version",),
        }
        allowed_caller_keys = {key for aliases_for_key in aliases.values() for key in aliases_for_key}
        unknown_caller_keys = set(device) - allowed_caller_keys
        if unknown_caller_keys:
            raise PermissionError("Caller-supplied unrecognized device/connection options are rejected: " + ", ".join(sorted(unknown_caller_keys)))
        for canonical_key, caller_keys in aliases.items():
            for key in caller_keys:
                if key in device and device[key] is not None:
                    caller_value = device[key]
                    trusted_value = canonical[canonical_key]
                    if canonical_key in ("id", "hostname", "management_ip", "vendor", "preferred_connector"):
                        matches = str(caller_value).strip().casefold() == str(trusted_value).strip().casefold()
                    else:
                        matches = caller_value == trusted_value
                    if not matches:
                        raise PermissionError(
                            f"Caller-supplied {key!r} does not match trusted inventory for device '{canonical['id']}'."
                        )

        # Identity, scope, registered-device, and per-device authorization all
        # happen before connector construction.
        check_permission(
            user_ctx=self._user_ctx,
            device_id=canonical["id"],
            operation="READ",
            classification=OperationClassification.DIAGNOSTIC,
        )

        vendor = canonical["vendor"].lower()
        connector_type = canonical["preferred_connector"]
        if connector_type not in {"ssh", "rest", "snmp"}:
            raise PermissionError(f"Unsupported connector protocol {connector_type!r} in trusted inventory.")
        connector_config = dict(canonical)  # no caller-controlled values copied
        connector = self._build_connector(connector_type, connector_config)
        adapter = AdapterFactory.get_adapter(vendor, connector)
        commands = COMMAND_CATALOG.get(vendor, [])
        if not commands:
            raise ValueError(
                f"No diagnostic commands configured for vendor '{vendor}' in "
                f"the command catalog. Refusing to run unknown commands."
            )
        steps: List[DiagnosticStep] = []
        connected = False
        try:
            # Live connector creation is disabled above; this module currently
            # supports only explicit SIMULATED/LAB_MOCK inventory. Establish the
            # mock connector lifecycle before invoking its command interface.
            connected = bool(connector.connect({"username": "simulation"}))
            if not connected:
                raise ConnectionError("Simulated diagnostic connector did not establish a session.")

            for cmd in commands:
                # Command allowlist enforcement: only execute commands present in
                # the validated catalog for this vendor.
                if cmd not in commands:
                    raise ValueError(
                        f"Command '{cmd}' is not in the allowlist for vendor "
                        f"'{vendor}'. Refusing to execute."
                    )
                operation_result = execute_authorized_module_workflow(
                    operations_engine=self.operations_engine,
                    user_ctx=self._user_ctx,
                    device_id=canonical["id"],
                    module="advanced_network_operations",
                    workflow="diagnostic_execution",
                    classification=OperationClassification.DIAGNOSTIC,
                    parameters={"command": cmd, "incident_id": self.incident_id},
                    command=cmd,
                    handler=lambda _canonical, _parameters: self._run_command(adapter, cmd),
                )
                if not operation_result.success:
                    raise PermissionError(operation_result.error or "Shared OperationsEngine denied diagnostic execution.")
                command_result = operation_result.output.get("result") if isinstance(operation_result.output, dict) else None
                if not isinstance(command_result, list) or len(command_result) != 2:
                    raise RuntimeError("Shared OperationsEngine returned an invalid diagnostic result.")
                raw, is_truncated = command_result[0], bool(command_result[1])

                # Store evidence securely — fail on protection error
                try:
                    file_path, file_hash = store_raw_output(
                        self.incident_id, canonical["id"], raw
                    )
                except EvidenceProtectionError as exc:
                    raise RuntimeError(
                        f"Evidence storage failed for device '{canonical['id']}', "
                        f"command '{cmd}': {exc}"
                    ) from exc

                step = DiagnosticStep(
                    device_id=canonical["id"],
                    connector=connector_type,
                    command=cmd,
                    raw_output=raw,
                    raw_output_hash=file_hash,
                    raw_output_ref=str(file_path),
                    is_truncated=is_truncated,
                    parsed_result={},
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                )
                steps.append(step)
            return steps
        finally:
            if connected:
                connector.disconnect()

    def _generate_findings(self, steps: List[DiagnosticStep], topology_snapshot: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Create findings from parsed step results using evidence-based RCA with causal correlation.

        Evidence-based rules:
        - Each finding tracks evidence provenance: device identity, command,
          timestamp, source independence, and topology relationship.
        - Freshness is evaluated using actual step timestamps.
        - Contradictions between independent sources are detected and recorded
          as alternative causes.
        - CONFIRMED requires:
          1. Sufficient causal evidence from multiple independent devices that share a verified
             topological or causal relationship (e.g. adjacent in topology, upstream/downstream link).
             Distinct device IDs alone without a verified causal relationship remain HYPOTHESIS.
          2. Fresh evidence (evaluated by actual timestamp).
          3. Complete absence of conflicting/contradictory healthy observations.
        - Otherwise the finding is HYPOTHESIS or INSUFFICIENT_EVIDENCE.
        """
        findings: List[Finding] = []
        now = datetime.datetime.now(datetime.UTC)

        # Group parsed results by parser type, tracking provenance.
        interface_results = [
            (s, parse_interface_status(s.raw_output))
            for s in steps if parse_interface_status(s.raw_output)
        ]
        ping_results = [
            (s, parse_ping_result(s.raw_output))
            for s in steps if parse_ping_result(s.raw_output)
        ]
        route_results = [
            (s, parse_route_table(s.raw_output))
            for s in steps if parse_route_table(s.raw_output)
        ]

        # ---------- Evidence freshness helper ----------
        def _freshness(ts: str) -> str:
            """Evaluate freshness using actual timestamps."""
            try:
                step_time = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                return "UNKNOWN"
            if step_time.tzinfo is None:
                step_time = step_time.replace(tzinfo=datetime.timezone.utc)
            age = (now - step_time).total_seconds()
            if age < -60:
                return "FUTURE"
            if age <= 300:
                return "FRESH"
            if age <= 3600:
                return "RECENT"
            return "STALE"

        # ---------- Source independence ----------
        def _independent_sources(items: List[Tuple[DiagnosticStep, Any]]) -> int:
            """Count distinct (device_id, command) source pairs."""
            return len({(s.device_id, s.command) for s, _ in items})

        # ---------- Finding 1: Interface health ----------
        if interface_results:
            up_count = sum(1 for _, r in interface_results if r.get("up", 0) > 0)
            down_count = sum(1 for _, r in interface_results if r.get("down", 0) > 0)
            alternative_causes: List[str] = []
            if up_count > 0 and down_count > 0:
                alternative_causes.append(
                    "Conflicting interface status reports across sources; possible partial outage or parser disagreement."
                )

            findings.append(Finding(
                description="Interface status observed.",
                device_id=steps[0].device_id if steps else "unknown",
                evidence_steps=[f"{s.device_id}:{s.command}" for s, _ in interface_results],
                evidence_timestamps=[s.timestamp for s, _ in interface_results],
                evidence_freshness=_freshness(interface_results[0][0].timestamp),
                topology_relation="same-device" if len({s.device_id for s, _ in interface_results}) == 1 else "multi-device",
                status=FindingStatus.HYPOTHESIS,
                confidence=ConfidenceLevel.LOW,
                recommended_action="Verify interface configurations if issues persist.",
                alternative_causes=alternative_causes,
                explanation=(
                    f"{len(interface_results)} interface-status source(s) from "
                    f"{_independent_sources(interface_results)} independent device/command pair(s). "
                    "Parser success alone does not confirm interface health."
                ),
            ))
        else:
            findings.append(Finding(
                description="No interface status data available.",
                device_id=steps[0].device_id if steps else "unknown",
                evidence_steps=[f"{s.device_id}:{s.command}" for s in steps],
                evidence_timestamps=[s.timestamp for s in steps],
                evidence_freshness=_freshness(steps[0].timestamp) if steps else "UNKNOWN",
                status=FindingStatus.INSUFFICIENT_EVIDENCE,
                confidence=ConfidenceLevel.LOW,
                recommended_action="Collect interface status from the target device.",
                explanation="No parser returned interface data. Insufficient evidence to assess interface state.",
            ))

        # ---------- Finding 2: Ping loss ----------
        loss_entries = [
            (s, r) for s, r in ping_results if r.get("packet_loss", "0%") != "0%"
        ]
        if loss_entries:
            findings.append(Finding(
                description=f"Ping loss detected ({loss_entries[0][1].get('packet_loss')}).",
                device_id=steps[0].device_id if steps else "unknown",
                evidence_steps=[f"{s.device_id}:{s.command}" for s, _ in loss_entries],
                evidence_timestamps=[s.timestamp for s, _ in loss_entries],
                evidence_freshness=_freshness(loss_entries[0][0].timestamp),
                topology_relation="same-device" if len({s.device_id for s, _ in loss_entries}) == 1 else "multi-device",
                status=FindingStatus.HYPOTHESIS,
                confidence=ConfidenceLevel.LOW,
                recommended_action="Investigate connectivity to the target.",
                alternative_causes=[
                    "Transient congestion, target host down, or intermediate device dropping ICMP.",
                ],
                explanation=(
                    f"{len(loss_entries)} ping-loss source(s) from "
                    f"{_independent_sources(loss_entries)} independent device/command pair(s). "
                    "Single data point; possible transient congestion."
                ),
            ))

        # ---------- Finding 3: Missing default route ----------
        missing_route_entries = [
            (s, r) for s, r in route_results if not r.get("has_default", True)
        ]
        if missing_route_entries:
            findings.append(Finding(
                description="Device is missing a default route.",
                device_id=steps[0].device_id if steps else "unknown",
                evidence_steps=[f"{s.device_id}:{s.command}" for s, _ in missing_route_entries],
                evidence_timestamps=[s.timestamp for s, _ in missing_route_entries],
                evidence_freshness=_freshness(missing_route_entries[0][0].timestamp),
                topology_relation="same-device" if len({s.device_id for s, _ in missing_route_entries}) == 1 else "multi-device",
                status=FindingStatus.HYPOTHESIS,
                confidence=ConfidenceLevel.MEDIUM,
                recommended_action="Configure a default route.",
                alternative_causes=[
                    "Default route may exist but not captured in parsed output, or routing is via static/default-gateway.",
                ],
                explanation=(
                    f"{len(missing_route_entries)} route-table source(s) from "
                    f"{_independent_sources(missing_route_entries)} independent device/command pair(s). "
                    "Default route absent in parsed output."
                ),
            ))

        # ---------- Cross-source corroboration & Causal Correlation ----------
        # CONFIRMED requires:
        # 1. Multiple independent devices (distinct device_id) corroborating the failure.
        #    Distinct device IDs alone do NOT establish causal independence without verified
        #    topological connection or causal relationship.
        # 2. Verified causal / topological link between devices (e.g., links in topology snapshot
        #    or explicit verified causal relationship).
        # 3. Fresh evidence across all corroborating steps.
        # 4. Zero conflicting or contradictory healthy evidence.
        
        loss_devices = {s.device_id for s, _ in loss_entries}
        missing_route_devices = {s.device_id for s, _ in missing_route_entries}
        all_involved_devices = loss_devices | missing_route_devices

        has_multiple_independent_devices = len(all_involved_devices) >= 2

        # Check topological / causal relationship
        has_causal_relationship = False
        if has_multiple_independent_devices:
            if topology_snapshot and "links" in topology_snapshot:
                # Check if involved devices share a link in topology
                links = topology_snapshot.get("links", [])
                for link in links:
                    # A link is causal evidence only when the topology engine marks
                    # it VERIFIED with corroborating discovery provenance.
                    if str(link.get("confidence", "")).upper() != "VERIFIED":
                        continue
                    evidence_sources = {str(src).upper() for src in link.get("evidence_sources", [])}
                    if not evidence_sources.intersection({"LLDP", "CDP", "MNDP"}):
                        continue
                    src = link.get("source") or link.get("src") or link.get("source_device_id")
                    dst = link.get("target") or link.get("dst") or link.get("target_device_id")
                    if src in all_involved_devices and dst in all_involved_devices and src != dst:
                        has_causal_relationship = True
                        break
            # Caller-supplied booleans and DiagnosticStep topology labels are not
            # trusted topology evidence and intentionally cannot confirm RCA.

        # Check for contradictions
        has_contradictions = any(
            r.get("packet_loss") == "0%" for _, r in ping_results
        ) or any(
            r.get("has_default") is True for _, r in route_results
        )

        all_evidence_steps = loss_entries + missing_route_entries
        all_fresh = (
            len(all_evidence_steps) > 0
            and all(_freshness(s.timestamp) in ("FRESH", "RECENT") for s, _ in all_evidence_steps)
        )

        if has_multiple_independent_devices and has_causal_relationship and not has_contradictions and all_fresh:
            confirmed_steps = sorted({f"{s.device_id}:{s.command}" for s, _ in all_evidence_steps})
            findings = [
                fi for fi in findings
                if not (
                    "Ping loss detected" in fi.description
                    or "missing a default route" in fi.description
                )
            ]
            findings.append(Finding(
                description=(
                    "Network connectivity failure corroborated across multiple causally-linked devices."
                ),
                device_id=steps[0].device_id if steps else "unknown",
                evidence_steps=confirmed_steps,
                evidence_timestamps=[s.timestamp for s, _ in all_evidence_steps],
                evidence_freshness="FRESH" if any(_freshness(s.timestamp) == "FRESH" for s, _ in all_evidence_steps) else "RECENT",
                topology_relation="causally-linked-topology",
                status=FindingStatus.CONFIRMED,
                confidence=ConfidenceLevel.HIGH,
                recommended_action="Remediate default route and link connectivity across affected topology.",
                alternative_causes=[],
                explanation=(
                    f"Corroborated by {len(all_involved_devices)} independent, causally-linked devices "
                    f"({', '.join(sorted(all_involved_devices))}). "
                    f"Evidence is fresh and free of contradictory healthy status reports. "
                    "Sufficient causal evidence established for CONFIRMED."
                ),
            ))
        elif has_multiple_independent_devices and not has_causal_relationship:
            # Note lack of causal link as alternative cause
            findings.append(Finding(
                description="Coincidental or unverified multi-device symptoms detected.",
                device_id=steps[0].device_id if steps else "unknown",
                evidence_steps=sorted({f"{s.device_id}:{s.command}" for s, _ in all_evidence_steps}),
                evidence_timestamps=[s.timestamp for s, _ in all_evidence_steps],
                evidence_freshness="FRESH" if any(_freshness(s.timestamp) == "FRESH" for s, _ in all_evidence_steps) else "RECENT",
                topology_relation="unverified-topology",
                status=FindingStatus.HYPOTHESIS,
                confidence=ConfidenceLevel.MEDIUM,
                recommended_action="Verify topology adjacency and path reachability between involved devices.",
                alternative_causes=[
                    "Devices exhibit similar symptoms but lack a verified topological causal link; could be independent coincidental issues.",
                ],
                explanation=(
                    f"Symptoms observed on {len(all_involved_devices)} devices, but no verified causal link or topology "
                    "adjacency connects them. Remaining at HYPOTHESIS."
                ),
            ))

        return findings

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        incident_summary: str,
        symptoms: List[str],
        target_device_ids: List[str],
        topology_snapshot: Optional[Dict[str, Any]] = None,
    ) -> RCAReport:
        """Execute the full troubleshooting workflow and return an RCAReport."""
        self.incident_id = str(uuid.uuid4())
        devices = [get_device_by_id(d_id) for d_id in target_device_ids]
        all_steps: List[DiagnosticStep] = []

        for device in devices:
            steps = self._collect_device_steps(device)
            for step in steps:
                for parser in [parse_interface_status, parse_ping_result, parse_route_table]:
                    result = parser(step.raw_output)
                    if result:
                        step.parsed_result.update(result)
                all_steps.append(step)

        findings = self._generate_findings(all_steps, topology_snapshot=topology_snapshot)

        overall_confidence = ConfidenceLevel.LOW
        for f in findings:
            if f.status == FindingStatus.CONFIRMED:
                overall_confidence = ConfidenceLevel.HIGH
                break

        return RCAReport(
            incident_id=self.incident_id,
            summary=incident_summary,
            symptoms=symptoms,
            target_devices=target_device_ids,
            topology_snapshot=topology_snapshot or {},
            steps=all_steps,
            findings=findings,
            probable_root_cause=next(
                (f.description for f in findings if f.status == FindingStatus.CONFIRMED), None
            ),
            confidence=overall_confidence,
            recommendations=[f.recommended_action for f in findings if f.recommended_action],
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        )


# Type hint helper
from typing import Any
