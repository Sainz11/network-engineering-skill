import datetime
import uuid
import re
from typing import Dict, Any, List, Optional
from .models import DeviceIdentity, TestStatus, TestResult, QCReportData, FinalQCStatus
from .profile_loader import ProfileLoader
from .test_catalog import TestCatalog
from .decision_engine import DecisionEngine
from .report_generator import QCReportGenerator
from .history_manager import QCHistoryManager
from .evidence_manager import QCEvidenceManager, EvidenceValidationError

class QCTestEngine:
    @staticmethod
    def _parse_speed_mbps(value: Any) -> Optional[float]:
        """Parse an explicit Ethernet link rate; ambiguous values stay unverified."""
        if not isinstance(value, str):
            return None
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(gbps|g|mbps|m)\s*", value, re.IGNORECASE)
        if not match:
            return None
        number = float(match.group(1))
        unit = match.group(2).casefold()
        return number * 1000.0 if unit in {"gbps", "g"} else number

    @staticmethod
    def _profile_ethernet_speeds_mbps(profile: Dict[str, Any]) -> List[float]:
        """Extract profile-advertised Ethernet rates without guessing unknown units."""
        interfaces = profile.get("interfaces", {}) if isinstance(profile, dict) else {}
        specification = interfaces.get("speed", "") if isinstance(interfaces, dict) else ""
        if not isinstance(specification, str):
            return []
        values = [float(item) for item in re.findall(r"(?<![\w.])(\d+(?:\.\d+)?)(?![\w.])", specification)]
        normalized = specification.casefold()
        if "gbps" in normalized and "mbps" not in normalized:
            values = [item * 1000.0 for item in values]
        return sorted(set(values))

    def __init__(self, profiles_dir: Optional[str] = None, history_file: Optional[str] = None, evidence_dir: Optional[str] = None, history_root: Optional[str] = None, operations_engine=None, user_ctx=None):
        self.profile_loader = ProfileLoader(profiles_dir)
        self.catalog = TestCatalog()
        self.history_manager = QCHistoryManager(history_file, allowed_root=history_root)
        self.evidence_manager = QCEvidenceManager(evidence_dir)
        self.operations_engine = operations_engine
        self.user_ctx = user_ctx

    def run_qc_session(
        self,
        device: DeviceIdentity,
        measurements: Dict[str, Any],
        technician: str,
        test_environment: str = "Lab Staging Bench",
        reviewer: Optional[str] = None,
        notes: str = ""
    ) -> QCReportData:
        if self.operations_engine is None:
            return self._run_qc_session_core(device, measurements, technician, test_environment, reviewer, notes, "LOCAL_MANUAL_OFFLINE")
        if not self.user_ctx or not device.device_id:
            raise PermissionError("Shared QC workflow requires an authenticated user and canonical device_id.")
        from engine.execution.module_workflow import execute_authorized_module_workflow
        from engine.policy.types import OperationClassification

        def run_assessment(canonical, _parameters):
            if canonical.vendor.casefold() != device.manufacturer.casefold() or canonical.model.casefold() != device.model.casefold():
                raise PermissionError("QC device manufacturer/model does not match canonical inventory identity.")
            return self._run_qc_session_core(device, measurements, technician, test_environment, reviewer, notes, "AUTHORIZED_SIMULATED")

        result = execute_authorized_module_workflow(
            operations_engine=self.operations_engine,
            user_ctx=self.user_ctx,
            device_id=device.device_id,
            module="advanced_device_quality_control",
            workflow="qc_assessment",
            classification=OperationClassification.READ_ONLY,
            parameters={"device_id": device.device_id, "measurement_count": len(measurements)},
            handler=run_assessment,
        )
        if not result.success:
            raise PermissionError(result.error or "Shared OperationsEngine denied QC assessment.")
        report = result.output.get("result") if isinstance(result.output, dict) else None
        if not isinstance(report, QCReportData):
            raise RuntimeError("Shared QC workflow did not return a QCReportData record.")
        return report

    def _run_qc_session_core(
        self,
        device: DeviceIdentity,
        measurements: Dict[str, Any],
        technician: str,
        test_environment: str = "Lab Staging Bench",
        reviewer: Optional[str] = None,
        notes: str = "",
        workflow_status: str = "LOCAL_MANUAL_OFFLINE"
    ) -> QCReportData:
        session_id = f"QC-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        qc_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Load device profile
        profile = self.profile_loader.get_profile(device.manufacturer, device.model)
        if profile and profile.get("device_category"):
            device.device_category = profile.get("device_category")

        # 2. Select applicable tests
        applicable_tests = self.catalog.get_applicable_tests(device.device_category, profile)

        # 3. Evaluate each test against profile criteria and provided measurements
        results: List[TestResult] = []
        for test in applicable_tests:
            # Check measurement input for this test id or test name key
            m_data = measurements.get(test.id) or measurements.get(test.name)
            
            if m_data is None:
                # No measurement recorded
                status = TestStatus.NOT_TESTED
                res = TestResult(
                    test_id=test.id,
                    test_name=test.name,
                    category=test.category,
                    status=status,
                    mandatory=test.mandatory,
                    measured_value=None,
                    expected_threshold="Criteria required in profile",
                    threshold_source="Test Catalog",
                    evidence_reference=None,
                    notes="No test evidence or measurement supplied."
                )
                results.append(res)
                continue

            # Parse measurement dict or raw value
            measured_val = m_data.get("value") if isinstance(m_data, dict) else m_data
            status_val = m_data.get("status") if isinstance(m_data, dict) else None
            evidence_ref = m_data.get("evidence_ref") if isinstance(m_data, dict) else None
            evidence_type = m_data.get("evidence_type", "MANUAL_ARTIFACT") if isinstance(m_data, dict) else None
            instrument_id = m_data.get("instrument_id") if isinstance(m_data, dict) else None
            attested_by = m_data.get("attested_by") if isinstance(m_data, dict) else None
            attestation = m_data.get("attestation") if isinstance(m_data, dict) else None
            evidence_metadata = None
            m_notes = ""
            if isinstance(m_data, dict) and (attested_by or attestation):
                try:
                    evidence_metadata = self.evidence_manager.validate_manual_attestation(attested_by, attestation)
                except EvidenceValidationError as exc:
                    m_notes = f"Invalid manual attestation: {exc}"
            elif evidence_ref:
                try:
                    evidence_metadata = self.evidence_manager.validate_reference(
                        evidence_ref, evidence_type=evidence_type, instrument_id=instrument_id
                    )
                except EvidenceValidationError as exc:
                    m_notes = f"Invalid evidence reference: {exc}"
            else:
                m_notes = "No valid evidence supplied."
            m_notes = (m_data.get("notes", "") + (" " + m_notes if m_notes else "")) if isinstance(m_data, dict) else m_notes

            # Check profile-based thresholds
            expected_thresh = "N/A"
            thresh_source = "Test Specification"

            if test.id == "ETH-01" and profile:
                ports_info = profile.get("interfaces", {})
                expected_thresh = f"Speeds: {ports_info.get('speed', 'Rated speed')}"
                thresh_source = f"{profile.get('model')} Datasheet"
                observed_speed = self._parse_speed_mbps(measured_val)
                supported_speeds = self._profile_ethernet_speeds_mbps(profile)
                expected_thresh = f"Supported link rates: {', '.join(str(int(v)) for v in supported_speeds)} Mbps" if supported_speeds else expected_thresh
                if status_val and str(status_val).upper() == TestStatus.FAIL.value:
                    status = TestStatus.FAIL
                elif observed_speed is None or not supported_speeds:
                    status = TestStatus.NEEDS_REVIEW
                    m_notes += " Ethernet link rate is missing, ambiguous, or profile speed capability is unavailable."
                elif observed_speed not in supported_speeds:
                    status = TestStatus.FAIL
                    m_notes += f" Observed Ethernet rate {observed_speed:g} Mbps is not supported by this model profile."
                else:
                    # A negotiated rate must be explicitly parseable and supported by
                    # the exact model profile. Do not turn arbitrary non-empty values
                    # or a manual PASS flag into a passing hardware check.
                    status = TestStatus.PASS

            elif test.id == "OPT-02" and profile:
                opt_info = profile.get("optical_capabilities", {})
                rx_min = opt_info.get("rx_power_min_dbm")
                rx_max = opt_info.get("rx_power_max_dbm")
                expected_thresh = f"{rx_min} to {rx_max} dBm" if rx_min is not None else "Model Specification"
                thresh_source = opt_info.get("reference_source", "Optical Module Specification")

                if measured_val is not None and rx_min is not None and rx_max is not None:
                    try:
                        val_float = float(measured_val)
                        if rx_min <= val_float <= rx_max:
                            status = TestStatus.PASS
                        else:
                            status = TestStatus.FAIL
                            m_notes += f" Optical RX {val_float} dBm outside allowed range [{rx_min}, {rx_max}]."
                    except ValueError:
                        status = TestStatus.NEEDS_REVIEW
                        m_notes += " Invalid numeric optical measurement format."
                else:
                    status = TestStatus(status_val) if status_val else TestStatus.NEEDS_REVIEW

            else:
                # General evaluation
                if status_val:
                    status = TestStatus(status_val)
                elif measured_val in [True, "PASS", "pass", "OK", "ok"]:
                    status = TestStatus.PASS
                elif measured_val in [False, "FAIL", "fail"]:
                    status = TestStatus.FAIL
                elif measured_val == "N/A":
                    status = TestStatus.NOT_APPLICABLE
                else:
                    status = TestStatus.PASS if measured_val else TestStatus.NEEDS_REVIEW

            # A mandatory PASS is downgraded unless the evidence reference resolves
            # to a real artifact or a separately recorded manual attestation.
            if test.mandatory and status == TestStatus.PASS and evidence_metadata is None:
                status = TestStatus.NEEDS_REVIEW
                m_notes += " Mandatory PASS downgraded: valid evidence is missing or could not be verified."

            results.append(TestResult(
                test_id=test.id,
                test_name=test.name,
                category=test.category,
                status=status,
                mandatory=test.mandatory,
                measured_value=measured_val,
                expected_threshold=expected_thresh,
                threshold_source=thresh_source,
                evidence_reference=(evidence_metadata or {}).get("reference", evidence_ref),
                notes=m_notes.strip(),
                evidence_type=(evidence_metadata or {}).get("evidence_type"),
                evidence_status=(evidence_metadata or {}).get("evidence_status"),
                evidence_sha256=(evidence_metadata or {}).get("sha256"),
                instrument_id=(evidence_metadata or {}).get("instrument_id"),
                evidence_attestation=(evidence_metadata or {}).get("attestation")
            ))

        # 4. Decision engine
        final_status, reason, findings = DecisionEngine.evaluate(results)

        # 5. Build report data
        report_data = QCReportData(
            session_id=session_id,
            device=device,
            technician=technician,
            qc_date=qc_date,
            test_environment=test_environment,
            final_status=final_status,
            status_reason=reason,
            results=results,
            findings=findings,
            reviewer=reviewer,
            notes=notes,
            workflow_status=workflow_status
        )

        # 6. Record session in history
        summary = {
            "session_id": session_id,
            "qc_date": qc_date,
            "technician": technician,
            "device": {
                "manufacturer": device.manufacturer,
                "model": device.model,
                "serial_number": device.serial_number,
                "firmware_version": device.firmware_version
            },
            "final_status": final_status.value,
            "status_reason": reason,
            "workflow_status": workflow_status,
            "findings_count": len(findings),
            "results": [
                {
                    "test_id": result.test_id,
                    "status": result.status.value,
                    "mandatory": result.mandatory,
                    "evidence_reference": result.evidence_reference,
                    "evidence_type": result.evidence_type,
                    "evidence_status": result.evidence_status,
                    "evidence_sha256": result.evidence_sha256,
                    "instrument_id": result.instrument_id,
                    "evidence_attestation": result.evidence_attestation,
                }
                for result in results
            ]
        }
        self.history_manager.record_session(summary)

        return report_data
