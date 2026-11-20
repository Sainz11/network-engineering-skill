from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
import datetime
import uuid

class TestStatus(str, Enum):
    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"

class FinalQCStatus(str, Enum):
    PASS = "PASS"
    PASS_WITH_NOTES = "PASS_WITH_NOTES"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"

@dataclass
class TestItem:
    __test__ = False
    id: str
    name: str
    category: str
    mandatory: bool = True
    severity: Severity = Severity.MAJOR
    applicable_categories: List[str] = field(default_factory=list)
    description: str = ""

@dataclass
class TestResult:
    __test__ = False
    test_id: str
    test_name: str
    category: str
    status: TestStatus
    mandatory: bool
    measured_value: Any = None
    expected_threshold: Optional[str] = None
    threshold_source: Optional[str] = None
    evidence_reference: Optional[str] = None
    notes: str = ""
    evidence_type: Optional[str] = None
    evidence_status: Optional[str] = None
    evidence_sha256: Optional[str] = None
    instrument_id: Optional[str] = None
    evidence_attestation: Optional[str] = None

@dataclass
class DeviceIdentity:
    manufacturer: str
    model: str
    serial_number: str
    mac_address: Optional[str] = None
    hardware_revision: Optional[str] = None
    firmware_version: Optional[str] = None
    device_category: str = "UNKNOWN"
    device_id: Optional[str] = None

@dataclass
class QCReportData:
    session_id: str
    device: DeviceIdentity
    technician: str
    qc_date: str
    test_environment: str
    final_status: FinalQCStatus
    status_reason: str
    results: List[TestResult]
    findings: List[str] = field(default_factory=list)
    reviewer: Optional[str] = None
    approval_date: Optional[str] = None
    notes: str = ""
    workflow_status: str = "LOCAL_MANUAL_OFFLINE"
