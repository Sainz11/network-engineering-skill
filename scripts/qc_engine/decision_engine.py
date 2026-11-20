from typing import List, Dict, Any, Tuple
import re
from .models import TestStatus, FinalQCStatus, TestResult, Severity

class DecisionEngine:
    @staticmethod
    def _has_valid_evidence_metadata(result: TestResult) -> bool:
        """Require traceable metadata already validated by QCEvidenceManager."""
        reference = result.evidence_reference
        evidence_type = result.evidence_type
        if result.evidence_status == "ARTIFACT_VERIFIED":
            if evidence_type not in {"MANUAL_ARTIFACT", "INSTRUMENT"}:
                return False
            if not isinstance(reference, str) or not reference.strip():
                return False
            if not isinstance(result.evidence_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", result.evidence_sha256):
                return False
            if evidence_type == "INSTRUMENT" and (not isinstance(result.instrument_id, str) or not result.instrument_id.strip()):
                return False
            return True
        if result.evidence_status == "MANUAL_ATTESTATION":
            return (
                evidence_type == "MANUAL_ATTESTATION"
                and isinstance(reference, str)
                and reference.startswith("manual-attestation:")
                and isinstance(result.evidence_attestation, str)
                and bool(result.evidence_attestation.strip())
            )
        return False

    @staticmethod
    def evaluate(results: List[TestResult]) -> Tuple[FinalQCStatus, str, List[str]]:
        findings: List[str] = []
        has_mandatory_fail = False
        has_mandatory_missing_or_review = False
        has_optional_fail = False
        
        tested_count = 0
        pass_count = 0

        for r in results:
            if r.status in [TestStatus.PASS]:
                if r.mandatory and not DecisionEngine._has_valid_evidence_metadata(r):
                    has_mandatory_missing_or_review = True
                    findings.append(
                        f"Mandatory test cannot PASS without valid evidence: [{r.category}] {r.test_name} "
                        f"(evidence_status={r.evidence_status or 'MISSING'}, evidence_type={r.evidence_type or 'MISSING'}, "
                        f"evidence_reference={'present' if r.evidence_reference else 'MISSING'})."
                    )
                    continue
                pass_count += 1
                tested_count += 1
            elif r.status in [TestStatus.FAIL]:
                tested_count += 1
                findings.append(f"Failed [{r.category}] {r.test_name}: measured={r.measured_value}, expected={r.expected_threshold}. Notes: {r.notes}")
                if r.mandatory:
                    has_mandatory_fail = True
                else:
                    has_optional_fail = True
            elif r.status in [TestStatus.NEEDS_REVIEW, TestStatus.NOT_TESTED]:
                if r.mandatory:
                    has_mandatory_missing_or_review = True
                    findings.append(f"Mandatory test requires review or evidence missing: [{r.category}] {r.test_name} (Status: {r.status.value})")
                else:
                    findings.append(f"Optional test flagged for review: [{r.category}] {r.test_name}")
            elif r.status == TestStatus.NOT_APPLICABLE:
                # Expected for unsupported features
                pass

        if has_mandatory_fail:
            return FinalQCStatus.FAIL, "One or more mandatory test items failed verification.", findings
        
        if has_mandatory_missing_or_review:
            return FinalQCStatus.NEEDS_REVIEW, "Mandatory test items lack complete verified evidence or require technical review.", findings

        if has_optional_fail:
            return FinalQCStatus.PASS_WITH_NOTES, "All mandatory criteria passed; minor optional tests failed or flagged with notes.", findings

        if pass_count > 0:
            return FinalQCStatus.PASS, "All evaluated mandatory criteria successfully met specification thresholds.", findings
        else:
            return FinalQCStatus.NEEDS_REVIEW, "No valid test measurements recorded.", findings
