"""Safe, traceable QC evidence reference validation.

Evidence references are relative paths below a dedicated QC evidence directory.
Files must exist, be regular files, and must not traverse or follow symlinks.
Manual attestations are represented separately and are never labeled instrument data.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "quality-control" / "evidence"


class EvidenceValidationError(ValueError):
    pass


class QCEvidenceManager:
    def __init__(self, evidence_dir: Optional[str] = None):
        self.root = Path(evidence_dir or DEFAULT_EVIDENCE_DIR).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_no_symlink_components(self.root)

    @staticmethod
    def _assert_no_symlink_components(path: Path) -> None:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode):
                raise EvidenceValidationError("QC evidence paths must not contain symlinks.")

    def validate_reference(self, reference: Any, evidence_type: str = "MANUAL_ARTIFACT", instrument_id: Optional[str] = None) -> Dict[str, Any]:
        if not isinstance(reference, str) or not reference.strip():
            raise EvidenceValidationError("Evidence reference must be a non-empty relative file path.")
        relative = Path(reference)
        if relative.is_absolute() or any(part in {"..", ""} for part in relative.parts):
            raise EvidenceValidationError("Evidence reference must remain within the approved QC evidence directory.")
        candidate = self.root / relative
        self._assert_no_symlink_components(candidate)
        try:
            resolved_root = self.root.resolve(strict=True)
            resolved_file = candidate.resolve(strict=True)
            if os.path.commonpath([str(resolved_root), str(resolved_file)]) != str(resolved_root):
                raise EvidenceValidationError("Evidence reference escaped the approved QC evidence directory.")
            file_stat = resolved_file.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                raise EvidenceValidationError("QC evidence reference must point to a regular file.")
            if file_stat.st_size <= 0:
                raise EvidenceValidationError("QC evidence file is empty.")
            digest = hashlib.sha256()
            with resolved_file.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except FileNotFoundError:
            raise EvidenceValidationError("QC evidence reference does not resolve to an existing file.") from None
        except OSError as exc:
            raise EvidenceValidationError(f"QC evidence could not be validated: {exc}") from None

        kind = str(evidence_type or "MANUAL_ARTIFACT").upper()
        if kind not in {"MANUAL_ARTIFACT", "INSTRUMENT"}:
            raise EvidenceValidationError("evidence_type must be MANUAL_ARTIFACT or INSTRUMENT.")
        if kind == "INSTRUMENT" and (not isinstance(instrument_id, str) or not instrument_id.strip()):
            raise EvidenceValidationError("Instrument evidence requires a non-empty instrument_id.")
        return {
            "reference": relative.as_posix(),
            "absolute_path": str(resolved_file),
            "sha256": digest.hexdigest(),
            "evidence_type": kind,
            "instrument_id": instrument_id.strip() if isinstance(instrument_id, str) else None,
            "evidence_status": "ARTIFACT_VERIFIED",
        }

    @staticmethod
    def validate_manual_attestation(attested_by: Any, attestation: Any) -> Dict[str, Any]:
        if not isinstance(attested_by, str) or not attested_by.strip():
            raise EvidenceValidationError("Manual attestation requires attested_by.")
        if not isinstance(attestation, str) or not attestation.strip():
            raise EvidenceValidationError("Manual attestation requires a non-empty attestation statement.")
        return {
            "reference": f"manual-attestation:{attested_by.strip()}",
            "sha256": None,
            "evidence_type": "MANUAL_ATTESTATION",
            "instrument_id": None,
            "evidence_status": "MANUAL_ATTESTATION",
            "attestation": attestation.strip(),
        }
