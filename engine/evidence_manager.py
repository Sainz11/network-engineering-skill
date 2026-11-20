"""Shared metadata-only evidence registry for auditable module workflows.

This registry does not replace source evidence artifacts (for example QC files or
protected troubleshooting output). It records metadata and a digest of a redacted
workflow result so all modules share a common evidence reference.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class EvidenceRegistryError(RuntimeError):
    """Raised when shared workflow evidence cannot be recorded safely."""


class OperationEvidenceManager:
    def __init__(self, root: Optional[str] = None):
        configured = root or os.environ.get("NETWORK_SKILL_EVIDENCE_DIR")
        self.root = Path(configured or (Path.home() / ".network-engineering-skill" / "evidence")).expanduser().absolute()
        # Inspect existing ancestors before mkdir so a pre-planted symlink cannot
        # redirect directory creation outside the configured location.
        current = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            current = current / part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise EvidenceRegistryError("Shared evidence root must not contain symlink components.")
            except FileNotFoundError:
                break
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._assert_safe_root()

    def _assert_safe_root(self) -> None:
        current = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            current = current / part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise EvidenceRegistryError("Shared evidence root must not contain symlink components.")
            except FileNotFoundError:
                continue
        resolved = self.root.resolve(strict=True)
        if not resolved.is_dir():
            raise EvidenceRegistryError("Shared evidence root must be a directory.")
        self.root = resolved
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            # Do not silently broaden permissions; the current directory's ACLs
            # remain an environmental boundary and are called out in limitations.
            pass

    @staticmethod
    def _serializable_result(value: Any) -> Any:
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return OperationEvidenceManager._serializable_result(dataclasses.asdict(value))
        if isinstance(value, dict):
            return {str(k): OperationEvidenceManager._serializable_result(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [OperationEvidenceManager._serializable_result(v) for v in value]
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    def record_workflow_result(
        self,
        *,
        request_id: str,
        module: str,
        workflow: str,
        device_id: str,
        result: Any,
        execution_status: str = "SIMULATED",
    ) -> Dict[str, Any]:
        """Persist metadata and a digest; never persist raw command output/secrets."""
        if execution_status != "SIMULATED":
            raise EvidenceRegistryError("This module evidence registry accepts only explicit SIMULATED workflows.")
        try:
            normalized = self._serializable_result(result)
            canonical = json.dumps(
                normalized, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise EvidenceRegistryError(f"Workflow result cannot be canonicalized: {type(exc).__name__}.") from None
        digest = hashlib.sha256(canonical).hexdigest()
        evidence_id = f"EV-{uuid.uuid4().hex}"
        record = {
            "evidence_id": evidence_id,
            "request_id": str(request_id),
            "module": str(module),
            "workflow": str(workflow),
            "device_id": str(device_id),
            "execution_status": "SIMULATED",
            "is_hardware_evidence": False,
            "result_sha256": digest,
            "result_type": type(result).__name__,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        final_path = self.root / f"{evidence_id}.json"
        with self._lock:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".evidence-", suffix=".tmp", dir=str(self.root))
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    json.dump(record, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._assert_safe_root()
                os.replace(temporary_name, final_path)
                if hasattr(os, "O_DIRECTORY"):
                    directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass
                raise
        return {
            "evidence_id": evidence_id,
            "reference": final_path.name,
            "sha256": hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
            "result_sha256": digest,
            "execution_status": "SIMULATED",
            "is_hardware_evidence": False,
        }

    def read_record(self, reference: str) -> Dict[str, Any]:
        if not isinstance(reference, str) or Path(reference).name != reference or not reference.startswith("EV-") or not reference.endswith(".json"):
            raise EvidenceRegistryError("Invalid shared evidence reference.")
        path = self.root / reference
        self._assert_safe_root()
        try:
            if stat.S_ISLNK(path.lstat().st_mode):
                raise EvidenceRegistryError("Shared evidence references cannot be symlinks.")
            resolved = path.resolve(strict=True)
            if resolved.parent != self.root:
                raise EvidenceRegistryError("Shared evidence reference escaped approved root.")
            data = json.loads(resolved.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise EvidenceRegistryError("Shared evidence reference does not exist.") from None
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceRegistryError(f"Shared evidence record cannot be read: {type(exc).__name__}.") from None
        if (
            not isinstance(data, dict)
            or data.get("evidence_id") != path.stem
            or data.get("execution_status") != "SIMULATED"
            or data.get("is_hardware_evidence") is not False
            or not isinstance(data.get("result_sha256"), str)
            or len(data["result_sha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in data["result_sha256"])
            or not all(isinstance(data.get(k), str) and data[k] for k in ("request_id", "module", "workflow", "device_id"))
        ):
            raise EvidenceRegistryError("Shared evidence record failed provenance validation.")
        return data
