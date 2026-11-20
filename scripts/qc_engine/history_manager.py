"""Safe, atomic QC history storage constrained to an approved directory."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import List, Dict, Any, Optional

HISTORY_DIR = Path(__file__).resolve().parents[2] / "quality-control" / "history"
HISTORY_FILE = HISTORY_DIR / "qc_sessions.json"


class QCHistoryManager:
    def __init__(self, history_file: Optional[str] = None, allowed_root: Optional[str] = None):
        self.root = Path(allowed_root).absolute() if allowed_root else HISTORY_DIR.absolute()
        if history_file is None:
            self.history_path = self.root / "qc_sessions.json"
        else:
            self.history_path = Path(history_file).absolute()
        self._thread_lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)
        self._validate_paths()
        if not self.history_path.exists():
            self._atomic_write([])

    def _validate_paths(self) -> None:
        """Reject traversal and symlink components from approved root to file."""
        root = self.root.resolve(strict=True)
        current = Path(self.history_path.anchor)
        for part in self.history_path.parts[1:]:
            current = current / part
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode):
                raise PermissionError("QC history path must not contain symlinks.")
        parent = self.history_path.parent.resolve(strict=True)
        if os.path.commonpath([str(root), str(parent)]) != str(root):
            raise PermissionError("QC history file must remain inside its approved history directory.")
        if self.history_path.exists() and not stat.S_ISREG(self.history_path.stat().st_mode):
            raise PermissionError("QC history destination must be a regular file.")

    @contextmanager
    def _exclusive_lock(self):
        """Serialize writers across threads and processes where OS locks exist."""
        with self._thread_lock:
            lock_path = self.root / (self.history_path.name + ".lock")
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(lock_path, flags, 0o600)
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                    try:
                        yield
                    finally:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _atomic_write(self, sessions: List[Dict[str, Any]]) -> None:
        self._validate_paths()
        fd, temp_name = tempfile.mkstemp(prefix=".qc-history-", suffix=".tmp", dir=str(self.root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(sessions, stream, indent=2, ensure_ascii=False, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            # Re-check destination immediately before replacement; never replace a symlink.
            self._validate_paths()
            os.replace(temp_name, self.history_path)
            try:
                dir_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def record_session(self, session_summary: Dict[str, Any]):
        if not isinstance(session_summary, dict) or not session_summary.get("session_id"):
            raise ValueError("QC session summary must contain a session_id.")
        with self._exclusive_lock():
            sessions = self._load_all_unlocked()
            sessions = [s for s in sessions if s.get("session_id") != session_summary.get("session_id")]
            sessions.append(session_summary)
            self._atomic_write(sessions)

    def _load_all_unlocked(self) -> List[Dict[str, Any]]:
        self._validate_paths()
        if not self.history_path.exists():
            return []
        with self.history_path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise ValueError("QC history file has an invalid JSON structure.")
        return payload

    def load_all(self) -> List[Dict[str, Any]]:
        with self._exclusive_lock():
            return self._load_all_unlocked()

    def get_device_history(self, serial_number: str) -> List[Dict[str, Any]]:
        sessions = self.load_all()
        return [s for s in sessions if s.get("device", {}).get("serial_number") == serial_number]

    def get_summary_statistics(self) -> Dict[str, Any]:
        sessions = self.load_all()
        total = len(sessions)
        counts = {"PASS": 0, "PASS_WITH_NOTES": 0, "FAIL": 0, "NEEDS_REVIEW": 0}
        model_stats = {}
        for session in sessions:
            status = session.get("final_status", "NEEDS_REVIEW")
            counts[status] = counts.get(status, 0) + 1
            model = f"{session.get('device', {}).get('manufacturer')} {session.get('device', {}).get('model')}"
            if model not in model_stats:
                model_stats[model] = {"total": 0, "pass": 0, "fail": 0}
            model_stats[model]["total"] += 1
            if "PASS" in status:
                model_stats[model]["pass"] += 1
            else:
                model_stats[model]["fail"] += 1
        return {"total_inspections": total, "status_counts": counts, "models": model_stats}
