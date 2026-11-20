"""Packaging integrity tests.

Ensures that packages and distribution files:
- Contain NO compiled bytecode (__pycache__, *.pyc, *.pyo).
- Contain NO test caches (.pytest_cache).
- Contain NO stale operational audit logs (audit_trail.jsonl).
- Contain NO unencrypted plaintext keys or credentials.
- Retain all required core files and modules.
"""

import os
import sys
import zipfile
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
FORBIDDEN_EXTENSIONS = {".pyc", ".pyo"}
FORBIDDEN_DIRS = {"__pycache__", ".pytest_cache"}
FORBIDDEN_FILES = {"audit_trail.jsonl", ".env", "id_rsa", "id_ed25519", "credentials.json", "secrets.json"}
FORBIDDEN_SUFFIXES = {".pem", ".p12", ".pfx", ".key", ".pyc", ".pyo"}
REQUIRED_ARCHIVE_FILES = {
    "SKILL.md", "README.md", "engine/auth_provider.py",
    "engine/policy/security_policy.py", "tests/helpers/auth_test_helper.py",
    "tests/test_p0_security.py", "tests/test_connector_security.py",
}


class TestPackagingHygiene(unittest.TestCase):
    """P1-3 packaging and repository hygiene test suite."""

    def test_repo_has_no_operational_audit_logs(self):
        """Repository root and subdirectories must not contain operational audit logs."""
        found = []
        for p in REPO_ROOT.rglob("*.jsonl"):
            if "audit" in p.name.lower():
                found.append(str(p.relative_to(REPO_ROOT)))
        self.assertEqual(found, [], f"Found operational audit log files in repo: {found}")

    def test_repository_has_no_secret_files_or_temp_artifacts(self):
        found = []
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(REPO_ROOT)
            if any(part in FORBIDDEN_DIRS for part in relative.parts):
                continue  # generated caches may exist during tests; final ZIP is checked separately
            if path.name in FORBIDDEN_FILES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
                found.append(str(relative))
        self.assertEqual(found, [], f"Secret/temp files found: {found}")

    def test_gitignore_covers_hygiene_patterns(self):
        """Verify .gitignore contains patterns for cache, bytecode, and audit logs."""
        gitignore = REPO_ROOT / ".gitignore"
        self.assertTrue(gitignore.exists(), ".gitignore must exist")
        text = gitignore.read_text(encoding="utf-8")
        self.assertIn("__pycache__", text)
        self.assertIn("*.py[cod]", text)
        self.assertIn(".pytest_cache", text)
        self.assertIn("audit_trail.jsonl", text)

    def test_zip_artifact_hygiene_if_present(self):
        """If network-engineering-skill-fixed.zip exists, verify its contents are clean."""
        zip_candidates = [
            pathlib.Path(r"C:/Users/dell/.gemini/antigravity/brain/b71373f6-3fd8-4c49-8c4b-8654436a4a7e/network-engineering-skill-fixed.zip"),
            REPO_ROOT / "network-engineering-skill-fixed.zip",
            REPO_ROOT / "network-engineering-skill-final.zip",
        ]
        tested = False
        for zpath in zip_candidates:
            if zpath.exists():
                tested = True
                with zipfile.ZipFile(str(zpath), "r") as zf:
                    names = set(zf.namelist())
                    for name in names:
                        parts = pathlib.PurePosixPath(name).parts
                        self.assertFalse(pathlib.PurePosixPath(name).is_absolute(), f"Absolute ZIP path: {name}")
                        self.assertNotIn("..", parts, f"ZIP path traversal: {name}")
                        for fdir in FORBIDDEN_DIRS:
                            self.assertNotIn(fdir, parts, f"Forbidden cache directory '{fdir}' found in ZIP entry '{name}'")
                        for ext in FORBIDDEN_EXTENSIONS:
                            self.assertFalse(name.endswith(ext), f"Forbidden compiled bytecode '{ext}' found in ZIP entry '{name}'")
                        basename = pathlib.PurePosixPath(name).name
                        self.assertNotIn(basename, FORBIDDEN_FILES, f"Forbidden secret/log file found: {name}")
                        self.assertFalse(basename.lower().startswith(".env.") and basename != ".env.example", f"Unexpected env file: {name}")
                        self.assertFalse(pathlib.PurePosixPath(name).parts[0] == ".git", f"Git metadata must not ship: {name}")
                        self.assertFalse(pathlib.PurePosixPath(name).parts[0] == "artifacts", f"Evidence artifacts must not ship: {name}")
                    self.assertTrue(REQUIRED_ARCHIVE_FILES.issubset(names), f"Required files missing from ZIP: {REQUIRED_ARCHIVE_FILES - names}")
        if not tested:
            self.skipTest("No distribution zip found to inspect yet.")


if __name__ == "__main__":
    unittest.main()
