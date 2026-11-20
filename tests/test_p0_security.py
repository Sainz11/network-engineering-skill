"""Security tests for P0 remediation.

Covers:
  - Authentication (P0-1 / P0-2)
  - Authorization
  - Windows evidence protection (P0-3)
  - Path traversal / symlink handling
  - AES-GCM tamper detection
  - Atomic file creation
  - Retention cleanup
  - DPAPI mock/stub behaviour
  - Regression: authenticated context flows through pipeline
"""

import os
import sys
import stat
import json
import hashlib
import secrets
import tempfile
import shutil
import unittest
from pathlib import Path
from unittest import mock

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.auth_provider import (
    LocalDevAuthProvider,
    ProdAuthProvider,
    get_auth_provider,
    authenticate_current_user,
    AuthenticationError,
    UserContext as AuthUserContext,
)
from engine.troubleshoot._utils import (
    safe_join,
    calculate_sha256,
    verify_sha256,
    store_raw_output,
    read_raw_output,
    cleanup_old_evidence,
    _secure_delete,
    _encrypt_evidence,
    _decrypt_evidence,
    _atomic_create,
    PathTraversalError,
    EvidenceProtectionError,
    EvidenceIntegrityError,
    ARTIFACT_ROOT,
    _HAS_CRYPTOGRAPHY,
    _IS_WINDOWS,
    _HAS_DPAPI,
)


# ===========================================================================
# A. Authentication tests  (P0-1 / P0-2)
# ===========================================================================

class TestLocalDevAuthProvider(unittest.TestCase):
    """LocalDevAuthProvider must require explicit opt-in and restrict scopes."""

    def _env(self, **kwargs):
        base = {k: v for k, v in os.environ.items()}
        base.update(kwargs)
        return base

    def test_rejects_when_env_not_dev(self):
        """Must reject when AGY_ENV is absent or not 'dev'."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "production"}, clear=False):
            os.environ.pop("AGY_ENV", None)
            with self.assertRaises(AuthenticationError):
                LocalDevAuthProvider().authenticate()

    def test_rejects_when_agy_env_not_dev_explicit(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "prod", "AGY_USER": "alice"}):
            with self.assertRaises(AuthenticationError):
                LocalDevAuthProvider().authenticate()

    def test_rejects_missing_agy_user(self):
        env = {"AGY_ENV": "dev"}
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("AGY_USER", None)
            with self.assertRaises(AuthenticationError):
                LocalDevAuthProvider().authenticate()

    def test_rejects_empty_agy_user(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": ""}):
            with self.assertRaises(AuthenticationError):
                LocalDevAuthProvider().authenticate()

    def test_rejects_traversal_in_username(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "../admin"}):
            with self.assertRaises(AuthenticationError):
                LocalDevAuthProvider().authenticate()

    def test_returns_user_context_on_success(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "noc-operator"}):
            ctx = LocalDevAuthProvider().authenticate()
        self.assertEqual(ctx.username, "noc-operator")
        self.assertTrue(ctx.is_dev_mode)

    def test_never_grants_write_in_dev_mode(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "attacker"}):
            ctx = LocalDevAuthProvider().authenticate()
        self.assertNotIn("WRITE", ctx.authorized_scopes)
        self.assertNotIn("CRITICAL", ctx.authorized_scopes)

    def test_never_grants_critical_in_dev_mode(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "attacker", "AGY_DEV_ROLE": "Admin"}):
            ctx = LocalDevAuthProvider().authenticate()
        self.assertNotIn("CRITICAL", ctx.authorized_scopes)
        self.assertNotIn("WRITE", ctx.authorized_scopes)

    def test_context_is_frozen(self):
        """UserContext must be immutable — callers cannot mutate scopes."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "operator"}):
            ctx = LocalDevAuthProvider().authenticate()
        with self.assertRaises((TypeError, AttributeError)):
            ctx.authorized_scopes = {"WRITE", "CRITICAL"}  # type: ignore[misc]

    def test_has_scope_read_only(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "operator"}):
            ctx = LocalDevAuthProvider().authenticate()
        self.assertTrue(ctx.has_scope("READ_ONLY"))
        self.assertFalse(ctx.has_scope("DIAGNOSTIC"), "DIAGNOSTIC must require explicit opt-in")
        self.assertFalse(ctx.has_scope("WRITE"))


class TestProdAuthProvider(unittest.TestCase):
    """ProdAuthProvider must always fail closed."""

    def test_always_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            ProdAuthProvider().authenticate()

    def test_does_not_fall_back_to_dev(self):
        """Even with AGY_USER set, production auth must fail closed."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "prod", "AGY_USER": "admin"}):
            with self.assertRaises(NotImplementedError):
                ProdAuthProvider().authenticate()


class TestGetAuthProvider(unittest.TestCase):
    """get_auth_provider() must select the correct provider."""

    def test_returns_dev_provider_for_dev(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            self.assertIsInstance(get_auth_provider(), LocalDevAuthProvider)

    def test_returns_prod_provider_by_default(self):
        env = dict(os.environ)
        env.pop("AGY_ENV", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsInstance(get_auth_provider(), ProdAuthProvider)

    def test_returns_prod_provider_for_non_dev(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "staging"}):
            self.assertIsInstance(get_auth_provider(), ProdAuthProvider)


class TestCLICannotSpoofIdentity(unittest.TestCase):
    """Verify the CLI has no --user / --role arguments."""

    def test_cli_has_no_user_argument(self):
        """The CLI must not accept --user."""
        from engine.cli.netops_cli import main
        import io
        with mock.patch("sys.argv", ["netops_cli", "exec", "--device", "r1", "--user", "admin"]):
            with self.assertRaises(SystemExit):
                # argparse will error on unknown --user argument
                main()

    def test_cli_has_no_role_argument(self):
        """The CLI must not accept --role."""
        from engine.cli.netops_cli import main
        with mock.patch("sys.argv", ["netops_cli", "exec", "--device", "r1", "--role", "Admin"]):
            with self.assertRaises(SystemExit):
                main()

    def test_cli_requires_authenticated_session(self):
        """CLI must refuse when no AGY_ENV=dev or prod auth is configured."""
        env = dict(os.environ)
        env.pop("AGY_ENV", None)
        env.pop("AGY_USER", None)
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch("sys.argv", ["netops_cli", "exec", "--device", "r1"]):
                with self.assertRaises(SystemExit) as cm:
                    from engine.cli.netops_cli import main
                    main()
                self.assertEqual(cm.exception.code, 2)


# ===========================================================================

class TestIssuedContextSignatureTampering(unittest.TestCase):
    def test_dataclasses_replace_tampering_is_rejected_for_all_signed_fields(self):
        from dataclasses import replace
        from tests.helpers.auth_test_helper import create_test_context
        from engine.auth_provider import verify_issued_context

        original = create_test_context(username="signed-user", role="operator", scopes={"READ_ONLY", "DIAGNOSTIC"}, is_dev_mode=True, authorized_devices={"RTR-CORE-01"})
        self.assertTrue(verify_issued_context(original))
        tampered = {"username": "other-user", "role": "admin", "authorized_scopes": frozenset({"READ_ONLY", "DIAGNOSTIC", "WRITE"}), "session_id": "session-other", "is_dev_mode": False, "authorized_devices": frozenset({"*"}), "issuer_id": "forged-issuer"}
        for field, value in tampered.items():
            with self.subTest(field=field):
                self.assertFalse(verify_issued_context(replace(original, **{field: value})))

    def test_none_and_empty_session_id_are_distinct_and_tampering_rejected(self):
        from dataclasses import replace
        from tests.helpers.auth_test_helper import create_test_context
        from engine.auth_provider import verify_issued_context
        original = create_test_context(username="signed-user", role="operator", scopes={"READ_ONLY"}, authorized_devices={"RTR-1"})
        self.assertTrue(verify_issued_context(original))
        self.assertFalse(verify_issued_context(replace(original, session_id="")))

    def test_runtime_has_no_unrestricted_signing_api(self):
        import engine.auth_provider as auth
        self.assertFalse(hasattr(auth, "_compute_context_signature"))
        self.assertFalse(hasattr(auth, "_AUTH_ISSUER_SECRET"))
        self.assertFalse(hasattr(auth, "_ISSUER_SIGN"))
        self.assertFalse(hasattr(auth, "_create_provider_capabilities"))

    def test_canonical_signatures_are_deterministic_for_equivalent_set_order(self):
        from engine.auth_provider import verify_issued_context
        provider = LocalDevAuthProvider()
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "same-user", "AGY_DEV_DEVICES": "RTR-1,RTR-2"}):
            first = provider.authenticate()
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev", "AGY_USER": "same-user", "AGY_DEV_DEVICES": "RTR-2,RTR-1"}):
            second = provider.authenticate()
        self.assertEqual(first._signature, second._signature)
        self.assertTrue(verify_issued_context(first))
        self.assertTrue(verify_issued_context(second))

# B. Authorization tests
# ===========================================================================

class TestAuthorizationScopes(unittest.TestCase):
    """Verify scope enforcement in the operations pipeline."""

    def _make_dev_ctx(self, **env_overrides):
        env = {"AGY_ENV": "dev", "AGY_USER": "test-noc"}
        env.update(env_overrides)
        with mock.patch.dict(os.environ, env):
            return LocalDevAuthProvider().authenticate()

    def test_dev_context_authorizes_read_only(self):
        ctx = self._make_dev_ctx()
        self.assertTrue(ctx.has_scope("READ_ONLY"))

    def test_dev_context_authorizes_diagnostic_only_with_explicit_opt_in(self):
        ctx = self._make_dev_ctx(AGY_DEV_DIAGNOSTIC="1")
        self.assertTrue(ctx.has_scope("DIAGNOSTIC"))

    def test_dev_context_denies_write(self):
        ctx = self._make_dev_ctx()
        self.assertFalse(ctx.has_scope("WRITE"))

    def test_dev_context_denies_critical(self):
        ctx = self._make_dev_ctx()
        self.assertFalse(ctx.has_scope("CRITICAL"))

    def test_troubleshoot_engine_requires_diagnostic_scope(self):
        """TroubleshootEngine must reject contexts that lack DIAGNOSTIC scope."""
        from engine.auth_provider import UserContext as FrozenUserContext
        ctx_no_diag = FrozenUserContext(
            username="readonly-user",
            role="viewer",
            authorized_scopes=frozenset({"READ_ONLY"}),
        )
        from engine.troubleshoot.engine import TroubleshootEngine
        with self.assertRaises(PermissionError):
            TroubleshootEngine(ctx_no_diag)

    def test_troubleshoot_engine_accepts_diagnostic_scope(self):
        from engine.auth_provider import UserContext as FrozenUserContext
        ctx = FrozenUserContext(
            username="noc",
            role="noc",
            authorized_scopes=frozenset({"READ_ONLY", "DIAGNOSTIC"}),
        )
        from engine.troubleshoot.engine import TroubleshootEngine
        engine = TroubleshootEngine(ctx)
        self.assertIsNotNone(engine)

    def test_troubleshoot_engine_rejects_non_context(self):
        from engine.troubleshoot.engine import TroubleshootEngine
        with self.assertRaises(TypeError):
            TroubleshootEngine("admin-username")  # raw string rejected


# ===========================================================================
# C. Path safety / traversal tests  (P0-3)
# ===========================================================================

class TestSafeJoin(unittest.TestCase):
    """safe_join must block traversal and symlink attacks."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.base), ignore_errors=True)

    def test_symlink_inside_base_rejected_on_all_platforms(self):
        target = self.base / "target_dir"
        target.mkdir()
        link = self.base / "linked_dir"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation requires an enabled privilege")
            raise
        with self.assertRaises(PathTraversalError):
            safe_join(self.base, "linked_dir", "file.txt")

    def test_valid_path_allowed(self):
        result = safe_join(self.base, "incidents", "INC-001", "device.txt")
        self.assertTrue(str(result).startswith(str(self.base.resolve())))

    def test_dotdot_blocked(self):
        with self.assertRaises(PathTraversalError):
            safe_join(self.base, "..", "etc", "passwd")

    def test_absolute_path_blocked(self):
        with self.assertRaises(PathTraversalError):
            safe_join(self.base, "/etc/passwd")

    def test_null_byte_in_segment(self):
        with self.assertRaises(Exception):
            # Path() itself should raise, or safe_join should block
            safe_join(self.base, "file\x00evil")

    @unittest.skipUnless(_IS_WINDOWS, "Windows Junction test — Windows 10/11 only")
    def test_windows_junction_reparse_point_blocked(self):
        """Reparse point (Junction) test: creating a junction inside base pointing
        outside base must be detected and blocked by safe_join.
        This test uses real Windows mklink /j and does not require admin privileges.
        """
        import subprocess
        target_dir = Path(tempfile.mkdtemp())
        junction_dir = self.base / "junction_link"
        try:
            res = subprocess.run(
                ["cmd", "/c", "mklink", "/j", str(junction_dir), str(target_dir)],
                capture_output=True, text=True
            )
            if res.returncode != 0:
                self.skipTest(f"Failed to create junction: {res.stderr}")
            with self.assertRaises(PathTraversalError) as cm:
                safe_join(self.base, "junction_link", "target_file.txt")
            self.assertIn("reparse point", str(cm.exception).lower())
        finally:
            shutil.rmtree(str(target_dir), ignore_errors=True)


class TestStoreRawOutputPathSafety(unittest.TestCase):
    """store_raw_output must reject traversal in incident_id or device_id."""

    def test_incident_id_traversal_rejected(self):
        with self.assertRaises(PathTraversalError):
            store_raw_output("../evil", "device1", "data")

    def test_device_id_traversal_rejected(self):
        with self.assertRaises(PathTraversalError):
            store_raw_output("INC-001", "../etc/passwd", "data")

    def test_null_byte_in_incident_id(self):
        with self.assertRaises(PathTraversalError):
            store_raw_output("INC\x00evil", "device1", "data")


# ===========================================================================
# D. Encryption / DPAPI tests  (P0-3)
# ===========================================================================

@unittest.skipUnless(_HAS_CRYPTOGRAPHY, "cryptography package not installed")
class TestAESGCMEncryption(unittest.TestCase):
    """AES-256-GCM must encrypt, authenticate, and detect tampering."""

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"sensitive diagnostic output"
        ciphertext, nonce, key = _encrypt_evidence(plaintext)
        result = _decrypt_evidence(ciphertext, nonce, key)
        self.assertEqual(result, plaintext)

    def test_tampered_ciphertext_detected(self):
        plaintext = b"original evidence"
        ciphertext, nonce, key = _encrypt_evidence(plaintext)
        # Flip one byte in ciphertext
        tampered = bytearray(ciphertext)
        tampered[5] ^= 0xFF
        with self.assertRaises(EvidenceIntegrityError):
            _decrypt_evidence(bytes(tampered), nonce, key)

    def test_wrong_key_detected(self):
        plaintext = b"evidence"
        ciphertext, nonce, key = _encrypt_evidence(plaintext)
        wrong_key = secrets.token_bytes(32)
        with self.assertRaises(EvidenceIntegrityError):
            _decrypt_evidence(ciphertext, nonce, wrong_key)

    def test_unique_nonces(self):
        """Each encryption must use a unique nonce."""
        _, nonce1, _ = _encrypt_evidence(b"a")
        _, nonce2, _ = _encrypt_evidence(b"a")
        self.assertNotEqual(nonce1, nonce2)

    def test_unique_keys(self):
        """Each encryption must generate a unique key."""
        _, _, key1 = _encrypt_evidence(b"a")
        _, _, key2 = _encrypt_evidence(b"a")
        self.assertNotEqual(key1, key2)


class TestDPAPIStub(unittest.TestCase):
    """DPAPI protect/unprotect must be symmetric (real or stubbed)."""

    def test_protect_unprotect_roundtrip(self):
        from engine.troubleshoot._utils import _dpapi_protect, _dpapi_unprotect
        secret = b"my-aes-key-" + secrets.token_bytes(32)
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            protected = _dpapi_protect(secret)
            recovered = _dpapi_unprotect(protected)
        self.assertNotEqual(protected, secret)  # must not be plaintext
        self.assertEqual(recovered, secret)

    @unittest.skipUnless(not _IS_WINDOWS, "Non-Windows stub test")
    def test_non_windows_stub_labelled(self):
        from engine.troubleshoot._utils import _dpapi_protect
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            result = _dpapi_protect(b"key")
        self.assertTrue(result.startswith(b"DEV_INSECURE_PLAINTEXT_KEY:"))


# ===========================================================================
# E. Atomic file creation
# ===========================================================================

class TestAtomicCreate(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_creates_file(self):
        target = self.tmpdir / "evidence.bin"
        _atomic_create(target, b"hello")
        self.assertTrue(target.exists())
        self.assertEqual(target.read_bytes(), b"hello")

    def test_fails_if_file_exists(self):
        target = self.tmpdir / "existing.bin"
        target.write_bytes(b"original")
        with self.assertRaises(EvidenceProtectionError):
            _atomic_create(target, b"overwrite attempt")
        # Original must be unchanged
        self.assertEqual(target.read_bytes(), b"original")


# ===========================================================================
# F. SHA-256 integrity
# ===========================================================================

class TestSHA256Helpers(unittest.TestCase):
    def test_calculate_sha256(self):
        expected = hashlib.sha256(b"hello world").hexdigest()
        self.assertEqual(calculate_sha256("hello world"), expected)

    def test_verify_sha256_matches(self):
        h = calculate_sha256("test data")
        self.assertTrue(verify_sha256("test data", h))

    def test_verify_sha256_mismatch(self):
        self.assertFalse(verify_sha256("test data", "deadbeef" * 8))


# ===========================================================================
# G. Retention cleanup
# ===========================================================================

class TestRetentionCleanup(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_cleanup_deletes_old_files(self):
        import time
        old_file = self.tmpdir / "old.txt"
        old_file.write_bytes(b"old evidence")
        # Backdate mtime by 100 days
        old_time = time.time() - (100 * 86400)
        os.utime(str(old_file), (old_time, old_time))

        # Patch ARTIFACT_ROOT to our temp dir
        with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
            deleted = cleanup_old_evidence(max_age_days=90)
        self.assertEqual(deleted, 1)
        self.assertFalse(old_file.exists())

    def test_cleanup_preserves_recent_files(self):
        recent = self.tmpdir / "recent.txt"
        recent.write_bytes(b"fresh evidence")
        with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
            deleted = cleanup_old_evidence(max_age_days=90)
        self.assertEqual(deleted, 0)
        self.assertTrue(recent.exists())


# ===========================================================================
# H. ACL enforcement (Windows-specific integration tests)
# ===========================================================================

@unittest.skipUnless(_IS_WINDOWS, "Windows ACL tests — Windows 10/11 only")
class TestWindowsACLIntegration(unittest.TestCase):
    """Real Windows ACL integration tests (not mocked)."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_acl_applied_and_verified(self):
        """Apply ACL to a real file and verify via icacls output — Windows Integration."""
        import subprocess
        from engine.troubleshoot._utils import _apply_and_verify_windows_acl
        target = self.tmpdir / "protected.txt"
        _atomic_create(target, b"test content")
        # Must not raise
        _apply_and_verify_windows_acl(target)
        # Verify via real icacls call that the ACL is restrictive
        result = subprocess.run(
            ["icacls", str(target)],
            capture_output=True, text=True, timeout=10
        )
        acl_output = result.stdout + result.stderr
        # Everyone must NOT appear in the ACL (was removed)
        self.assertNotIn("Everyone", acl_output,
            msg=f"'Everyone' should have been removed from ACL.\nicacls output:\n{acl_output}")
        # The file must still exist and be accessible
        self.assertTrue(target.exists())

    def test_acl_verification_catches_broad_access(self):
        """Verify ACL parser rejects output containing broad principals.

        Since _apply_and_verify_windows_acl *removes* Everyone before verifying,
        we mock the final icacls read to simulate a failed-removal scenario where
        Everyone still appears. This tests the verification parser logic.
        (Windows Integration test — real icacls calls for setup commands.)
        """
        import subprocess
        from unittest import mock as _mock
        from engine.troubleshoot._utils import _apply_and_verify_windows_acl, EvidenceProtectionError
        target = self.tmpdir / "broad.txt"
        _atomic_create(target, b"test")

        # Fake the final verify call to return Everyone in the output.
        fake_verify = type("R", (), {"stdout": f"{target} Everyone:(R)\n", "stderr": "", "returncode": 0})()

        orig_run = subprocess.run
        call_count = {"n": 0}

        def selective_mock(cmd, **kwargs):
            call_count["n"] += 1
            # The verify call is `icacls <path>` with no other flags (len == 2)
            if isinstance(cmd, list) and cmd[:1] == ["icacls"] and len(cmd) == 2:
                return fake_verify
            return orig_run(cmd, **kwargs)

        with _mock.patch("engine.troubleshoot._utils.subprocess.run", side_effect=selective_mock):
            with self.assertRaises(EvidenceProtectionError) as cm:
                _apply_and_verify_windows_acl(target)
        self.assertIn("Everyone", str(cm.exception))


@unittest.skipIf(_IS_WINDOWS, "Non-Windows ACL fallback tests")
class TestNonWindowsACLFallback(unittest.TestCase):
    """On non-Windows, _apply_and_verify_windows_acl uses chmod(600) as a best-effort fallback."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_chmod_fallback_applied(self):
        from engine.troubleshoot._utils import _apply_and_verify_windows_acl
        target = self.tmpdir / "file.txt"
        _atomic_create(target, b"data")
        _apply_and_verify_windows_acl(target)
        mode = stat.S_IMODE(os.stat(str(target)).st_mode)
        self.assertEqual(mode & 0o777, 0o600)


# ===========================================================================
# I. Store/read roundtrip
# ===========================================================================

@unittest.skipUnless(_HAS_CRYPTOGRAPHY, "cryptography required for roundtrip test")
class TestPlaintextEvidenceRestriction(unittest.TestCase):
    def test_plaintext_storage_requires_dev_mode(self):
        with mock.patch.dict(os.environ, {"AGY_ENV": "production"}):
            with self.assertRaises(EvidenceProtectionError):
                store_raw_output("incident-test", "device-test", "sensitive", encrypt=False)

    def test_plaintext_evidence_read_requires_dev_mode(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "raw.txt"
            path.write_text("# UNENCRYPTED EVIDENCE — development environment only\n# SHA256: test\n\nsensitive\n")
            with mock.patch.dict(os.environ, {"AGY_ENV": "production"}):
                with self.assertRaises(EvidenceProtectionError):
                    read_raw_output(path, "")

    def test_evidence_read_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "raw.txt"
            target.write_text("sensitive")
            link = Path(d) / "link.txt"
            try:
                link.symlink_to(target)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symlink creation requires an enabled privilege")
                raise
            with self.assertRaises(EvidenceProtectionError):
                read_raw_output(link, "")


class TestStoreReadRoundtrip(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_store_and_read_encrypted(self):
        raw = "interface eth0 is UP; received 1023 packets"
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
                file_path, sha256 = store_raw_output("INC-TEST-001", "device-01", raw, encrypt=True)
        self.assertTrue(file_path.exists())
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
                recovered = read_raw_output(file_path, sha256)
        self.assertEqual(recovered, raw)

    def test_envelope_hash_is_checked_even_without_expected_hash(self):
        import json
        import tempfile
        from pathlib import Path
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}), mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", Path(tempfile.mkdtemp())):
            file_path, digest = store_raw_output("INC-HASH", "DEV-HASH", "evidence")
            envelope = json.loads(file_path.read_text())
            envelope["sha256_original"] = "0" * 64
            file_path.write_text(json.dumps(envelope))
            with self.assertRaises(EvidenceIntegrityError):
                read_raw_output(file_path, "")

    def test_tampered_file_raises_integrity_error(self):
        raw = "some diagnostic output"
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
                file_path, sha256 = store_raw_output("INC-TAMPER", "device-02", raw, encrypt=True)
        # Corrupt the ciphertext field in the envelope
        envelope = json.loads(file_path.read_text(encoding="utf-8"))
        import base64
        ct = bytearray(base64.b64decode(envelope["ciphertext"]))
        ct[10] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        file_path.write_text(json.dumps(envelope), encoding="utf-8")
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
                with self.assertRaises(EvidenceIntegrityError):
                    read_raw_output(file_path, sha256)


    def test_missing_cryptography_fails_closed_no_plaintext(self):
        """Simulate missing cryptography library; store_raw_output(encrypt=True)
        MUST raise EvidenceProtectionError and write NO plaintext file.
        """
        with mock.patch("engine.troubleshoot._utils._HAS_CRYPTOGRAPHY", False):
            with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
                with self.assertRaises(EvidenceProtectionError) as cm:
                    store_raw_output("INC-NOCRYPTO", "dev01", "super-secret-diagnostic-data", encrypt=True)
                self.assertIn("AES-256-GCM", str(cm.exception))
                # Verify no files were created in self.tmpdir
                created_files = list(self.tmpdir.rglob("*"))
                # Filter only files
                created_files = [f for f in created_files if f.is_file()]
                self.assertEqual(len(created_files), 0, f"No files should be written on failure, found: {created_files}")

    def test_encrypt_true_never_writes_plaintext_or_dot_enc_plaintext(self):
        """Verify that store_raw_output with encrypt=True never writes unencrypted plaintext."""
        with mock.patch.dict(os.environ, {"AGY_ENV": "dev"}):
            with mock.patch("engine.troubleshoot._utils.ARTIFACT_ROOT", self.tmpdir):
                file_path, sha256 = store_raw_output("INC-CHECK-ENC", "dev01", "my-raw-diagnostics", encrypt=True)
            self.assertTrue(str(file_path).endswith(".enc"))
            raw_bytes = file_path.read_bytes()
            # Plaintext shouldn't appear in the file
            self.assertNotIn(b"my-raw-diagnostics", raw_bytes)
            # Must be JSON envelope containing base64 ciphertext
            envelope = json.loads(raw_bytes.decode("utf-8"))
            self.assertIn("ciphertext", envelope)
            self.assertIn("nonce", envelope)


if __name__ == "__main__":
    unittest.main()
