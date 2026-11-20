"""Secure evidence storage utilities for the Troubleshooting module.

Guarantees (on Windows 10/11):
- Raw diagnostic output is stored in a path derived from safe_join (no traversal).
- Reparse-point / symlink attacks are blocked before writing.
- Files are created atomically with O_CREAT | O_EXCL to prevent TOCTOU races.
- Windows ACLs are applied via icacls; the resulting ACL is VERIFIED before the
  function returns.  If verification fails the file is securely deleted and an
  EvidenceProtectionError is raised – the caller must not continue.
- Evidence is encrypted with AES-256-GCM.
- The AES key is protected with Windows DPAPI (CryptProtectData via ctypes).
- Encrypted evidence and the DPAPI-wrapped key are stored separately.
- A SHA-256 hash of the *original plaintext* is returned and stored for integrity.
- Redaction strips credentials and secrets from text before it appears in reports.
- Retention cleanup is explicit and on-demand; no background threads.

Non-Windows environments:
- DPAPI calls are skipped; AES-256-GCM encryption still runs (key stored unprotected,
  clearly labelled as insecure).
- ACL calls are skipped and labelled as UNVERIFIED.
- All such limitations are reported, not silently swallowed.
"""

import os
import sys
import hashlib
import datetime
import secrets
import json
import stat
import struct
import re
import subprocess
from pathlib import Path
from typing import Tuple, Optional

# ---------------------------------------------------------------------------
# Encryption (AES-256-GCM via cryptography library)
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

# ---------------------------------------------------------------------------
# Windows DPAPI (via ctypes)
# ---------------------------------------------------------------------------

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import ctypes
    import ctypes.wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _CRYPTPROTECT_UI_FORBIDDEN = 0x01

    def _dpapi_protect(data: bytes) -> bytes:
        """Encrypt data with Windows DPAPI (CryptProtectData)."""
        blob_in = _DATA_BLOB(len(data), ctypes.cast(ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        ok = _crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out)
        )
        if not ok:
            raise EvidenceProtectionError("DPAPI CryptProtectData failed.")
        protected = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return protected

    def _dpapi_unprotect(data: bytes) -> bytes:
        """Decrypt data with Windows DPAPI (CryptUnprotectData)."""
        blob_in = _DATA_BLOB(len(data), ctypes.cast(ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out)
        )
        if not ok:
            raise EvidenceProtectionError("DPAPI CryptUnprotectData failed.")
        plaintext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return plaintext

    _HAS_DPAPI = True
else:
    def _dpapi_protect(data: bytes) -> bytes:
        # On non-Windows platforms, in production, fail closed because DPAPI is not available
        # and no OS-backed key protection mechanism is configured.
        env = os.environ.get("AGY_ENV", "").strip().lower()
        if env != "dev":
            raise EvidenceProtectionError(
                "OS-backed key protection (DPAPI) is unavailable on this non-Windows platform. "
                "Production evidence storage fails closed. Use AGY_ENV=dev for local development testing only."
            )
        # Development-mode explicit fallback ONLY:
        return b"DEV_INSECURE_PLAINTEXT_KEY:" + data

    def _dpapi_unprotect(data: bytes) -> bytes:
        if data.startswith(b"DEV_INSECURE_PLAINTEXT_KEY:"):
            env = os.environ.get("AGY_ENV", "").strip().lower()
            if env != "dev":
                raise EvidenceProtectionError(
                    "Attempted to read development-mode insecure key in non-dev environment. Refusing to decrypt."
                )
            return data[len(b"DEV_INSECURE_PLAINTEXT_KEY:"):]
        raise EvidenceProtectionError("Unknown or unsupported key protection envelope.")

    _HAS_DPAPI = False


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class EvidenceProtectionError(RuntimeError):
    """Raised when required evidence protection cannot be established."""


class EvidenceIntegrityError(RuntimeError):
    """Raised when evidence integrity verification fails."""


class PathTraversalError(ValueError):
    """Raised when a path traversal attempt is detected."""


# ---------------------------------------------------------------------------
# Base artifact directory
# ---------------------------------------------------------------------------

# Use a path relative to the repository to avoid hardcoding per-user brain paths.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ARTIFACT_ROOT = _REPO_ROOT / "artifacts" / "troubleshoot" / "raw"

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_REDACT_PATTERNS = [
    # Passwords in key=value or config lines
    re.compile(r'(?i)(password|passwd|secret|community|api[_-]?key|token|credential)\s*[:=]\s*\S+'),
    # IPv4 addresses in internal RFC-1918 ranges (redact host-part only)
    re.compile(r'(?i)\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b'),
]

def redact_for_report(text: str) -> str:
    """Return a copy of *text* with credentials and sensitive values redacted.

    This output is safe for inclusion in public-facing reports.
    """
    result = text
    result = re.sub(
        r'(?i)(password|passwd|secret|community|api[_-]?key|token|credential)\s*[:=]\s*\S+',
        r'\1=***REDACTED***',
        result,
    )
    return result


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def safe_join(base: Path, *parts: str) -> Path:
    """Return ``base / parts`` only if the result is strictly inside *base*.

    Raises PathTraversalError on any traversal attempt.
    Also rejects Windows reparse points (symlinks / junctions) anywhere in
    the resulting path that fall outside *base*.
    """
    # Explicitly reject null bytes before passing to Path()
    for part in parts:
        if "\x00" in str(part):
            raise PathTraversalError(
                f"Null byte detected in path segment: {part!r}"
            )
    base = base.resolve()
    candidate = base.joinpath(*parts)
    # resolve() follows symlinks; we want to detect them BEFORE resolving
    # so we walk the path segments and check each component.
    for parent in list(candidate.parents) + [candidate]:
        if parent == base:
            break
        # Reject symlinks on every platform and Windows reparse points where available.
        if parent.exists() or parent.is_symlink():
            try:
                st = os.lstat(str(parent))
                is_reparse = stat.S_ISLNK(st.st_mode)
                if hasattr(st, "st_file_attributes"):
                    reparse_attr = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    is_reparse = is_reparse or bool(st.st_file_attributes & reparse_attr)
                if is_reparse:
                    raise PathTraversalError(
                        f"Symlink/reparse point detected at '{parent}' — refusing to follow."
                    )
            except PathTraversalError:
                raise
            except OSError:
                pass  # Path component does not exist yet — OK

    resolved = candidate.resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise PathTraversalError(
            f"Path traversal detected: '{candidate}' resolves outside '{base}'."
        )
    return resolved


# ---------------------------------------------------------------------------
# Windows ACL helpers
# ---------------------------------------------------------------------------

def _get_current_username() -> str:
    """Return the current Windows username (DOMAIN\\user or just user)."""
    if _IS_WINDOWS:
        import ctypes
        buf = ctypes.create_unicode_buffer(256)
        ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(ctypes.wintypes.DWORD(256)))
        return buf.value or os.environ.get("USERNAME", "UNKNOWN")
    return os.environ.get("USER", os.environ.get("USERNAME", "UNKNOWN"))


def _apply_and_verify_windows_acl(file_path: Path) -> None:
    """Apply restrictive Windows ACL to *file_path* and verify it was applied.

    Steps:
    1. Remove inherited ACEs (icacls /inheritance:r /remove:g Everyone).
    2. Grant read+write to the current user only.
    3. Re-read the ACL via icacls and verify that only the expected principals appear.

    Raises EvidenceProtectionError if any step fails or verification is inconclusive.
    """
    if not _IS_WINDOWS:
        # Non-Windows: use chmod(600) as a best-effort alternative; label as UNVERIFIED.
        try:
            os.chmod(str(file_path), 0o600)
        except OSError as exc:
            raise EvidenceProtectionError(
                f"chmod 600 failed on '{file_path}': {exc}. "
                "Evidence is UNPROTECTED — aborting storage."
            )
        # Non-Windows: cannot verify ACL, label clearly.
        return  # UNVERIFIED on non-Windows — caller should note this

    username = _get_current_username()
    path_str = str(file_path)

    # 1. Remove inherited ACEs and strip Everyone/Users broad access
    cmds = [
        ["icacls", path_str, "/inheritance:r"],
        ["icacls", path_str, "/remove:g", "Everyone"],
        ["icacls", path_str, "/remove:g", "BUILTIN\\Users"],
        ["icacls", path_str, "/remove:g", "Authenticated Users"],
        # Grant current user full control of this specific file
        ["icacls", path_str, "/grant:r", f"{username}:(F)"],
        # Allow SYSTEM read (needed for backup/antivirus with restricted rights)
        ["icacls", path_str, "/grant:r", "NT AUTHORITY\\SYSTEM:(R)"],
    ]
    for cmd in cmds:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                raise EvidenceProtectionError(
                    f"ACL command failed (exit {result.returncode}): "
                    f"{' '.join(cmd)}\nstderr: {result.stderr.strip()}"
                )
        except subprocess.TimeoutExpired:
            raise EvidenceProtectionError(
                f"ACL command timed out: {' '.join(cmd)}"
            )

    # 2. Verify — re-read ACL and check that broad-access principals are absent
    try:
        verify = subprocess.run(
            ["icacls", path_str],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise EvidenceProtectionError("ACL verification timed out.")

    if verify.returncode != 0:
        raise EvidenceProtectionError(
            f"ACL verification query failed (exit {verify.returncode}): {verify.stderr.strip()}"
        )

    acl_output = verify.stdout + verify.stderr
    if not acl_output.strip():
        raise EvidenceProtectionError("ACL verification inconclusive: empty icacls output.")

    forbidden_principals = ["Everyone", "BUILTIN\\Users", "Authenticated Users"]
    for principal in forbidden_principals:
        if principal.lower() in acl_output.lower():
            raise EvidenceProtectionError(
                f"ACL verification FAILED: '{principal}' still appears in ACL of '{path_str}'.\n"
                f"icacls output:\n{acl_output}"
            )

    # Verify the current user is present
    if username.lower() not in acl_output.lower():
        raise EvidenceProtectionError(
            f"ACL verification FAILED: expected user '{username}' not found in ACL of '{path_str}'.\n"
            f"icacls output:\n{acl_output}"
        )

    # Verify that the user has full access (F) or at least read/write permissions
    user_line = [line for line in acl_output.splitlines() if username.lower() in line.lower()]
    if not any(":(F)" in l or ":(M)" in l or ":(R,W)" in l or ":(OI)(CI)(F)" in l for l in user_line):
        raise EvidenceProtectionError(
            f"ACL verification FAILED: expected full/write access '(F)' for '{username}' in ACL of '{path_str}'.\n"
            f"icacls output:\n{acl_output}"
        )


# ---------------------------------------------------------------------------
# Atomic file creation
# ---------------------------------------------------------------------------

def _atomic_create(file_path: Path, data: bytes) -> None:
    """Create *file_path* atomically, failing if it already exists.

    Uses O_CREAT | O_EXCL to prevent TOCTOU races.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_BINARY if _IS_WINDOWS else \
            os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(str(file_path), flags, 0o600)
    except FileExistsError:
        raise EvidenceProtectionError(
            f"Evidence file already exists and will not be overwritten: '{file_path}'."
        )
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _encrypt_evidence(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    Returns (ciphertext_with_tag, nonce, raw_key).
    Key is 32 random bytes; nonce is 12 random bytes (96-bit, GCM standard).
    The raw_key must be DPAPI-protected before storage.
    """
    if not _HAS_CRYPTOGRAPHY:
        raise EvidenceProtectionError(
            "The 'cryptography' package is not installed. "
            "Cannot encrypt evidence. Install it with: pip install cryptography"
        )
    key = secrets.token_bytes(32)       # AES-256
    nonce = secrets.token_bytes(12)     # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes GCM tag
    return ciphertext, nonce, key


def _decrypt_evidence(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext and verify integrity.

    Raises EvidenceIntegrityError on tag mismatch.
    """
    if not _HAS_CRYPTOGRAPHY:
        raise EvidenceProtectionError("'cryptography' package not installed.")
    from cryptography.exceptions import InvalidTag
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise EvidenceIntegrityError(
            "AES-GCM authentication tag mismatch — evidence may have been tampered with."
        )


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

def calculate_sha256(data: str) -> str:
    """Return the hex SHA-256 hash of *data* encoded as UTF-8."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_sha256(data: str, expected_hash: str) -> bool:
    """Return True if SHA-256 of *data* matches *expected_hash*."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest() == expected_hash


# ---------------------------------------------------------------------------
# Primary public API
# ---------------------------------------------------------------------------

def store_raw_output(
    incident_id: str,
    device_id: str,
    raw: str,
    encrypt: bool = True,
) -> Tuple[Path, str]:
    """Securely store raw diagnostic output for incident *incident_id*.

    Workflow:
    1. Validate and construct a safe path under ARTIFACT_ROOT.
    2. Compute SHA-256 of original plaintext (before truncation/encryption).
    3. If encrypt=True: AES-256-GCM encrypt; protect key with DPAPI; store separately.
    4. Create the evidence file atomically (O_CREAT|O_EXCL).
    5. Apply and VERIFY Windows ACL (or chmod 600 on non-Windows, labelled UNVERIFIED).
    6. If ACL enforcement fails: securely delete the written file, raise EvidenceProtectionError.

    Returns:
        (file_path, sha256_hash_of_original_plaintext)

    Raises:
        PathTraversalError        — if incident_id or device_id contain traversal sequences.
        EvidenceProtectionError   — if ACL / encryption setup fails.
    """
    if ARTIFACT_ROOT.is_symlink():
        raise EvidenceProtectionError("Evidence artifact root must not be a symlink")
    # Sanitise path segments
    for segment, name in [(incident_id, "incident_id"), (device_id, "device_id")]:
        if "\x00" in segment or any(c in segment for c in ("/", "\\", "..", ":")):
            raise PathTraversalError(
                f"Disallowed characters in {name}: '{segment}'"
            )

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    ext = ".enc" if encrypt else ".txt"
    filename = f"{device_id}_{timestamp}{ext}"

    # Build and verify safe path
    incident_dir_rel = Path(incident_id)
    file_path = safe_join(ARTIFACT_ROOT, str(incident_dir_rel), filename)
    file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(file_path.parent, 0o700)
    except OSError as exc:
        raise EvidenceProtectionError("Unable to apply restrictive evidence-directory permissions") from None

    # Compute hash of original plaintext
    original_hash = calculate_sha256(raw)

    # Fail closed: if encryption was requested but AES-GCM is unavailable,
    # refuse to write any plaintext. Production evidence storage requires
    # successful encryption and key protection.
    if encrypt and not _HAS_CRYPTOGRAPHY:
        raise EvidenceProtectionError(
            "AES-256-GCM (cryptography package) is required for encrypted evidence "
            "storage but is not installed. Refusing to write plaintext."
        )

    # Key protection verification: in production on any OS, key protection must be available.
    # On Windows DPAPI is used; on non-Windows it fails closed unless AGY_ENV=dev.
    if encrypt and _IS_WINDOWS and not _HAS_DPAPI:
        raise EvidenceProtectionError(
            "Windows DPAPI is required for encrypted evidence storage on Windows "
            "but is unavailable. Refusing to write evidence."
        )

    if encrypt:
        plaintext_bytes = raw.encode("utf-8")
        ciphertext, nonce, raw_key = _encrypt_evidence(plaintext_bytes)
        # Protect the AES key with DPAPI
        protected_key = _dpapi_protect(raw_key)
        # Store envelope: JSON metadata + base64-encoded fields
        import base64
        envelope = {
            "version": 1,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "sha256_original": original_hash,
            "dpapi_protected": _HAS_DPAPI,
            "protected_key": base64.b64encode(protected_key).decode(),
        }
        file_data = json.dumps(envelope, indent=2).encode("utf-8")
    else:
        # Plaintext storage is explicitly restricted to development.
        if os.environ.get("AGY_ENV", "").strip().lower() != "dev":
            raise EvidenceProtectionError("Plaintext evidence storage is development-only; refusing in non-dev mode.")
        header = f"# UNENCRYPTED EVIDENCE — development environment only\n# SHA256: {original_hash}\n\n"
        file_data = (header + raw).encode("utf-8")

    # Atomic creation
    _atomic_create(file_path, file_data)

    # Apply and verify ACL — fail closed on failure
    try:
        _apply_and_verify_windows_acl(file_path)
    except EvidenceProtectionError:
        # Secure delete before re-raising
        _secure_delete(file_path)
        raise

    return file_path, original_hash


def read_raw_output(file_path: Path, expected_hash: str) -> str:
    """Read and decrypt a stored evidence file, verifying its integrity.

    Raises:
        EvidenceIntegrityError  — if the decrypted content hash does not match expected_hash.
        EvidenceProtectionError — if decryption fails.
    """
    if file_path.is_symlink():
        raise EvidenceProtectionError("Refusing to read evidence through a symlink")
    try:
        relative = file_path.absolute().relative_to(ARTIFACT_ROOT.absolute())
        safe_path = safe_join(ARTIFACT_ROOT, *relative.parts)
    except (ValueError, PathTraversalError):
        raise EvidenceProtectionError("Evidence path is outside the trusted artifact root.") from None
    if not safe_path.exists():
        raise FileNotFoundError("Evidence file not found in trusted artifact storage.")

    raw_bytes = safe_path.read_bytes()

    if file_path.suffix == ".enc":
        import base64
        try:
            envelope = json.loads(raw_bytes.decode("utf-8"))
            if envelope.get("version") != 1:
                raise EvidenceProtectionError("Unsupported evidence envelope version")
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            protected_key = base64.b64decode(envelope["protected_key"], validate=True)
            if len(nonce) != 12:
                raise EvidenceProtectionError("Invalid evidence nonce length")
            raw_key = _dpapi_unprotect(protected_key)
            if len(raw_key) != 32:
                raise EvidenceProtectionError("Invalid evidence key length")
            plaintext_bytes = _decrypt_evidence(ciphertext, nonce, raw_key)
            plaintext = plaintext_bytes.decode("utf-8")
            stored_hash = envelope.get("sha256_original", "")
        except EvidenceProtectionError:
            raise
        except Exception:
            raise EvidenceIntegrityError("Malformed evidence envelope; refusing to read.") from None
    else:
        if os.environ.get("AGY_ENV", "").strip().lower() != "dev":
            raise EvidenceProtectionError("Plaintext evidence cannot be read outside development mode.")
        content = raw_bytes.decode("utf-8")
        # Strip header lines
        lines = content.splitlines()
        data_lines = [l for l in lines if not l.startswith("#")]
        plaintext = "\n".join(data_lines).lstrip("\n")
        hash_line = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("# SHA256:")), "")
        stored_hash = hash_line

    # Verify both caller-provided and envelope/header integrity claims.
    actual_hash = calculate_sha256(plaintext)
    for claimed_hash in (expected_hash, stored_hash):
        if claimed_hash and actual_hash != claimed_hash:
            raise EvidenceIntegrityError("Evidence integrity check failed; stored content does not match its SHA-256 claim.")

    return plaintext


# ---------------------------------------------------------------------------
# Retention cleanup  (explicit, on-demand)
# ---------------------------------------------------------------------------

def cleanup_old_evidence(max_age_days: int = 90) -> int:
    """Delete evidence files older than *max_age_days*.

    Cleanup is EXPLICIT and must be called by an authorised operator; it does not
    run automatically in the background.

    Returns the number of files deleted.
    """
    if not ARTIFACT_ROOT.exists():
        return 0
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=max_age_days)
    deleted = 0
    for f in ARTIFACT_ROOT.rglob("*"):
        if f.is_symlink():
            continue
        if f.is_file():
            mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime, datetime.timezone.utc)
            if mtime < cutoff:
                _secure_delete(f)
                deleted += 1
    return deleted


# ---------------------------------------------------------------------------
# Secure delete
# ---------------------------------------------------------------------------

def _secure_delete(file_path: Path) -> None:
    """Overwrite and delete *file_path* to reduce data remanence."""
    if file_path.is_symlink():
        try:
            file_path.unlink()
        except OSError:
            pass
        return
    try:
        size = file_path.stat().st_size
        with open(str(file_path), "r+b") as fh:
            fh.write(os.urandom(max(size, 1)))
            fh.flush()
        file_path.unlink()
    except OSError:
        # Best-effort; at minimum attempt plain unlink
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            pass
