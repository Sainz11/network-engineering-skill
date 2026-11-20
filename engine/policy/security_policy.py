import re
import json
import hashlib
import datetime
from dataclasses import dataclass
from typing import Tuple, Callable, Optional, FrozenSet
from .types import (
    OperationClassification,
    OperationRequest,
    ExecutionMode,
    UserContext,
    is_production_identity,
)

# Exact and prefix command classification dictionaries
READ_ONLY_PATTERNS = [
    re.compile(r'(?i)^\s*(show|display|get).*'),
    # Exact RouterOS read-only command families after path normalization.
    # Keep this list explicit; arbitrary unknown CLI forms remain WRITE.
    re.compile(r'(?i)^\s*(?:system\s+(?:resource|health)|interface|ip\s+(?:address|route)|ppp\s+active)\s+print(?:\s|$).*'),
    re.compile(r'(?i)^\s*(uptime|version|hostname|uname).*'),
]

DIAGNOSTIC_PATTERNS = [
    re.compile(r'(?i)^\s*(ping|traceroute|mtr|tool\s+traceroute|tool\s+ping).*'),
    re.compile(r'(?i)^\s*(test|debug|monitor|tool\s+torch|tool\s+sniffer).*'),
]

WRITE_PATTERNS = [
    re.compile(r'(?i)^\s*(configure|conf\s+t|set|add|ip\s+address\s+add|interface\s+set|ppp\s+secret\s+add).*'),
    re.compile(r'(?i)^\s*(delete|remove|interface\s+disable|interface\s+enable).*'),
]

CRITICAL_PATTERNS = [
    re.compile(r'(?i)^\s*(reload|reboot|\/system\s+reboot|shutdown|erase|format|factory-reset|\/system\s+reset-configuration).*'),
    re.compile(r'(?i)^\s*(firmware\s+upgrade|\/system\s+routerboard\s+upgrade|install\s+os).*'),
]

@dataclass(frozen=True)
class ApprovalVerificationResult:
    """Claims returned only after a trusted external verifier validates a token."""
    approved: bool
    requester: str
    target_id: str
    classification: str
    request_id: str
    diff_hash: str
    approver_ids: FrozenSet[str]
    expires_at: str


class SecurityPolicyEngine:
    """Fail-closed policy validator.

    Approval validation must be supplied by a trusted external approval service.
    The legacy ``approved`` boolean is never treated as authorization evidence.
    """
    def __init__(self, approval_verifier: Optional[Callable[..., ApprovalVerificationResult]] = None):
        self.approval_verifier = approval_verifier

    @staticmethod
    def _canonical_diff_hash(request: OperationRequest) -> str:
        diff = {
            "action": request.action,
            "command": request.command,
            "parameters": request.parameters,
            "classification": request.classification.value,
        }
        payload = json.dumps(diff, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _normalize_command(command: str) -> str:
        """Normalize common CLI path/prefix and whitespace variants for policy checks."""
        value = str(command or "").strip().casefold()
        value = re.sub(r"\s+", " ", value)
        # RouterOS path-qualified commands (for example /system reset-configuration)
        # are semantically identical to their unqualified form.
        value = re.sub(r"^/+(?=[a-z])", "", value)
        # RouterOS command paths use slash-separated menu components.
        value = value.replace("/", " ")
        value = re.sub(r"\s+", " ", value).strip()
        return value

    @classmethod
    def _known_critical_command(cls, command: str) -> bool:
        normalized = cls._normalize_command(command)
        known_patterns = (
            r"^(?:(?:system|routerboard) )?(?:reset(?:-configuration)?|factory[- ]reset|reboot|reload|shutdown|erase|format|delete|remove)(?:\s|$)",
            r"^write erase(?:\s|$)",
            r"^(?:firmware|software) (?:upgrade|install)(?:\s|$)",
            r"^(?:install|upgrade) (?:os|firmware|software)(?:\s|$)",
            r"^routerboard upgrade(?:\s|$)",
            r"^request platform software package install(?:\s|$)",
            r"^request system zeroize(?:\s|$)",
            r"^copy .* (?:startup-config|running-config)(?:\s|$)",
        )
        return any(re.match(pattern, normalized) for pattern in known_patterns)

    @classmethod
    def _contains_destructive_intent(cls, command: str) -> bool:
        normalized = cls._normalize_command(command)
        tokens = re.findall(r"[a-z0-9_-]+", normalized)
        dangerous = {
            "reset", "reset-configuration", "factory-reset", "factory", "erase",
            "format", "delete", "remove", "reboot", "reload", "shutdown",
            "upgrade", "install", "firmware", "rollback", "restore", "wipe",
            "zeroize", "clear",
        }
        return any(token in dangerous or any(token.startswith(prefix) for prefix in ("reset-", "factory-", "wipe-")) for token in tokens)

    def classify_command(self, command: str) -> OperationClassification:
        cmd = self._normalize_command(command)
        # Destructive intent is checked before lower-risk patterns and independent
        # of vendor CLI path prefixes. This intentionally errs on the restrictive side.
        if self._known_critical_command(cmd) or self._contains_destructive_intent(cmd):
            return OperationClassification.CRITICAL
        for p in WRITE_PATTERNS:
            if p.match(cmd):
                return OperationClassification.WRITE
        for p in DIAGNOSTIC_PATTERNS:
            if p.match(cmd):
                return OperationClassification.DIAGNOSTIC
        for p in READ_ONLY_PATTERNS:
            if p.match(cmd):
                return OperationClassification.READ_ONLY
        # Unrecognized commands are not executable as read-only. They are
        # classified WRITE and still require explicit scope/approval.
        return OperationClassification.WRITE

    def validate_request(self, request: OperationRequest) -> Tuple[bool, str]:
        if not isinstance(request, OperationRequest):
            return False, "Operation request must use the canonical OperationRequest type."
        if not isinstance(request.classification, OperationClassification):
            return False, "Operation classification is invalid."
        if not isinstance(request.execution_mode, ExecutionMode):
            return False, "Operation execution mode is invalid."
        if not isinstance(request.action, str) or not request.action.strip():
            return False, "Operation action must be a non-empty string."
        if not isinstance(request.parameters, dict):
            return False, "Operation parameters must be a dictionary."
        try:
            json.dumps(request.parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False, "Operation parameters must be finite, JSON-compatible values."
        if request.command is not None and not isinstance(request.command, str):
            return False, "Operation command must be a string when supplied."
        # Reject shell metacharacters/control characters before classification.
        if request.command:
            if any(ch in request.command for ch in (";", "|", "&", ">", "<", "$", "`", "\n", "\r")):
                return False, "Command contains shell control characters or operators and is rejected."
            if not re.fullmatch(r"[A-Za-z0-9_./:=,+@% -]+", request.command.strip()):
                return False, "Command contains unsupported characters and is rejected."
            if self._contains_destructive_intent(request.command) and not self._known_critical_command(request.command):
                return False, "Unrecognized potentially destructive command form is denied pending explicit vendor-specific policy support."

        # Action names and parameterized command lists are also policy inputs;
        # they cannot bypass classification by leaving request.command empty.
        action_requirements = {
            "ping": OperationClassification.DIAGNOSTIC,
            "apply_config": OperationClassification.WRITE,
            "set_config": OperationClassification.WRITE,
            "backup_config": OperationClassification.READ_ONLY,
            "system_info": OperationClassification.READ_ONLY,
            "interfaces": OperationClassification.READ_ONLY,
        }
        required_by_action = action_requirements.get(str(request.action).lower())
        severity_order = {
            OperationClassification.READ_ONLY: 1,
            OperationClassification.DIAGNOSTIC: 2,
            OperationClassification.WRITE: 3,
            OperationClassification.CRITICAL: 4,
        }
        if required_by_action and severity_order[required_by_action] > severity_order[request.classification]:
            return False, f"Action '{request.action}' requires {required_by_action.value} classification."

        command_list = request.parameters.get("commands") if isinstance(request.parameters, dict) else None
        if command_list is not None:
            if not isinstance(command_list, (list, tuple)) or not command_list or len(command_list) > 50:
                return False, "Configuration command list must contain 1..50 commands."
            for item in command_list:
                if not isinstance(item, str) or not item.strip():
                    return False, "Configuration command list contains an invalid command."
                if any(ch in item for ch in (";", "|", "&", ">", "<", "$", "`", "\n", "\r")) or not re.fullmatch(r"[A-Za-z0-9_./:=,+@% -]+", item.strip()):
                    return False, "Configuration command contains shell control characters or unsupported syntax."
                if self._contains_destructive_intent(item) and not self._known_critical_command(item):
                    return False, "Unrecognized potentially destructive configuration command is denied."
                detected = self.classify_command(item)
                if severity_order[detected] > severity_order[request.classification]:
                    return False, f"Configuration command requires {detected.value} classification."

        if request.action == "ping":
            target = request.parameters.get("target", "8.8.8.8")
            count = request.parameters.get("count", 4)
            if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", target) or target.startswith("-") or ".." in target:
                return False, "Ping target is invalid."
            if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10:
                return False, "Ping count must be an integer from 1 to 10."

        # --- Identity must be a trusted authenticated UserContext, not a raw username ---
        user_ctx = request.user
        if not hasattr(user_ctx, "has_scope") or not hasattr(user_ctx, "username"):
            return False, (
                f"Invalid user identity on request '{request.request_id}': expected an "
                f"authenticated UserContext, got {type(user_ctx).__name__}. Raw usernames "
                f"are not proof of authentication."
            )

        # --- Reject mutable compatibility contexts as production identities ---
        if not is_production_identity(user_ctx):
            return False, (
                f"User '{user_ctx.username}' is not a trusted authenticated identity. "
                f"Mutable compatibility contexts are not accepted as production identities."
            )

        # --- Enforce DIAGNOSTIC classification for troubleshooting operations ---
        if request.classification == OperationClassification.DIAGNOSTIC:
            if not user_ctx.has_scope(OperationClassification.DIAGNOSTIC.value):
                return False, (
                    f"User '{user_ctx.username}' lacks DIAGNOSTIC scope required for "
                    f"troubleshooting on device '{request.device.hostname}'."
                )

        # 1. Check command vs declared classification
        if request.command:
            detected = self.classify_command(request.command)
            # If command is more restrictive than declared, escalate
            severity_order = {
                OperationClassification.READ_ONLY: 1,
                OperationClassification.DIAGNOSTIC: 2,
                OperationClassification.WRITE: 3,
                OperationClassification.CRITICAL: 4
            }
            if severity_order[detected] > severity_order[request.classification]:
                return False, f"Command '{request.command}' requires {detected.value} classification, but request declared {request.classification.value}."

        # 2. Check user role and authorized scopes
        if not user_ctx.has_scope(request.classification.value):
            return False, (
                f"User '{user_ctx.username}' with role '{user_ctx.role}' lacks "
                f"authorization for {request.classification.value} operations."
            )

        # 2b. Device-level authorization
        if hasattr(user_ctx, "can_access_device") and not user_ctx.can_access_device(request.device.device_id):
            return False, (
                f"User '{user_ctx.username}' is not authorized to access device '{request.device.device_id}'."
            )

        # 3. Exact-diff approval. A caller-controlled boolean is not evidence.
        if request.classification in [OperationClassification.WRITE, OperationClassification.CRITICAL]:
            if not request.approval_token:
                return False, f"{request.classification.value} operation requires an externally verified approval token."
            if self.approval_verifier is None:
                return False, "Trusted approval provider is not configured; WRITE/CRITICAL operations fail closed."
            try:
                diff_hash = self._canonical_diff_hash(request)
            except (TypeError, ValueError, OverflowError, RecursionError):
                return False, "Proposed operation diff is not safely serializable for approval verification."
            try:
                evidence = self.approval_verifier(
                    token=request.approval_token,
                    requester=user_ctx.username,
                    target_id=request.device.device_id,
                    classification=request.classification.value,
                    request_id=request.request_id,
                    diff_hash=diff_hash,
                )
            except Exception:
                evidence = None
            if not isinstance(evidence, ApprovalVerificationResult) or not evidence.approved:
                return False, "Approval token is invalid, expired, or not bound to this exact target and proposed diff."
            expected_claims = (user_ctx.username, request.device.device_id, request.classification.value, request.request_id, diff_hash)
            actual_claims = (evidence.requester, evidence.target_id, evidence.classification, evidence.request_id, evidence.diff_hash)
            if actual_claims != expected_claims:
                return False, "Approval evidence claims do not match the exact requester, target, classification, request, and diff."
            approvers = {str(a).strip().casefold() for a in evidence.approver_ids if str(a).strip()}
            if not approvers or user_ctx.username.casefold() in approvers:
                return False, "Approval must be issued by an approver other than the requester."
            if request.classification == OperationClassification.CRITICAL and len(approvers) < 2:
                return False, "CRITICAL operations require two distinct approvers, separate from the requester."
            try:
                expiry = datetime.datetime.fromisoformat(evidence.expires_at.replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            except (AttributeError, ValueError):
                return False, "Approval evidence has an invalid expiry timestamp."
            if expiry <= datetime.datetime.now(datetime.timezone.utc):
                return False, "Approval evidence is expired."

        return True, "Authorization and policy check passed."
