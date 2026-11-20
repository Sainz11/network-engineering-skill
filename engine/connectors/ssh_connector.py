from typing import Dict, Any, Optional
from .base import BaseConnector
from scripts.redact import redact_sensitive_data

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

class SSHConnector(BaseConnector):
    def __init__(self, host: str, port: int = 22, timeout: int = 10, host_key_policy: str = "RejectUnknown"):
        if not 1 <= int(port) <= 65535:
            raise ValueError("SSH port must be in range 1..65535")
        super().__init__(host, port, max(1, min(int(timeout), 30)))
        self.client: Optional[Any] = None
        self.host_key_policy = host_key_policy
        self.allow_write_commands = False
        self.allow_critical_commands = False

    def connect(self, credentials: Dict[str, Any]) -> bool:
        if self.host_key_policy != "RejectUnknown":
            raise ValueError("Only RejectUnknown SSH host-key policy is supported")
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("paramiko library is required for live SSH connections.")
        
        username = credentials.get("username")
        password = credentials.get("password")
        key_filename = credentials.get("key_filename")

        self.client = paramiko.SSHClient()
        if self.host_key_policy != "RejectUnknown":
            raise ValueError("Only RejectUnknown SSH host-key policy is supported")
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False if password else True
            )
            self.is_connected = True
            return True
        except Exception as e:
            self.is_connected = False
            # Avoid leaking credential values or server banners in exception text.
            raise ConnectionError(f"SSH connection failed to {self.host}:{self.port} ({type(e).__name__})") from None

    def disconnect(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            finally:
                self.client = None
                self.is_connected = False

    def execute_command(self, command: str) -> str:
        if not self.is_connected or not self.client:
            raise RuntimeError("SSH Client is not connected.")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("SSH command must be a non-empty string")
        if any(ch in command for ch in (";", "|", "&", ">", "<", "$", "`", "\n", "\r")):
            raise PermissionError("SSH command contains shell control characters or operators")
        if not __import__("re").fullmatch(r"[A-Za-z0-9_./:=,+@% -]+", command.strip()):
            raise PermissionError("SSH command contains unsupported syntax")
        from ..policy.security_policy import SecurityPolicyEngine
        from ..policy.types import OperationClassification
        classification = SecurityPolicyEngine().classify_command(command)
        if classification == OperationClassification.WRITE and not self.allow_write_commands:
            raise PermissionError("SSH connector is read-only; WRITE command requires verified authorization")
        if classification == OperationClassification.CRITICAL and not self.allow_critical_commands:
            raise PermissionError("SSH connector blocks CRITICAL commands")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if err and not out:
                return err
            return out
        except Exception as e:
            raise RuntimeError(f"SSH command execution error ({type(e).__name__})") from None

    def ping_check(self) -> bool:
        return self.is_connected
