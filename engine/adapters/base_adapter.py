from abc import ABC, abstractmethod
import ipaddress
import re
from typing import Dict, Any, List, Optional
from ..connectors.base import BaseConnector

def validate_ping_parameters(target: str, count: int = 4) -> tuple[str, int]:
    """Validate ping parameters against shell/CLI option injection."""
    if not isinstance(target, str) or not target or len(target) > 253 or target.startswith("-"):
        raise ValueError("Ping target must be a valid IP address or hostname")
    try:
        normalized = str(ipaddress.ip_address(target))
    except ValueError:
        if not re.fullmatch(r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", target):
            raise ValueError("Ping target must be a valid IP address or hostname")
        normalized = target
    if isinstance(count, bool):
        raise ValueError("Ping count must be an integer from 1 to 10")
    try:
        count = int(count)
    except (TypeError, ValueError):
        raise ValueError("Ping count must be an integer from 1 to 10") from None
    if count < 1 or count > 10:
        raise ValueError("Ping count must be an integer from 1 to 10")
    return normalized, count

class BaseDeviceAdapter(ABC):
    def __init__(self, connector: BaseConnector):
        self.connector = connector

    @abstractmethod
    def get_system_info(self) -> Dict[str, Any]:
        """Collect platform, version, uptime, and serial."""
        pass

    @abstractmethod
    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Collect interface statuses, MTU, and counters."""
        pass

    @abstractmethod
    def run_diagnostic_ping(self, target: str, count: int = 4) -> Dict[str, Any]:
        """Execute diagnostic ICMP reachability check."""
        pass

    @abstractmethod
    def backup_configuration(self) -> str:
        """Retrieve complete running configuration with redaction."""
        pass

    @abstractmethod
    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        """Apply configuration changes with dry-run support."""
        pass
