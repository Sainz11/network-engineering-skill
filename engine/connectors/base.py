from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import time

class BaseConnector(ABC):
    def __init__(self, host: str, port: int = 22, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.is_connected = False

    @abstractmethod
    def connect(self, credentials: Dict[str, Any]) -> bool:
        """Establish connection to endpoint."""
        pass

    @abstractmethod
    def disconnect(self):
        """Safely terminate connection."""
        pass

    @abstractmethod
    def execute_command(self, command: str) -> str:
        """Execute command and return raw output."""
        pass

    @abstractmethod
    def ping_check(self) -> bool:
        """Verify reachability."""
        pass
