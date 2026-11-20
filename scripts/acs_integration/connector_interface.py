from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import time

class ACSConnectorInterface(ABC):
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate against the ACS server."""
        pass

    @abstractmethod
    def discover_devices(self, filter_criteria: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List devices discovered/registered with the ACS."""
        pass

    @abstractmethod
    def get_parameter_values(self, device_id: str, parameter_paths: List[str]) -> Dict[str, Any]:
        """Read CWMP / USP parameter values from a device."""
        pass

    @abstractmethod
    def set_parameter_values(self, device_id: str, parameter_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Write CWMP / USP parameter values to a device."""
        pass

    @abstractmethod
    def trigger_connection_request(self, device_id: str) -> bool:
        """Issue an active Connection Request (HTTP GET or XMPP/STOMP) to wake up the CPE."""
        pass

    @abstractmethod
    def reboot_device(self, device_id: str) -> Dict[str, Any]:
        """Queue a safe reboot task on the CPE."""
        pass

    @abstractmethod
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Query status of an asynchronous provisioning job."""
        pass
