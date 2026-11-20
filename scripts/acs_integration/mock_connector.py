import uuid
import datetime
from typing import Dict, Any, List, Optional
from .connector_interface import ACSConnectorInterface
from engine.execution.module_workflow import execute_authorized_module_workflow
from engine.policy.types import OperationClassification

class MockACSConnector(ACSConnectorInterface):
    """
    Mock ACS Connector for development, testing, and offline staging environments.
    Simulates CWMP (TR-069) / USP (TR-369) interactions without requiring physical devices or live ACS endpoints.
    """
    def __init__(self, endpoint_url: str = "http://mock-acs.local:7547", api_key: Optional[str] = None,
                 operations_engine=None, user_ctx=None, inventory_device_id: Optional[str] = None,
                 simulation_mutation_authorizer=None):
        self.endpoint_url = endpoint_url
        if api_key is not None:
            raise ValueError("Mock ACS does not accept API credentials; its in-memory authentication is simulation-only.")
        self.api_key = None
        self.authenticated = False
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.operations_engine = operations_engine
        self.user_ctx = user_ctx
        self.inventory_device_id = inventory_device_id
        # Explicit test/development-only approval hook for this in-memory mock.
        # It cannot authorize any live ACS operation.
        self.simulation_mutation_authorizer = simulation_mutation_authorizer

        # In-memory simulated device registry
        self.devices: Dict[str, Dict[str, Any]] = {
            "HWTC12345678": {
                "id": "HWTC12345678",
                "manufacturer": "Huawei",
                "model_name": "HG8245H5",
                "serial_number": "HWTC12345678",
                "hardware_version": "V1.0",
                "software_version": "V5R019C20S125",
                "ip_address": "10.100.20.15",
                "connection_request_url": "http://10.100.20.15:7547/tr069",
                "last_inform": datetime.datetime.now().isoformat(),
                "parameters": {
                    "Device.DeviceInfo.Manufacturer": "Huawei",
                    "Device.DeviceInfo.ModelName": "HG8245H5",
                    "Device.DeviceInfo.SerialNumber": "HWTC12345678",
                    "Device.DeviceInfo.SoftwareVersion": "V5R019C20S125",
                    "Device.ManagementServer.URL": "http://mock-acs.local:7547",
                    "Device.ManagementServer.PeriodicInformInterval": 86400,
                    "Device.Ethernet.InterfaceNumberOfEntries": 4,
                    "Device.WiFi.SSID.1.SSID": "ISP_FiberHome_2.4G",
                    "Device.WiFi.SSID.1.Enable": True,
                    "Device.Optical.Interface.1.RXPower": -19.5,
                    "Device.Optical.Interface.1.TXPower": 2.3,
                    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username": "cust_10928@isp.net",
                    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password": "***REDACTED***",
                    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ConnectionStatus": "Connected",
                    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress": "100.64.12.89"
                }
            },
            "ZTEG98765432": {
                "id": "ZTEG98765432",
                "manufacturer": "ZTE",
                "model_name": "F670L",
                "serial_number": "ZTEG98765432",
                "hardware_version": "V9.0",
                "software_version": "V9.0.10P1N12",
                "ip_address": "10.100.20.16",
                "connection_request_url": "http://10.100.20.16:7547/tr069",
                "last_inform": datetime.datetime.now().isoformat(),
                "parameters": {
                    "Device.DeviceInfo.Manufacturer": "ZTE",
                    "Device.DeviceInfo.ModelName": "F670L",
                    "Device.DeviceInfo.SerialNumber": "ZTEG98765432",
                    "Device.DeviceInfo.SoftwareVersion": "V9.0.10P1N12",
                    "Device.Optical.Interface.1.RXPower": -21.2,
                    "Device.Optical.Interface.1.TXPower": 2.1
                }
            }
        }

    def _log_audit(self, action: str, device_id: Optional[str], details: Any):
        self.audit_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action,
            "device_id": device_id,
            "details": details
        })

    def _authorize_mock_operation(self, action: str, device_id: str, parameters: Dict[str, Any],
                                  classification: OperationClassification, approval_token: Optional[str] = None):
        workflow = {
            OperationClassification.READ_ONLY: "acs_mock_read",
            OperationClassification.DIAGNOSTIC: "acs_mock_connection_request",
            OperationClassification.WRITE: "acs_mock_configuration",
            OperationClassification.CRITICAL: "acs_mock_reboot",
        }[classification]
        if self.operations_engine is not None and self.user_ctx is not None and self.inventory_device_id:
            result = execute_authorized_module_workflow(
                operations_engine=self.operations_engine,
                user_ctx=self.user_ctx,
                device_id=self.inventory_device_id,
                module="isp_provisioning_remote_management",
                workflow=workflow,
                classification=classification,
                parameters={"acs_action": action, "acs_device_id": device_id, "parameters": parameters},
                approval_token=approval_token,
                handler=lambda canonical, payload: {
                    "authorized_inventory_device": canonical.device_id,
                    "acs_device_id": payload.get("acs_device_id"),
                    "simulation_only": True,
                },
            )
            if not result.success:
                raise PermissionError(result.error or "Shared OperationsEngine denied ACS mock operation.")
            self._log_audit("SHARED_ENGINE_AUTHORIZATION", device_id, {"operation": action, "result": result.status})
            return
        if classification == OperationClassification.READ_ONLY and self.operations_engine is None:
            self._log_audit("MOCK_READ_ONLY", device_id, {"operation": action})
            return
        authorizer = self.simulation_mutation_authorizer
        if callable(authorizer) and authorizer(action, device_id, dict(parameters), classification.value) is True:
            self._log_audit("EXPLICIT_MOCK_SIMULATION_APPROVAL", device_id, {"operation": action, "classification": classification.value})
            return
        raise PermissionError(
            "ACS connector is MOCK ONLY. Mutating or action-triggering operations require "
            "the shared OperationsEngine authorization path or an explicit simulation-only test authorizer."
        )

    def authenticate(self) -> bool:
        """Enter explicit in-memory mock mode; this is not ACS authentication."""
        self.authenticated = True
        self._log_audit(
            "MOCK_AUTHENTICATED", None,
            {"endpoint": self.endpoint_url, "auth_mode": "IN_MEMORY_SIMULATION", "live_authentication": False},
        )
        return True

    def discover_devices(self, filter_criteria: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self.authenticated:
            raise PermissionError("ACS Connector not authenticated. Call authenticate() first.")
        if self.operations_engine is not None:
            self._authorize_mock_operation("discover_devices", "", filter_criteria or {}, OperationClassification.READ_ONLY)
        results = []
        for dev in self.devices.values():
            if filter_criteria:
                match = True
                for k, v in filter_criteria.items():
                    if dev.get(k) != v:
                        match = False
                        break
                if match:
                    results.append(dev)
            else:
                results.append(dev)
        self._log_audit("DEVICE_DISCOVERY", None, {"count": len(results)})
        return results

    def get_parameter_values(self, device_id: str, parameter_paths: List[str]) -> Dict[str, Any]:
        if not self.authenticated:
            raise PermissionError("ACS Connector not authenticated.")
        if device_id not in self.devices:
            raise KeyError(f"Device {device_id} not found in ACS inventory.")
        if self.operations_engine is not None:
            self._authorize_mock_operation("get_parameter_values", device_id, {"parameter_paths": list(parameter_paths)}, OperationClassification.READ_ONLY)

        dev_params = self.devices[device_id].get("parameters", {})
        ret = {}
        for path in parameter_paths:
            if path in dev_params:
                ret[path] = dev_params[path]
            else:
                # Support wildcard prefix query
                matched = {k: v for k, v in dev_params.items() if k.startswith(path)}
                if matched:
                    ret.update(matched)
                else:
                    ret[path] = None
        self._log_audit("GET_PARAMETER_VALUES", device_id, {"requested": parameter_paths})
        return ret

    def set_parameter_values(self, device_id: str, parameter_dict: Dict[str, Any], approval_token: Optional[str] = None) -> Dict[str, Any]:
        if not self.authenticated:
            raise PermissionError("ACS Connector not authenticated.")
        if device_id not in self.devices:
            raise KeyError(f"Device {device_id} not found in ACS inventory.")
        if not isinstance(parameter_dict, dict) or not parameter_dict:
            raise ValueError("A non-empty parameter dictionary is required.")
        self._authorize_mock_operation("set_parameter_values", device_id, parameter_dict, OperationClassification.WRITE, approval_token)

        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        dev_params = self.devices[device_id].setdefault("parameters", {})
        
        # Apply parameters
        for k, v in parameter_dict.items():
            dev_params[k] = v

        job = {
            "job_id": job_id,
            "device_id": device_id,
            "status": "COMPLETED",
            "execution_mode": "SIMULATED",
            "integration": "MOCK_ONLY",
            "modified_parameters": list(parameter_dict.keys()),
            "completed_at": datetime.datetime.now().isoformat()
        }
        self.jobs[job_id] = job
        self._log_audit("SET_PARAMETER_VALUES", device_id, {"job_id": job_id, "params": list(parameter_dict.keys())})
        return job

    def trigger_connection_request(self, device_id: str) -> bool:
        if not self.authenticated:
            raise PermissionError("ACS Connector not authenticated.")
        if device_id not in self.devices:
            raise KeyError(f"Device {device_id} not found.")
        self._authorize_mock_operation("trigger_connection_request", device_id, {}, OperationClassification.DIAGNOSTIC)
        self._log_audit("CONNECTION_REQUEST_SENT", device_id, {"url": self.devices[device_id].get("connection_request_url"), "mode": "MOCK_ONLY"})
        return True

    def reboot_device(self, device_id: str, approval_token: Optional[str] = None) -> Dict[str, Any]:
        if not self.authenticated:
            raise PermissionError("ACS Connector not authenticated.")
        if device_id not in self.devices:
            raise KeyError(f"Device {device_id} not found.")
        self._authorize_mock_operation("reboot_device", device_id, {"command": "Reboot"}, OperationClassification.CRITICAL, approval_token)
        job_id = f"JOB-REBOOT-{uuid.uuid4().hex[:8].upper()}"
        job = {
            "job_id": job_id,
            "device_id": device_id,
            "status": "PENDING_CPE_CONTACT",
            "command": "Reboot",
            "execution_mode": "SIMULATED",
            "integration": "MOCK_ONLY",
            "created_at": datetime.datetime.now().isoformat()
        }
        self.jobs[job_id] = job
        self._log_audit("REBOOT_REQUEST", device_id, {"job_id": job_id})
        return job

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        if not self.authenticated:
            raise PermissionError("ACS Connector not authenticated.")
        if job_id not in self.jobs:
            raise KeyError(f"Job {job_id} not found.")
        job = self.jobs[job_id]
        if self.operations_engine is not None:
            self._authorize_mock_operation(
                "get_job_status", str(job.get("device_id", "")), {"job_id": job_id},
                OperationClassification.READ_ONLY,
            )
        return dict(job)
