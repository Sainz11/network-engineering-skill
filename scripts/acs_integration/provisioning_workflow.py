"""Offline ISP provisioning request simulation through the shared OperationsEngine.

This service validates request shape and records an auditable simulated workflow.
It does not speak PPPoE, DHCP, VLAN/QinQ, PON, ONT/ONU, CWMP or USP protocols,
and it never applies configuration to a network device.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from engine.execution.module_workflow import execute_authorized_module_workflow
from engine.policy.types import OperationClassification


SUPPORTED_REQUEST_TYPES = {
    "PPPOE", "IPOE", "DHCP", "VLAN", "QINQ", "GPON", "EPON", "XGS-PON", "ONT", "ONU"
}
_FORBIDDEN_PARAMETER_WORDS = {"password", "passwd", "secret", "token", "credential", "private_key", "psk", "community"}


class ISPProvisioningSimulationService:
    """Create auditable, offline-only provisioning request simulations."""

    def __init__(self, operations_engine, user_ctx):
        if operations_engine is None or user_ctx is None:
            raise ValueError("Provisioning simulation requires the shared OperationsEngine and an authenticated UserContext.")
        self.operations_engine = operations_engine
        self.user_ctx = user_ctx

    @staticmethod
    def _validate_parameters(parameters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if parameters is None:
            return {}
        if not isinstance(parameters, dict) or len(parameters) > 40:
            raise ValueError("Provisioning parameters must be a dictionary with at most 40 entries.")
        validated: Dict[str, Any] = {}
        for key, value in parameters.items():
            if not isinstance(key, str) or not key.strip() or len(key) > 80:
                raise ValueError("Provisioning parameter names must be non-empty strings of at most 80 characters.")
            normalized_key = key.casefold().replace("-", "_")
            if any(secret_word in normalized_key for secret_word in _FORBIDDEN_PARAMETER_WORDS):
                raise ValueError("Credential-bearing parameters are not accepted by the offline simulation service.")
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError(f"Provisioning parameter {key!r} must be a scalar value.")
            if isinstance(value, str) and len(value) > 256:
                raise ValueError(f"Provisioning parameter {key!r} exceeds 256 characters.")
            validated[key] = value
        return validated

    def simulate_request(self, device_id: str, request_type: str, parameters: Optional[Dict[str, Any]] = None):
        normalized_type = str(request_type or "").strip().upper().replace(" ", "-")
        if normalized_type not in SUPPORTED_REQUEST_TYPES:
            raise ValueError(f"Unsupported provisioning request type {request_type!r}.")
        safe_parameters = self._validate_parameters(parameters)
        request = {
            "request_type": normalized_type,
            "parameters": safe_parameters,
            "execution_mode": "SIMULATED",
            "provider": "NONE",
            "transport": "NONE",
            "applied": False,
            "real_integration": False,
        }
        return execute_authorized_module_workflow(
            operations_engine=self.operations_engine,
            user_ctx=self.user_ctx,
            device_id=device_id,
            module="isp_provisioning_remote_management",
            workflow="provisioning_simulation",
            classification=OperationClassification.DIAGNOSTIC,
            parameters=request,
            handler=lambda canonical, payload: {
                "canonical_device_id": canonical.device_id,
                "request_type": payload["request_type"],
                "parameters": payload["parameters"],
                "workflow_status": "SIMULATED_NOT_APPLIED",
                "provider": "NONE",
                "transport": "NONE",
                "applied": False,
                "real_integration": False,
                "note": "Offline request-shape simulation only; no PPPoE/DHCP/VLAN/PON/ACS operation was performed.",
            },
        )
