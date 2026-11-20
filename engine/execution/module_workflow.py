"""Small helper for routing offline module workflows through OperationsEngine."""
from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, Optional

from ..policy.types import OperationRequest, OperationClassification, ExecutionMode


def execute_authorized_module_workflow(
    operations_engine,
    user_ctx,
    device_id: str,
    module: str,
    workflow: str,
    classification: OperationClassification,
    parameters: Optional[Dict[str, Any]],
    handler: Callable[..., Any],
    command: Optional[str] = None,
    approval_token: Optional[str] = None,
):
    """Create a canonical-target request and delegate lifecycle to OperationsEngine.

    Local handlers are always represented as SIMULATED. There is deliberately no
    helper for turning these callbacks into LIVE device operations.
    """
    if operations_engine is None or user_ctx is None:
        raise PermissionError("Shared OperationsEngine and authenticated UserContext are required for this workflow.")
    canonical = operations_engine.inventory_manager.get_device(device_id)
    if canonical is None:
        raise PermissionError("Workflow target must resolve to the canonical device inventory.")
    request = OperationRequest(
        request_id=f"WF-{uuid.uuid4().hex[:12].upper()}",
        user=user_ctx,
        device=canonical,
        classification=classification,
        action="module_workflow",
        command=command,
        parameters=dict(parameters or {}),
        approval_token=approval_token,
        execution_mode=ExecutionMode.SIMULATED,
    )
    return operations_engine.run_module_workflow(request, module, workflow, handler)
