from typing import Tuple, Dict, Any

class ConnectorSelector:
    """
    Intelligently selects the optimal connection mechanism:
    1. RouterOS API: High-throughput structured automation, bulk queries, scripted configuration.
    2. SSH Connector: Fast CLI diagnostics, batch scripting, routerboard firmware review.
    3. Winbox GUI: Live desktop troubleshooting, visual inspection, neighbor list discovery, screenshot evidence.
    """
    @staticmethod
    def select_connector(task_type: str, user_preference: str = "auto", winbox_available: bool = False) -> Tuple[str, str]:
        pref = user_preference.lower()
        if pref in ["winbox", "gui"]:
            if winbox_available:
                return "winbox", "User explicitly requested Winbox GUI desktop interaction."
            return "ssh", "Winbox GUI requested but not detected on Windows host. Falling back to SSH CLI."

        t = task_type.lower()
        if any(w in t for w in ["screenshot", "visual", "gui", "desktop", "neighbor_scan"]):
            if winbox_available:
                return "winbox", "Task requires visual UI inspection or screenshot evidence; selecting Winbox GUI."
            return "ssh", "Visual task requested, but Winbox not installed; falling back to SSH CLI diagnostic."

        if any(w in t for w in ["bulk_provisioning", "api", "structured_json", "telemetry"]):
            return "api", "Task requires structured JSON telemetry and high-throughput execution; selecting RouterOS API."

        # Default standard for operations
        return "ssh", "Standard operation; selecting SSH for fast, scriptable, and auditable execution."
