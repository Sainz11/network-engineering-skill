from typing import Dict, Any, List
from .base_adapter import BaseDeviceAdapter, validate_ping_parameters
from scripts.redact import redact_sensitive_data

class HuaweiAdapter(BaseDeviceAdapter):
    def get_system_info(self) -> Dict[str, Any]:
        raw = self.connector.execute_command("display version")
        info = {"vendor": "Huawei", "raw_version": raw}
        for line in raw.splitlines():
            if "VRP" in line:
                info["vrp_version"] = line.strip()
            elif "uptime is" in line:
                info["uptime"] = line.strip()
        return info

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("display interface brief")
        interfaces = []
        for line in raw.splitlines():
            if "Ethernet" in line or "GE" in line or "XGE" in line:
                interfaces.append({"raw": line.strip()})
        return interfaces

    def run_diagnostic_ping(self, target: str, count: int = 5) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        cmd = f"ping -c {count} {target}"
        raw = self.connector.execute_command(cmd)
        return {"target": target, "count": count, "raw_output": raw}

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("display current-configuration")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {
                "dry_run": True,
                "status": "VALIDATED",
                "commands": [redact_sensitive_data(c) for c in config_commands]
            }
        results = []
        self.connector.execute_command("system-view")
        for cmd in config_commands:
            out = self.connector.execute_command(cmd)
            results.append({"command": redact_sensitive_data(cmd), "result": out})
        self.connector.execute_command("return")
        return {
            "dry_run": False,
            "status": "APPLIED",
            "execution_log": results,
            "rollback_guidance": "Execute 'rollback configuration to file <file>' or commit rollback."
        }
