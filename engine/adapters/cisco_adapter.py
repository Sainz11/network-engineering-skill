from typing import Dict, Any, List
from .base_adapter import BaseDeviceAdapter, validate_ping_parameters
from scripts.redact import redact_sensitive_data

class CiscoAdapter(BaseDeviceAdapter):
    def get_system_info(self) -> Dict[str, Any]:
        ver_output = self.connector.execute_command("show version")
        info = {"vendor": "Cisco", "raw_version": ver_output}
        for line in ver_output.splitlines():
            if "Cisco IOS" in line:
                info["software"] = line.strip()
            elif "uptime is" in line:
                info["uptime"] = line.strip()
            elif "Processor board ID" in line or "System serial number" in line:
                info["serial"] = line.strip()
        return info

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("show ip interface brief")
        interfaces = []
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                interfaces.append({
                    "interface": parts[0],
                    "ip_address": parts[1],
                    "status": parts[4],
                    "protocol": parts[5] if len(parts) > 5 else "unknown"
                })
        return interfaces

    def run_diagnostic_ping(self, target: str, count: int = 5) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        cmd = f"ping {target} repeat {count}"
        raw = self.connector.execute_command(cmd)
        success_rate = "100%" if "!" in raw else "0%"
        if "Success rate is" in raw:
            for part in raw.split("\n"):
                if "Success rate is" in part:
                    success_rate = part.strip()
        return {
            "target": target,
            "count": count,
            "success_rate": success_rate,
            "raw_output": raw
        }

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("show running-config")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {
                "dry_run": True,
                "status": "VALIDATED",
                "commands": [redact_sensitive_data(c) for c in config_commands],
                "message": "Commands staged for execution. Cisco archive config rollback suggested before commit."
            }
        results = []
        self.connector.execute_command("configure terminal")
        for cmd in config_commands:
            out = self.connector.execute_command(cmd)
            results.append({"command": redact_sensitive_data(cmd), "result": out})
        self.connector.execute_command("end")
        return {
            "dry_run": False,
            "status": "APPLIED",
            "execution_log": results,
            "rollback_guidance": "Execute 'configure replace <checkpoint_file>' to restore prior state."
        }
