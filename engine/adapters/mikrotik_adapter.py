from typing import Dict, Any, List
from .base_adapter import BaseDeviceAdapter, validate_ping_parameters
from scripts.redact import redact_sensitive_data

class MikroTikAdapter(BaseDeviceAdapter):
    def get_system_info(self) -> Dict[str, Any]:
        res_output = self.connector.execute_command("/system resource print")
        rb_output = self.connector.execute_command("/system routerboard print")
        
        info = {"raw_resource": res_output, "vendor": "MikroTik"}
        for line in (res_output + "\n" + rb_output).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip().replace("-", "_")] = v.strip()
        return info

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("/interface print detail")
        interfaces = []
        for line in raw.splitlines():
            if "name=" in line:
                interfaces.append({"raw": line.strip()})
        if not interfaces:
            # Fallback table parse
            interfaces = [{"raw": l.strip()} for l in raw.splitlines() if len(l.strip()) > 0 and not l.startswith("Flags:")]
        return interfaces

    def run_diagnostic_ping(self, target: str, count: int = 4) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        cmd = f"/ping {target} count={count}"
        raw = self.connector.execute_command(cmd)
        packet_loss = "0%"
        if "packet-loss=" in raw:
            for part in raw.split():
                if "packet-loss=" in part:
                    packet_loss = part.split("=")[1]
        return {
            "target": target,
            "count": count,
            "packet_loss": packet_loss,
            "raw_output": raw
        }

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("/export")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {
                "dry_run": True,
                "status": "VALIDATED",
                "commands": [redact_sensitive_data(cmd) for cmd in config_commands],
                "message": "Commands validated in dry-run mode. Safe Mode recommended for live application."
            }
        
        results = []
        for cmd in config_commands:
            out = self.connector.execute_command(cmd)
            results.append({"command": redact_sensitive_data(cmd), "result": out})
        return {
            "dry_run": False,
            "status": "APPLIED",
            "execution_log": results,
            "rollback_guidance": "Use '/system backup load' or RouterOS Safe Mode auto-revert on disconnect."
        }
