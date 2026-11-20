from typing import Dict, Any, List
from .base_adapter import BaseDeviceAdapter, validate_ping_parameters
from scripts.redact import redact_sensitive_data

class RuijieAdapter(BaseDeviceAdapter):
    """Ruijie Networks & Reyee Enterprise / Cloud Gateway / Switch Adapter."""
    def get_system_info(self) -> Dict[str, Any]:
        raw = self.connector.execute_command("show version")
        return {"vendor": "Ruijie", "raw_output": raw}

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("show ip interface brief")
        return [{"raw": line.strip()} for line in raw.splitlines() if line.strip()]

    def run_diagnostic_ping(self, target: str, count: int = 5) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        raw = self.connector.execute_command(f"ping {target} -c {count}")
        return {"target": target, "count": count, "raw_output": raw}

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("show running-config")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {"dry_run": True, "status": "VALIDATED", "commands": [redact_sensitive_data(c) for c in config_commands]}
        results = []
        self.connector.execute_command("configure terminal")
        for cmd in config_commands:
            results.append({"command": redact_sensitive_data(cmd), "result": self.connector.execute_command(cmd)})
        self.connector.execute_command("end")
        return {"dry_run": False, "status": "APPLIED", "execution_log": results}

class CambiumAdapter(BaseDeviceAdapter):
    """Cambium Networks ePMP / cnWave / PTP / cnMaestro Adapter."""
    def get_system_info(self) -> Dict[str, Any]:
        raw = self.connector.execute_command("get configSysApp")
        return {"vendor": "Cambium", "raw_output": raw}

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("get ethernetLinkStatus")
        return [{"raw": raw}]

    def run_diagnostic_ping(self, target: str, count: int = 4) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        raw = self.connector.execute_command(f"ping {target}")
        return {"target": target, "raw_output": raw}

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("show config")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {"dry_run": True, "status": "VALIDATED", "commands": [redact_sensitive_data(c) for c in config_commands]}
        results = [self.connector.execute_command(cmd) for cmd in config_commands]
        return {"dry_run": False, "status": "APPLIED", "execution_log": results}

class UbiquitiAdapter(BaseDeviceAdapter):
    """Ubiquiti airMAX / EdgeMAX / UniFi Adapter."""
    def get_system_info(self) -> Dict[str, Any]:
        raw = self.connector.execute_command("cat /etc/version")
        return {"vendor": "Ubiquiti", "version": raw.strip(), "raw_output": raw}

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("ifconfig")
        return [{"raw": raw}]

    def run_diagnostic_ping(self, target: str, count: int = 4) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        raw = self.connector.execute_command(f"ping -c {count} {target}")
        return {"target": target, "raw_output": raw}

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("cat /tmp/system.cfg")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {"dry_run": True, "status": "VALIDATED", "commands": [redact_sensitive_data(c) for c in config_commands]}
        results = [self.connector.execute_command(cmd) for cmd in config_commands]
        return {"dry_run": False, "status": "APPLIED", "execution_log": results}

class TPLinkAdapter(BaseDeviceAdapter):
    """TP-Link Omada / Pharos Adapter."""
    def get_system_info(self) -> Dict[str, Any]:
        raw = self.connector.execute_command("show system-info")
        return {"vendor": "TP-Link", "raw_output": raw}

    def get_interfaces(self) -> List[Dict[str, Any]]:
        raw = self.connector.execute_command("show interface status")
        return [{"raw": raw}]

    def run_diagnostic_ping(self, target: str, count: int = 4) -> Dict[str, Any]:
        target, count = validate_ping_parameters(target, count)
        raw = self.connector.execute_command(f"ping {target}")
        return {"target": target, "raw_output": raw}

    def backup_configuration(self) -> str:
        raw = self.connector.execute_command("show running-config")
        return redact_sensitive_data(raw)

    def apply_configuration(self, config_commands: List[str], dry_run: bool = True) -> Dict[str, Any]:
        if dry_run:
            return {"dry_run": True, "status": "VALIDATED", "commands": [redact_sensitive_data(c) for c in config_commands]}
        results = [self.connector.execute_command(cmd) for cmd in config_commands]
        return {"dry_run": False, "status": "APPLIED", "execution_log": results}
