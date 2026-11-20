import json
import os
import stat
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional
from ..policy.types import TargetDevice

DEFAULT_INVENTORY_FILE = os.path.join(os.path.dirname(__file__), "devices.json")

class DeviceInventoryManager:
    def __init__(self, inventory_file: Optional[str] = None):
        self.inventory_file = os.path.abspath(inventory_file or DEFAULT_INVENTORY_FILE)
        os.makedirs(os.path.dirname(self.inventory_file), exist_ok=True)
        current = os.path.dirname(self.inventory_file)
        while current and current != os.path.dirname(current):
            if os.path.islink(current):
                raise PermissionError("Trusted inventory path must not contain symlinks")
            current = os.path.dirname(current)
        if os.path.islink(self.inventory_file):
            raise PermissionError("Trusted inventory file must not be a symlink")
        if not os.path.exists(self.inventory_file):
            self._init_default_inventory()

    def _init_default_inventory(self):
        sample_devices = [
            {
                "device_id": "RTR-CORE-01",
                "hostname": "core-rtr01.isp.net",
                "ip_address": "10.0.0.1",
                "vendor": "MikroTik",
                "model": "CCR2004-16G-2S+",
                "device_category": "router",
                "port": 22,
                "protocol": "ssh",
                "environment": "SIMULATED"
            },
            {
                "device_id": "SW-AGG-01",
                "hostname": "agg-sw01.isp.net",
                "ip_address": "10.0.0.2",
                "vendor": "Cisco",
                "model": "Catalyst 9300",
                "device_category": "switch",
                "port": 22,
                "protocol": "ssh",
                "environment": "SIMULATED"
            },
            {
                "device_id": "OLT-GPON-01",
                "hostname": "olt01.central.isp.net",
                "ip_address": "10.100.1.10",
                "vendor": "Huawei",
                "model": "SmartAX MA5800-X7",
                "device_category": "ont_onu",
                "port": 22,
                "protocol": "ssh",
                "environment": "SIMULATED"
            }
        ]
        with open(self.inventory_file, "w", encoding="utf-8") as f:
            json.dump(sample_devices, f, indent=2)

    def list_devices(self) -> List[TargetDevice]:
        if os.path.islink(self.inventory_file):
            raise PermissionError("Trusted inventory file must not be a symlink")
        with open(self.inventory_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Inventory must be a JSON list")
        devices = [TargetDevice(**item) for item in data]
        ids = [device.device_id.casefold() for device in devices]
        hostnames = [device.hostname.casefold() for device in devices]
        ips = [device.ip_address.casefold() for device in devices]
        if len(ids) != len(set(ids)):
            raise ValueError("Inventory contains duplicate device IDs")
        if len(hostnames) != len(set(hostnames)):
            raise ValueError("Inventory contains duplicate hostnames")
        if len(ips) != len(set(ips)):
            raise ValueError("Inventory contains duplicate management IPs")
        for device in devices:
            if not device.device_id or not device.hostname or not device.ip_address:
                raise ValueError("Inventory device is missing a required identity field")
            try:
                ipaddress.ip_address(device.ip_address)
            except ValueError:
                raise ValueError(f"Inventory management address for {device.device_id} must be an IP address") from None
            if not 1 <= int(device.port) <= 65535:
                raise ValueError(f"Invalid port for inventory device {device.device_id}")
            if device.protocol not in {"ssh", "rest", "snmp", "winbox"}:
                raise ValueError(f"Unsupported protocol in inventory for {device.device_id}")
        return devices

    def get_device(self, device_id: str) -> Optional[TargetDevice]:
        for dev in self.list_devices():
            if dev.device_id.lower() == device_id.lower() or dev.hostname.lower() == device_id.lower():
                return dev
        return None
