import re
from typing import List, Dict, Any, Optional
from .models import DiscoveredNeighbor, DiscoverySource

class NeighborParser:
    """
    Parses LLDP, CDP, MNDP, and ARP outputs across multi-vendor network operating systems.
    """

    @staticmethod
    def parse_mikrotik_neighbors(raw_text: str) -> List[DiscoveredNeighbor]:
        """
        Parses MikroTik RouterOS `/ip neighbor print detail` or standard print.
        """
        neighbors = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue

            current = {}
            parts = re.findall(r'(\w+(?:-\w+)*)=(".*?"|\S+)', line)
            for k, v in parts:
                current[k.replace("-", "_")] = v.strip('"')

            if current and "interface" in current:
                neighbors.append(DiscoveredNeighbor(
                    local_interface=current.get("interface", "unknown"),
                    remote_device_id=current.get("identity") or current.get("mac_address", "UNKNOWN"),
                    remote_interface=current.get("interface_name"),
                    remote_hostname=current.get("identity"),
                    remote_ip=current.get("address"),
                    remote_mac=current.get("mac_address"),
                    discovery_protocol=DiscoverySource.MNDP if "mndp" in current.get("protocol", "").lower() else DiscoverySource.LLDP,
                    raw_details=dict(current)
                ))
        return neighbors

    @staticmethod
    def parse_cisco_cdp_neighbors(raw_text: str) -> List[DiscoveredNeighbor]:
        """
        Parses Cisco IOS/IOS-XE `show cdp neighbors detail`.
        """
        neighbors = []
        entries = re.split(r'-------------------------', raw_text)
        for entry in entries:
            if "Device ID:" not in entry:
                continue
            
            dev_id_match = re.search(r'Device ID:\s*(\S+)', entry)
            ip_match = re.search(r'IP address:\s*(\d+\.\d+\.\d+\.\d+)', entry)
            local_intf_match = re.search(r'Interface:\s*([^,]+),', entry)
            port_id_match = re.search(r'Port ID \(outgoing port\):\s*(\S+)', entry)

            if dev_id_match and local_intf_match:
                dev_id = dev_id_match.group(1).split(".")[0] # strip domain if present
                local_intf = local_intf_match.group(1).strip()
                remote_intf = port_id_match.group(1).strip() if port_id_match else None
                ip_addr = ip_match.group(1).strip() if ip_match else None

                neighbors.append(DiscoveredNeighbor(
                    local_interface=local_intf,
                    remote_device_id=dev_id,
                    remote_interface=remote_intf,
                    remote_hostname=dev_id,
                    remote_ip=ip_addr,
                    discovery_protocol=DiscoverySource.CDP,
                    raw_details={"entry": entry[:100]}
                ))
        return neighbors

    @staticmethod
    def parse_standard_lldp(raw_text: str) -> List[DiscoveredNeighbor]:
        """
        Parses standard IEEE 802.1AB LLDP outputs (Huawei, Cisco, Ruijie, Linux).
        """
        neighbors = []
        for line in raw_text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and not parts[0].lower().startswith(("local", "port", "interface", "--", "phy")):
                local_if = parts[0]
                chassis = parts[1]
                port_id = parts[2]
                sys_name = parts[3]
                neighbors.append(DiscoveredNeighbor(
                    local_interface=local_if,
                    remote_device_id=sys_name,
                    remote_interface=port_id,
                    remote_hostname=sys_name,
                    remote_mac=chassis if ":" in chassis or "-" in chassis else None,
                    discovery_protocol=DiscoverySource.LLDP
                ))
        return neighbors
