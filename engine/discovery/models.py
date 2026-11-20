from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import datetime

class DiscoverySource(str, Enum):
    LLDP = "LLDP"
    CDP = "CDP"
    MNDP = "MNDP"
    ARP = "ARP"
    BRIDGE_HOST = "BRIDGE_HOST"
    DHCP_LEASE = "DHCP_LEASE"
    ACS_INVENTORY = "ACS_INVENTORY"
    MANUAL = "MANUAL"
    ROUTEROS_API = "ROUTEROS_API"
    SNMP = "SNMP"

class LinkConfidence(str, Enum):
    VERIFIED = "VERIFIED"     # Verified bidirectional LLDP/CDP/physical corroboration
    INFERRED = "INFERRED"     # Single-sided observation, ARP/Bridge correlation
    UNKNOWN = "UNKNOWN"       # Subnet match or uncorroborated single host hint

class DeviceRole(str, Enum):
    INTERNET_GATEWAY = "INTERNET_GATEWAY"
    ROUTER = "ROUTER"
    CORE_SWITCH = "CORE_SWITCH"
    DISTRIBUTION_SWITCH = "DISTRIBUTION_SWITCH"
    ACCESS_SWITCH = "ACCESS_SWITCH"
    ACCESS_POINT = "ACCESS_POINT"
    ONT_ONU = "ONT_ONU"
    OUTDOOR_RADIO = "OUTDOOR_RADIO"
    MICROWAVE = "MICROWAVE"
    UNKNOWN = "UNKNOWN"

@dataclass
class DiscoveredNeighbor:
    local_interface: str
    remote_device_id: str
    remote_interface: Optional[str] = None
    remote_hostname: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_mac: Optional[str] = None
    discovery_protocol: DiscoverySource = DiscoverySource.LLDP
    raw_details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DiscoveredDevice:
    device_id: str
    management_ip: str
    hostname: str
    vendor: str
    model: str = "UNKNOWN"
    role: DeviceRole = DeviceRole.UNKNOWN
    mac_address: Optional[str] = None
    firmware_version: Optional[str] = None
    hardware_revision: Optional[str] = None
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    neighbors: List[DiscoveredNeighbor] = field(default_factory=list)
    discovery_sources: List[DiscoverySource] = field(default_factory=list)
    confidence: float = 1.0 # 0.0 to 1.0
    last_observed: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    health_status: str = "HEALTHY" # HEALTHY, WARNING, CRITICAL, UNKNOWN
    health_metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TopologyLink:
    link_id: str
    source_device_id: str
    source_interface: str
    target_device_id: str
    target_interface: str
    confidence: LinkConfidence
    evidence_sources: List[str] = field(default_factory=list)
    status: str = "UP" # UP, DOWN, DEGRADED
    metrics: Dict[str, Any] = field(default_factory=dict)
