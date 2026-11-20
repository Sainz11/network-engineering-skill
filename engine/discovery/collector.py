import ipaddress
from typing import List, Dict, Any, Optional
from .models import DiscoveredDevice, DiscoveredNeighbor, DiscoverySource, DeviceRole
from .neighbor_parser import NeighborParser
from ..connectors.base import BaseConnector
from ..connectors.mock_connector import MockConnector
from ..execution.module_workflow import execute_authorized_module_workflow
from ..policy.types import OperationClassification

class DiscoveryCollector:
    """
    Manages authorized device discovery using scoped IP ranges, inventory sources, or connectors.
    Enforces non-disruptive, read-only discovery. Never performs unbounded port scans.
    """
    def __init__(self, authorized_subnets: Optional[List[str]] = None, operations_engine=None,
                 user_ctx=None, authorization_device_id: Optional[str] = None):
        self.authorized_subnets = [ipaddress.ip_network(s) for s in (authorized_subnets or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])]
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self.operations_engine = operations_engine
        self.user_ctx = user_ctx
        self.authorization_device_id = authorization_device_id
        self.last_ingestion_mode = "LOCAL_IMPORT_OFFLINE"

    def is_ip_authorized(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.authorized_subnets)
        except ValueError:
            return False

    def ingest_device(self, device: DiscoveredDevice, authorization_device_id: Optional[str] = None) -> bool:
        """Ingest local discovery evidence, optionally through shared authorization.

        With an OperationsEngine configured, the import is bound to a canonical
        inventory seed device and a verified DIAGNOSTIC context. Without one this
        remains an offline/manual import, not a live discovery capability.
        """
        if not self.is_ip_authorized(device.management_ip):
            return False
        if self.operations_engine is not None:
            seed_id = authorization_device_id or self.authorization_device_id
            if not seed_id or not self.user_ctx:
                raise PermissionError("Shared discovery ingestion requires an authorized canonical seed device and UserContext.")
            result = execute_authorized_module_workflow(
                operations_engine=self.operations_engine,
                user_ctx=self.user_ctx,
                device_id=seed_id,
                module="network_discovery_topology",
                workflow="discovery_ingestion",
                classification=OperationClassification.DIAGNOSTIC,
                parameters={
                    "observed_device_id": device.device_id,
                    "management_ip": device.management_ip,
                    "discovery_sources": [getattr(source, "value", str(source)) for source in device.discovery_sources],
                },
                handler=lambda canonical, _payload: self._ingest_device_local(device),
            )
            if not result.success:
                raise PermissionError(result.error or "Shared OperationsEngine denied discovery ingestion.")
            self.last_ingestion_mode = "AUTHORIZED_SIMULATED"
            return bool(result.output.get("result"))
        self.last_ingestion_mode = "LOCAL_IMPORT_OFFLINE"
        return self._ingest_device_local(device)

    def _ingest_device_local(self, device: DiscoveredDevice) -> bool:
        if not self.is_ip_authorized(device.management_ip):
            return False
        key = device.device_id
        if key in self.discovered_devices:
            existing = self.discovered_devices[key]
            for source in device.discovery_sources:
                if source not in existing.discovery_sources:
                    existing.discovery_sources.append(source)
            existing.confidence = min(1.0, existing.confidence + 0.1)
            if device.interfaces:
                existing.interfaces = device.interfaces
            if device.neighbors:
                existing.neighbors.extend(device.neighbors)
            return True
        self.discovered_devices[key] = device
        return True

    def build_topology(self, topology_engine=None, authorization_device_id: Optional[str] = None):
        """Build an on-demand topology; optionally authorize/audit the workflow."""
        if topology_engine is None:
            from ..topology.topology_engine import TopologyEngine
            topology_engine = TopologyEngine()
        if self.operations_engine is None:
            self.last_ingestion_mode = "LOCAL_IMPORT_OFFLINE"
            return topology_engine.build_topology(list(self.discovered_devices.values()))
        seed_id = authorization_device_id or self.authorization_device_id
        if not seed_id or not self.user_ctx:
            raise PermissionError("Shared topology building requires an authorized canonical seed device and UserContext.")
        result = execute_authorized_module_workflow(
            operations_engine=self.operations_engine,
            user_ctx=self.user_ctx,
            device_id=seed_id,
            module="network_discovery_topology",
            workflow="topology_build",
            classification=OperationClassification.READ_ONLY,
            parameters={"discovered_device_count": len(self.discovered_devices)},
            handler=lambda canonical, _payload: topology_engine.build_topology(list(self.discovered_devices.values())),
        )
        if not result.success:
            raise PermissionError(result.error or "Shared OperationsEngine denied topology build.")
        self.last_ingestion_mode = "AUTHORIZED_SIMULATED"
        return result.output.get("result")

    def discover_from_mock_environment(self) -> List[DiscoveredDevice]:
        """
        Discovers a complete multi-vendor network topology from mock devices.
        Topology includes:
        - Core Router (MikroTik CCR2004) -> Internet Gateway
        - Aggregation Switch (Cisco Catalyst 9300)
        - Access Switch (Huawei S5720)
        - OLT (Huawei MA5800-X7)
        - Customer ONT (Huawei HG8245H5)
        - Wireless AP (Ruijie RG-RAP2200E)
        - Outdoor Radio PTP Link (Ubiquiti Loco5AC)
        """
        # 1. Core Router (MikroTik)
        rtr_core = DiscoveredDevice(
            device_id="RTR-CORE-01",
            management_ip="10.0.0.1",
            hostname="core-rtr01.isp.net",
            vendor="MikroTik",
            model="CCR2004-16G-2S+",
            role=DeviceRole.ROUTER,
            mac_address="00:0C:42:01:00:01",
            firmware_version="RouterOS 7.15.2",
            discovery_sources=[DiscoverySource.ROUTEROS_API, DiscoverySource.MNDP],
            interfaces=[
                {"name": "sfp-sfpplus1", "status": "UP", "speed": "10Gbps", "ip": "10.0.0.1/30"},
                {"name": "ether1", "status": "UP", "speed": "1Gbps", "ip": "10.100.1.1/24"},
                {"name": "ether2", "status": "UP", "speed": "1Gbps", "ip": "10.200.1.1/24"}
            ],
            neighbors=[
                DiscoveredNeighbor(local_interface="sfp-sfpplus1", remote_device_id="SW-AGG-01", remote_interface="TenGigabitEthernet1/1/1", discovery_protocol=DiscoverySource.LLDP)
            ],
            health_status="HEALTHY",
            health_metrics={"cpu_load": 14, "free_memory_mb": 3400, "uptime": "42d 12h"}
        )

        # 2. Aggregation Switch (Cisco)
        sw_agg = DiscoveredDevice(
            device_id="SW-AGG-01",
            management_ip="10.0.0.2",
            hostname="agg-sw01.isp.net",
            vendor="Cisco",
            model="Catalyst 9300",
            role=DeviceRole.DISTRIBUTION_SWITCH,
            mac_address="00:1E:BD:02:00:01",
            firmware_version="IOS-XE 17.06.05",
            discovery_sources=[DiscoverySource.CDP, DiscoverySource.LLDP],
            interfaces=[
                {"name": "TenGigabitEthernet1/1/1", "status": "UP", "speed": "10Gbps"},
                {"name": "GigabitEthernet1/0/1", "status": "UP", "speed": "1Gbps"},
                {"name": "GigabitEthernet1/0/2", "status": "UP", "speed": "1Gbps"}
            ],
            neighbors=[
                DiscoveredNeighbor(local_interface="TenGigabitEthernet1/1/1", remote_device_id="RTR-CORE-01", remote_interface="sfp-sfpplus1", discovery_protocol=DiscoverySource.LLDP),
                DiscoveredNeighbor(local_interface="GigabitEthernet1/0/1", remote_device_id="SW-ACC-01", remote_interface="GE0/0/24", discovery_protocol=DiscoverySource.CDP),
                DiscoveredNeighbor(local_interface="GigabitEthernet1/0/2", remote_device_id="OLT-GPON-01", remote_interface="GE0/19/0", discovery_protocol=DiscoverySource.LLDP)
            ],
            health_status="HEALTHY",
            health_metrics={"cpu_load": 8, "free_memory_mb": 1800, "uptime": "112d 4h"}
        )

        # 3. Access Switch (Huawei)
        sw_acc = DiscoveredDevice(
            device_id="SW-ACC-01",
            management_ip="10.0.0.3",
            hostname="acc-sw01.isp.net",
            vendor="Huawei",
            model="S5720-28P-SI",
            role=DeviceRole.ACCESS_SWITCH,
            mac_address="48:57:02:03:00:01",
            firmware_version="VRP V200R019C00",
            discovery_sources=[DiscoverySource.LLDP],
            interfaces=[
                {"name": "GE0/0/24", "status": "UP", "speed": "1Gbps"},
                {"name": "GE0/0/1", "status": "UP", "speed": "1Gbps"},
                {"name": "GE0/0/2", "status": "UP", "speed": "1Gbps"}
            ],
            neighbors=[
                DiscoveredNeighbor(local_interface="GE0/0/24", remote_device_id="SW-AGG-01", remote_interface="GigabitEthernet1/0/1", discovery_protocol=DiscoverySource.LLDP),
                DiscoveredNeighbor(local_interface="GE0/0/1", remote_device_id="AP-CAMPUS-01", remote_interface="LAN1/PoE", discovery_protocol=DiscoverySource.LLDP),
                DiscoveredNeighbor(local_interface="GE0/0/2", remote_device_id="RADIO-PTP-01", remote_interface="eth0", discovery_protocol=DiscoverySource.LLDP)
            ],
            health_status="HEALTHY",
            health_metrics={"cpu_load": 12, "free_memory_mb": 412, "uptime": "65d 1h"}
        )

        # 4. Access Point (Ruijie)
        ap_campus = DiscoveredDevice(
            device_id="AP-CAMPUS-01",
            management_ip="10.0.0.50",
            hostname="ap-campus-01",
            vendor="Ruijie",
            model="RG-RAP2200(E)",
            role=DeviceRole.ACCESS_POINT,
            mac_address="00:D0:F8:50:00:01",
            firmware_version="ReyeeOS 1.22",
            discovery_sources=[DiscoverySource.LLDP, DiscoverySource.DHCP_LEASE],
            interfaces=[{"name": "LAN1/PoE", "status": "UP", "speed": "1Gbps"}],
            neighbors=[
                DiscoveredNeighbor(local_interface="LAN1/PoE", remote_device_id="SW-ACC-01", remote_interface="GE0/0/1", discovery_protocol=DiscoverySource.LLDP)
            ],
            health_status="HEALTHY",
            health_metrics={"client_count": 28, "channel_2g": 6, "channel_5g": 44, "uptime": "19d 8h"}
        )

        # 5. Outdoor Radio PTP (Ubiquiti)
        radio_ptp = DiscoveredDevice(
            device_id="RADIO-PTP-01",
            management_ip="10.0.0.60",
            hostname="ptp-tower-south",
            vendor="Ubiquiti",
            model="NanoStation 5AC Loco",
            role=DeviceRole.OUTDOOR_RADIO,
            mac_address="24:A4:3C:60:00:01",
            firmware_version="airOS 8.7.1",
            discovery_sources=[DiscoverySource.LLDP],
            interfaces=[{"name": "eth0", "status": "UP", "speed": "1Gbps"}],
            neighbors=[
                DiscoveredNeighbor(local_interface="eth0", remote_device_id="SW-ACC-01", remote_interface="GE0/0/2", discovery_protocol=DiscoverySource.LLDP)
            ],
            health_status="HEALTHY",
            health_metrics={"rssi_dbm": -56, "snr_db": 34, "noise_floor_dbm": -94, "throughput_mbps": 320}
        )

        # 6. OLT (Huawei)
        olt_gpon = DiscoveredDevice(
            device_id="OLT-GPON-01",
            management_ip="10.0.0.10",
            hostname="olt01.central.isp.net",
            vendor="Huawei",
            model="SmartAX MA5800-X7",
            role=DeviceRole.DISTRIBUTION_SWITCH,
            mac_address="48:57:02:10:00:01",
            firmware_version="MA5800 V100R019C10",
            discovery_sources=[DiscoverySource.LLDP, DiscoverySource.SNMP],
            interfaces=[
                {"name": "GE0/19/0", "status": "UP", "speed": "1Gbps"},
                {"name": "GPON0/1/0", "status": "UP", "speed": "2.5G/1.25G"}
            ],
            neighbors=[
                DiscoveredNeighbor(local_interface="GE0/19/0", remote_device_id="SW-AGG-01", remote_interface="GigabitEthernet1/0/2", discovery_protocol=DiscoverySource.LLDP),
                DiscoveredNeighbor(local_interface="GPON0/1/0:1", remote_device_id="ONT-CUST-101", remote_interface="PON", discovery_protocol=DiscoverySource.ACS_INVENTORY)
            ],
            health_status="HEALTHY",
            health_metrics={"total_onus": 128, "active_onus": 126, "los_alarms": 2}
        )

        # 7. Customer ONT (Huawei)
        ont_cust = DiscoveredDevice(
            device_id="ONT-CUST-101",
            management_ip="10.100.20.15",
            hostname="EchoLife HG8245H5",
            vendor="Huawei",
            model="HG8245H5",
            role=DeviceRole.ONT_ONU,
            mac_address="48:57:54:43:12:34",
            firmware_version="V5R019C20S125",
            discovery_sources=[DiscoverySource.ACS_INVENTORY],
            interfaces=[{"name": "PON", "status": "UP"}, {"name": "LAN1", "status": "UP", "speed": "1Gbps"}],
            neighbors=[
                DiscoveredNeighbor(local_interface="PON", remote_device_id="OLT-GPON-01", remote_interface="GPON0/1/0:1", discovery_protocol=DiscoverySource.ACS_INVENTORY)
            ],
            health_status="HEALTHY",
            health_metrics={"rx_power_dbm": -19.5, "tx_power_dbm": 2.3, "status": "O5_OPERATION"}
        )

        devs = [rtr_core, sw_agg, sw_acc, ap_campus, radio_ptp, olt_gpon, ont_cust]
        for d in devs:
            self.ingest_device(d)

        return list(self.discovered_devices.values())
