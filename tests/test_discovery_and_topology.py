import unittest
import os
import tempfile
from engine.discovery.models import DiscoveredDevice, DiscoveredNeighbor, DiscoverySource, LinkConfidence, DeviceRole
from engine.discovery.neighbor_parser import NeighborParser
from engine.discovery.collector import DiscoveryCollector
from engine.topology.topology_engine import TopologyEngine
from engine.topology.visualizer import TopologyVisualizer
from engine.health.analyzer import NetworkHealthAnalyzer

class TestDiscoveryAndTopology(unittest.TestCase):
    def setUp(self):
        self.collector = DiscoveryCollector(authorized_subnets=["10.0.0.0/16", "192.168.1.0/24"])
        self.temp_dir = tempfile.mkdtemp()

    def test_neighbor_parser_mikrotik(self):
        raw_mndp = """
        interface=ether1 mac-address=00:1E:BD:02:00:01 identity="SW-AGG-01" address=10.0.0.2 interface-name="TenGigabitEthernet1/1/1"
        interface=ether2 mac-address=48:57:02:10:00:01 identity="OLT-GPON-01" address=10.0.0.10
        """
        neighbors = NeighborParser.parse_mikrotik_neighbors(raw_mndp)
        self.assertEqual(len(neighbors), 2)
        self.assertEqual(neighbors[0].remote_hostname, "SW-AGG-01")
        self.assertEqual(neighbors[0].local_interface, "ether1")
        self.assertEqual(neighbors[0].remote_interface, "TenGigabitEthernet1/1/1")

    def test_neighbor_parser_cisco_cdp(self):
        raw_cdp = """
        -------------------------
        Device ID: SW-ACC-01.isp.net
        Entry address(es): 
          IP address: 10.0.0.3
        Platform: cisco WS-C2960X-48TS-L,  Capabilities: Switch IGMP 
        Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet0/0/24
        Holdtime : 142 sec
        -------------------------
        """
        neighbors = NeighborParser.parse_cisco_cdp_neighbors(raw_cdp)
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(neighbors[0].remote_device_id, "SW-ACC-01")
        self.assertEqual(neighbors[0].local_interface, "GigabitEthernet1/0/1")
        self.assertEqual(neighbors[0].remote_interface, "GigabitEthernet0/0/24")

    def test_neighbor_parser_standard_lldp(self):
        raw_lldp = """
        Local Intf       Chassis ID      Port ID       System Name
        -------------------------------------------------------------
        GE0/0/1          00d0-f850-0001  LAN1/PoE      AP-CAMPUS-01
        GE0/0/2          24a4-3c60-0001  eth0          RADIO-PTP-01
        """
        neighbors = NeighborParser.parse_standard_lldp(raw_lldp)
        self.assertEqual(len(neighbors), 2)
        self.assertEqual(neighbors[0].remote_device_id, "AP-CAMPUS-01")
        self.assertEqual(neighbors[0].remote_interface, "LAN1/PoE")
        self.assertEqual(neighbors[1].remote_device_id, "RADIO-PTP-01")

    def test_discovery_collector_authorization(self):
        # In authorized range 10.0.0.0/16
        dev_auth = DiscoveredDevice("DEV-01", "10.0.1.5", "rtr.local", "MikroTik")
        self.assertTrue(self.collector.ingest_device(dev_auth))

        # Outside authorized range (e.g. 8.8.8.8)
        dev_unauth = DiscoveredDevice("DEV-ROGUE", "8.8.8.8", "public.dns", "Google")
        self.assertFalse(self.collector.ingest_device(dev_unauth))

    def test_topology_engine_corroboration_and_confidence(self):
        # Dev A sees Dev B on Port 1 -> Dev B sees Dev A on Port 2 (Bidirectional = VERIFIED)
        dev_a = DiscoveredDevice(
            device_id="DEV-A", management_ip="10.0.0.10", hostname="Switch-A", vendor="Cisco",
            neighbors=[DiscoveredNeighbor("Gi0/1", "DEV-B", "Gi0/2", discovery_protocol=DiscoverySource.LLDP)]
        )
        dev_b = DiscoveredDevice(
            device_id="DEV-B", management_ip="10.0.0.20", hostname="Switch-B", vendor="Cisco",
            neighbors=[DiscoveredNeighbor("Gi0/2", "DEV-A", "Gi0/1", discovery_protocol=DiscoverySource.LLDP)]
        )
        # Dev C is only seen unidirectionally by Dev B (Unidirectional = INFERRED)
        dev_c = DiscoveredDevice(
            device_id="DEV-C", management_ip="10.0.0.30", hostname="AP-C", vendor="Ruijie",
            neighbors=[]
        )
        dev_b.neighbors.append(DiscoveredNeighbor("Gi0/3", "DEV-C", "eth0", discovery_protocol=DiscoverySource.LLDP))

        engine = TopologyEngine()
        devs, links = engine.build_topology([dev_a, dev_b, dev_c])

        self.assertEqual(len(devs), 3)
        self.assertEqual(len(links), 2)

        # Link A-B must be VERIFIED
        link_ab = [l for l in links if ("DEV-A" in [l.source_device_id, l.target_device_id] and "DEV-B" in [l.source_device_id, l.target_device_id])][0]
        self.assertEqual(link_ab.confidence, LinkConfidence.VERIFIED)

        # Link B-C must be INFERRED
        link_bc = [l for l in links if ("DEV-B" in [l.source_device_id, l.target_device_id] and "DEV-C" in [l.source_device_id, l.target_device_id])][0]
        self.assertEqual(link_bc.confidence, LinkConfidence.INFERRED)

    def test_bidirectional_acs_inventory_is_not_verified_physical_adjacency(self):
        dev_a = DiscoveredDevice(
            device_id="A", management_ip="10.0.0.1", hostname="A", vendor="Vendor",
            neighbors=[DiscoveredNeighbor("p1", "B", "p2", discovery_protocol=DiscoverySource.ACS_INVENTORY)],
        )
        dev_b = DiscoveredDevice(
            device_id="B", management_ip="10.0.0.2", hostname="B", vendor="Vendor",
            neighbors=[DiscoveredNeighbor("p2", "A", "p1", discovery_protocol=DiscoverySource.ACS_INVENTORY)],
        )
        _, links = TopologyEngine().build_topology([dev_a, dev_b])
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].confidence, LinkConfidence.INFERRED)

    def test_hostname_resolution_requires_exact_match(self):
        dev_a = DiscoveredDevice(
            device_id="A", management_ip="10.0.0.1", hostname="Switch-A", vendor="Vendor",
            neighbors=[DiscoveredNeighbor("p1", "Switch", "p2", discovery_protocol=DiscoverySource.LLDP)],
        )
        dev_b = DiscoveredDevice(
            device_id="B", management_ip="10.0.0.2", hostname="Switch-B", vendor="Vendor",
            neighbors=[DiscoveredNeighbor("p2", "A", "p1", discovery_protocol=DiscoverySource.LLDP)],
        )
        _, links = TopologyEngine().build_topology([dev_a, dev_b])
        self.assertFalse(any(link.confidence == LinkConfidence.VERIFIED for link in links))

    def test_mock_multi_vendor_topology_and_visualization(self):
        collector = DiscoveryCollector()
        discovered = collector.discover_from_mock_environment()
        self.assertEqual(len(discovered), 7)

        top_engine = TopologyEngine()
        devs, links = top_engine.build_topology(discovered)
        self.assertGreaterEqual(len(links), 6)

        data = top_engine.export_topology_data()
        self.assertEqual(len(data["devices"]), 7)

        # Test SVG generation
        svg_file = os.path.join(self.temp_dir, "topology.svg")
        vis = TopologyVisualizer(data)
        vis.generate_svg(svg_file)
        self.assertTrue(os.path.exists(svg_file))
        with open(svg_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("<svg", content)
        self.assertIn("RTR-CORE-01", content)
        self.assertIn("SW-AGG-01", content)

        # Test HTML viewer generation
        html_file = os.path.join(self.temp_dir, "topology.html")
        vis.generate_html_viewer(html_file)
        self.assertTrue(os.path.exists(html_file))

    def test_network_health_analysis(self):
        # 1. Healthy device
        d_healthy = DiscoveredDevice("D1", "10.0.0.1", "core", "MikroTik", health_metrics={"cpu_load": 15, "free_memory_mb": 512})
        h1 = NetworkHealthAnalyzer.analyze_device_health(d_healthy)
        self.assertEqual(h1["health_status"], "HEALTHY")
        self.assertEqual(len(h1["anomalies"]), 0)

        # 2. Critical CPU
        d_hot = DiscoveredDevice("D2", "10.0.0.2", "sw", "Cisco", health_metrics={"cpu_load": 92})
        h2 = NetworkHealthAnalyzer.analyze_device_health(d_hot)
        self.assertEqual(h2["health_status"], "CRITICAL")
        self.assertTrue(any("High CPU" in a for a in h2["anomalies"]))

        # 3. Optical Attenuation Fault
        d_ont = DiscoveredDevice("D3", "10.0.0.3", "ont", "Huawei", health_metrics={"rx_power_dbm": -29.2})
        h3 = NetworkHealthAnalyzer.analyze_device_health(d_ont)
        self.assertEqual(h3["health_status"], "CRITICAL")
        self.assertTrue(any("Optical power attenuation fault" in a for a in h3["anomalies"]))

        # 4. Summary generator
        summary = NetworkHealthAnalyzer.generate_health_summary([d_healthy, d_hot, d_ont])
        self.assertEqual(summary["total_devices"], 3)
        self.assertEqual(summary["status_breakdown"]["HEALTHY"], 1)
        self.assertEqual(summary["status_breakdown"]["CRITICAL"], 2)
        self.assertEqual(summary["overall_health"], "CRITICAL")

if __name__ == '__main__':
    unittest.main()
