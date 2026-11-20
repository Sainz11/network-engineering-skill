from typing import List, Dict, Any, Optional
from .models import DeviceIdentity, TestItem, TestResult, TestStatus, Severity

# Standard Test Catalog definitions
STANDARD_TESTS = [
    TestItem(
        id="PHYS-01",
        name="Physical Enclosure & Casing",
        category="physical_inspection",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Inspect housing for cracks, deep gouges, tampering, water damage, or damaged seals."
    ),
    TestItem(
        id="PHYS-02",
        name="Ports & Connector Integrity",
        category="physical_inspection",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Check RJ45, SFP cages, optical SC/APC ports, power jacks, and grounding terminals for bent pins or debris."
    ),
    TestItem(
        id="PHYS-03",
        name="Serial & Model Label Legibility",
        category="physical_inspection",
        mandatory=True,
        severity=Severity.MAJOR,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Verify MAC/Serial label is intact, matches firmware reporting, and is legible."
    ),
    TestItem(
        id="PWR-01",
        name="Power-on & Boot Initialization",
        category="power_and_boot",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Device completes cold boot sequence without reboot loops, kernel panics, or buzzer alarms."
    ),
    TestItem(
        id="PWR-02",
        name="System LED Status Indications",
        category="power_and_boot",
        mandatory=True,
        severity=Severity.MAJOR,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Power, Status, and Interface LEDs operate normally according to manufacturer state table."
    ),
    TestItem(
        id="ETH-01",
        name="Ethernet Link Negotiation & Speed",
        category="ethernet",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Interfaces negotiate rated speed (100M/1G/10G) as defined in model profile without speed drops."
    ),
    TestItem(
        id="ETH-02",
        name="Ethernet Error Counters & Frame Loss",
        category="ethernet",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["router", "switch", "ont_onu", "access_point", "outdoor_radio", "microwave", "modem"],
        description="Port counters maintain 0 CRC, 0 frame errors, and 0 drop errors under test traffic."
    ),
    TestItem(
        id="OPT-01",
        name="PON Registration / Optical Link",
        category="ont_onu_and_modem",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["ont_onu"],
        description="ONT registers to OLT, establishes State O5 (Operation State), with LOID/SN accepted."
    ),
    TestItem(
        id="OPT-02",
        name="Optical Power RX / TX Levels",
        category="ont_onu_and_modem",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["ont_onu"],
        description="Optical RX/TX power levels fall strictly within vendor/operator specifications."
    ),
    TestItem(
        id="WIFI-01",
        name="Wireless RF Radio Beaconing & SSID",
        category="wireless_ap",
        mandatory=True,
        severity=Severity.MAJOR,
        applicable_categories=["access_point", "ont_onu"],
        description="Radios (2.4GHz / 5GHz) broadcast configured SSIDs without beacon drops."
    ),
    TestItem(
        id="WLAN-02",
        name="Client Association & WPA Authentication",
        category="wireless_ap",
        mandatory=True,
        severity=Severity.MAJOR,
        applicable_categories=["access_point", "ont_onu"],
        description="Test station associates, completes 4-way WPA2/WPA3 handshake, and obtains DHCP lease."
    ),
    TestItem(
        id="RAD-01",
        name="Outdoor Wireless Link Registration & RSSI",
        category="outdoor_radio",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["outdoor_radio"],
        description="Radio associates with master/AP, RSSI/CINR within expected path budget margin."
    ),
    TestItem(
        id="UWIRE-01",
        name="Microwave Backhaul RSL & Modulation",
        category="microwave",
        mandatory=True,
        severity=Severity.CRITICAL,
        applicable_categories=["microwave"],
        description="Backhaul modem achieves target RSL, zero IDU/ODU alarms, and stable target modulation."
    ),
    TestItem(
        id="MGMT-01",
        name="Remote Management & CWMP / TR-069 Check",
        category="routing_and_switching",
        mandatory=False,
        severity=Severity.MINOR,
        applicable_categories=["router", "ont_onu", "switch", "access_point"],
        description="Device responds to SSH, HTTPS, or TR-069 Inform without authentication failure."
    ),
]

class TestCatalog:
    __test__ = False
    def __init__(self, items: Optional[List[TestItem]] = None):
        self.items = items or list(STANDARD_TESTS)

    def get_applicable_tests(self, device_category: str, profile: Optional[Dict[str, Any]] = None) -> List[TestItem]:
        applicable = []
        for item in self.items:
            cat = device_category.lower()
            if cat in item.applicable_categories:
                # If device profile specifies supported_test_categories or capabilities
                if profile:
                    # check optical capabilities
                    if item.category == "ont_onu_and_modem" and not profile.get("optical_capabilities", {}).get("is_pon", False) and cat != "ont_onu":
                        continue
                    # check wireless capabilities
                    if item.category == "wireless_ap" and not profile.get("wireless_bands"):
                        continue
                applicable.append(item)
        return applicable
