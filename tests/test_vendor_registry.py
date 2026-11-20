import unittest
from engine.vendors.registry import capability_status, vendor_capabilities

class VendorRegistryTests(unittest.TestCase):
    def test_unknown_vendor_is_not_claimed_supported(self):
        self.assertEqual(capability_status("unknown-vendor")["status"], "NOT IMPLEMENTED")
    def test_documented_only_vendor_has_no_adapter(self):
        status = capability_status("zte")
        self.assertEqual(status["status"], "DOCUMENTED ONLY")
        self.assertIsNone(status["adapter"])
    def test_registry_returns_copy(self):
        copy = vendor_capabilities()
        copy["mikrotik"]["connectors"].append("fake")
        self.assertNotIn("fake", vendor_capabilities()["mikrotik"]["connectors"])

class AdapterSafetyTests(unittest.TestCase):
    def test_ping_target_rejects_option_and_command_injection(self):
        from engine.adapters.base_adapter import validate_ping_parameters
        for target in ["-c 9", "10.0.0.1; reboot", "foo bar", "$(id)"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_ping_parameters(target, 3)
    def test_ping_count_is_bounded(self):
        from engine.adapters.base_adapter import validate_ping_parameters
        for count in [0, 11, -1, "bad", True]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                validate_ping_parameters("192.0.2.1", count)
    def test_unknown_adapter_fails_closed(self):
        from engine.adapters.factory import AdapterFactory
        from unittest.mock import Mock
        with self.assertRaises(ValueError):
            AdapterFactory.get_adapter("unregistered-vendor", Mock())
