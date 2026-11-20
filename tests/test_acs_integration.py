import unittest
from scripts.acs_integration.mock_connector import MockACSConnector

class TestMockACSIntegration(unittest.TestCase):
    def setUp(self):
        self.acs = MockACSConnector(simulation_mutation_authorizer=lambda action, device, params, classification: True)

    def test_unauthenticated_access_rejected(self):
        with self.assertRaises(PermissionError):
            self.acs.discover_devices()

    def test_authentication_success(self):
        self.assertTrue(self.acs.authenticate())
        self.assertTrue(self.acs.authenticated)

    def test_device_discovery(self):
        self.acs.authenticate()
        devices = self.acs.discover_devices()
        self.assertGreaterEqual(len(devices), 2)
        huawei_devs = self.acs.discover_devices({"manufacturer": "Huawei"})
        self.assertEqual(len(huawei_devs), 1)
        self.assertEqual(huawei_devs[0]["model_name"], "HG8245H5")

    def test_get_parameter_values(self):
        self.acs.authenticate()
        res = self.acs.get_parameter_values("HWTC12345678", ["Device.DeviceInfo.Manufacturer", "Device.Optical.Interface.1.RXPower"])
        self.assertEqual(res["Device.DeviceInfo.Manufacturer"], "Huawei")
        self.assertEqual(res["Device.Optical.Interface.1.RXPower"], -19.5)

    def test_set_parameter_values_and_job(self):
        self.acs.authenticate()
        params_to_set = {
            "Device.WiFi.SSID.1.SSID": "New_Fiber_SSID_5G",
            "Device.ManagementServer.PeriodicInformInterval": 43200
        }
        job = self.acs.set_parameter_values("HWTC12345678", params_to_set)
        self.assertIn("job_id", job)
        self.assertEqual(job["status"], "COMPLETED")
        
        # Verify value was updated in device parameter store
        updated = self.acs.get_parameter_values("HWTC12345678", ["Device.WiFi.SSID.1.SSID"])
        self.assertEqual(updated["Device.WiFi.SSID.1.SSID"], "New_Fiber_SSID_5G")

    def test_connection_request_and_reboot(self):
        self.acs.authenticate()
        self.assertTrue(self.acs.trigger_connection_request("HWTC12345678"))
        reboot_job = self.acs.reboot_device("HWTC12345678")
        self.assertEqual(reboot_job["command"], "Reboot")
        status = self.acs.get_job_status(reboot_job["job_id"])
        self.assertEqual(status["status"], "PENDING_CPE_CONTACT")

    def test_device_not_found(self):
        self.acs.authenticate()
        with self.assertRaises(KeyError):
            self.acs.get_parameter_values("NON_EXISTENT_DEVICE", ["Device.DeviceInfo.ModelName"])

    def test_audit_log_tracking(self):
        self.acs.authenticate()
        self.acs.discover_devices()
        self.assertGreater(len(self.acs.audit_log), 0)
        actions = [entry["action"] for entry in self.acs.audit_log]
        self.assertIn("MOCK_AUTHENTICATED", actions)
        self.assertIn("DEVICE_DISCOVERY", actions)
        auth_record = next(entry for entry in self.acs.audit_log if entry["action"] == "MOCK_AUTHENTICATED")
        self.assertFalse(auth_record["details"]["live_authentication"])

if __name__ == '__main__':
    unittest.main()
