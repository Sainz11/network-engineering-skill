import unittest
import os
import tempfile
import hashlib
from scripts.qc_engine import (
    QCTestEngine,
    DeviceIdentity,
    ProfileLoader,
    DecisionEngine,
    TestCatalog,
    TestStatus,
    FinalQCStatus,
    TestResult,
    QCReportGenerator,
    QCHistoryManager
)

class TestQCEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Tests use a dedicated approved history root and actual evidence artifacts.
        self.history_root = os.path.join(self.temp_dir, "history")
        self.evidence_dir = os.path.join(self.temp_dir, "evidence")
        os.makedirs(self.history_root, exist_ok=True)
        os.makedirs(self.evidence_dir, exist_ok=True)
        evidence_names = [
            "photo_1.jpg", "photo_2.jpg", "label.jpg", "boot.log", "led.jpg", "iperf.txt",
            "counters.txt", "omci_o5.txt", "optic_meter.jpg", "wifi_scan.png", "assoc.log",
            "assoc.txt", "b.log", "c.txt", "e.txt", "l.jpg", "negotiation.txt", "p1.jpg",
            "p2.jpg", "p3.jpg", "photo.jpg", "wifi.txt",
        ]
        for name in evidence_names:
            with open(os.path.join(self.evidence_dir, name), "wb") as evidence_file:
                evidence_file.write(b"test evidence artifact")
        self.engine = QCTestEngine(
            history_file=os.path.join(self.history_root, "qc_sessions_test.json"),
            history_root=self.history_root,
            evidence_dir=self.evidence_dir,
        )

    def test_profile_loader(self):
        loader = ProfileLoader()
        profile_hex = loader.get_profile("MikroTik", "RB750Gr3")
        self.assertIsNotNone(profile_hex)
        self.assertEqual(profile_hex["interfaces"]["count"], 5)
        self.assertIn("Gigabit", profile_hex["interfaces"]["speed"])

        profile_hap = loader.get_profile("MikroTik", "RB941-2nD")
        self.assertIsNotNone(profile_hap)
        self.assertIn("Fast Ethernet ONLY", profile_hap["interfaces"]["speed"])

        profile_huawei = loader.get_profile("Huawei", "HG8245H5")
        self.assertIsNotNone(profile_huawei)
        self.assertTrue(profile_huawei["optical_capabilities"]["is_pon"])
        self.assertEqual(profile_huawei["optical_capabilities"]["rx_power_min_dbm"], -27.0)

    def test_test_catalog_selection(self):
        catalog = TestCatalog()
        router_tests = catalog.get_applicable_tests("router")
        self.assertTrue(any(t.id == "ETH-01" for t in router_tests))
        # Optical PON test must NOT be applicable to pure router
        self.assertFalse(any(t.id == "OPT-01" for t in router_tests))

        ont_tests = catalog.get_applicable_tests("ont_onu")
        self.assertTrue(any(t.id == "OPT-01" for t in ont_tests))
        self.assertTrue(any(t.id == "ETH-01" for t in ont_tests))

    def test_decision_engine_rules(self):
        # 1. All mandatory pass -> PASS
        results_pass = [
            TestResult("PHYS-01", "Casing", "phys", TestStatus.PASS, mandatory=True, evidence_reference="photo_1.jpg", evidence_type="MANUAL_ARTIFACT", evidence_status="ARTIFACT_VERIFIED", evidence_sha256=hashlib.sha256(b"test evidence artifact").hexdigest()),
            TestResult("ETH-01", "Ethernet", "eth", TestStatus.PASS, mandatory=True, evidence_reference="photo_2.jpg", evidence_type="MANUAL_ARTIFACT", evidence_status="ARTIFACT_VERIFIED", evidence_sha256=hashlib.sha256(b"test evidence artifact").hexdigest())
        ]
        status, reason, findings = DecisionEngine.evaluate(results_pass)
        self.assertEqual(status, FinalQCStatus.PASS)

        # 2. Mandatory failure -> FAIL
        results_fail = [
            TestResult("PHYS-01", "Casing", "phys", TestStatus.PASS, mandatory=True, evidence_reference="photo_1.jpg", evidence_type="MANUAL_ARTIFACT", evidence_status="ARTIFACT_VERIFIED", evidence_sha256=hashlib.sha256(b"test evidence artifact").hexdigest()),
            TestResult("ETH-01", "Ethernet", "eth", TestStatus.FAIL, mandatory=True, measured_value="CRC Errors")
        ]
        status, reason, findings = DecisionEngine.evaluate(results_fail)
        self.assertEqual(status, FinalQCStatus.FAIL)
        self.assertGreater(len(findings), 0)

        # 3. Missing mandatory test -> NEEDS_REVIEW
        results_missing = [
            TestResult("PHYS-01", "Casing", "phys", TestStatus.PASS, mandatory=True, evidence_reference="photo_1.jpg", evidence_type="MANUAL_ARTIFACT", evidence_status="ARTIFACT_VERIFIED", evidence_sha256=hashlib.sha256(b"test evidence artifact").hexdigest()),
            TestResult("ETH-01", "Ethernet", "eth", TestStatus.NOT_TESTED, mandatory=True)
        ]
        status, reason, findings = DecisionEngine.evaluate(results_missing)
        self.assertEqual(status, FinalQCStatus.NEEDS_REVIEW)

        # 4. Optional failure only -> PASS_WITH_NOTES
        results_opt_fail = [
            TestResult("PHYS-01", "Casing", "phys", TestStatus.PASS, mandatory=True, evidence_reference="photo_1.jpg", evidence_type="MANUAL_ARTIFACT", evidence_status="ARTIFACT_VERIFIED", evidence_sha256=hashlib.sha256(b"test evidence artifact").hexdigest()),
            TestResult("MGMT-01", "Remote Mgmt", "mgmt", TestStatus.FAIL, mandatory=False)
        ]
        status, reason, findings = DecisionEngine.evaluate(results_opt_fail)
        self.assertEqual(status, FinalQCStatus.PASS_WITH_NOTES)

    def test_model_specific_optical_threshold_validation(self):
        dev = DeviceIdentity(
            manufacturer="Huawei",
            model="HG8245H5",
            serial_number="HWTC48601111",
            firmware_version="V5R019C20S125"
        )
        
        # Scenario A: Valid optical power (-19.2 dBm is within [-27, -8])
        measurements_ok = {
            "PHYS-01": {"value": "PASS", "evidence_ref": "photo_1.jpg"},
            "PHYS-02": {"value": "PASS", "evidence_ref": "photo_2.jpg"},
            "PHYS-03": {"value": "PASS", "evidence_ref": "label.jpg"},
            "PWR-01": {"value": "PASS", "evidence_ref": "boot.log"},
            "PWR-02": {"value": "PASS", "evidence_ref": "led.jpg"},
            "ETH-01": {"value": "1000M", "evidence_ref": "iperf.txt"},
            "ETH-02": {"value": "0 errors", "evidence_ref": "counters.txt"},
            "OPT-01": {"value": "PASS", "evidence_ref": "omci_o5.txt"},
            "OPT-02": {"value": -19.2, "evidence_ref": "optic_meter.jpg"},
            "WIFI-01": {"value": "PASS", "evidence_ref": "wifi_scan.png"},
            "WLAN-02": {"value": "PASS", "evidence_ref": "assoc.log"}
        }
        report = self.engine.run_qc_session(dev, measurements_ok, technician="Tech_Alice")
        self.assertEqual(report.final_status, FinalQCStatus.PASS)

        # Scenario B: Weak optical signal (-29.5 dBm is below -27.0 dBm)
        measurements_weak = dict(measurements_ok)
        measurements_weak["OPT-02"] = {"value": -29.5, "evidence_ref": "optic_meter.jpg"}
        report_fail = self.engine.run_qc_session(dev, measurements_weak, technician="Tech_Alice")
        self.assertEqual(report_fail.final_status, FinalQCStatus.FAIL)
        opt_res = [r for r in report_fail.results if r.test_id == "OPT-02"][0]
        self.assertEqual(opt_res.status, TestStatus.FAIL)

    def test_model_specific_fast_ethernet_hap_lite(self):
        # RB941-2nD (hAP lite) only has 10/100M Fast Ethernet ports.
        # Measuring 100M must PASS and not be flagged as a 1G failure.
        dev = DeviceIdentity(
            manufacturer="MikroTik",
            model="RB941-2nD",
            serial_number="HE9912001",
            firmware_version="6.49.10"
        )
        measurements = {
            "PHYS-01": {"value": "PASS", "evidence_ref": "photo.jpg"},
            "PHYS-02": {"value": "PASS", "evidence_ref": "photo.jpg"},
            "PHYS-03": {"value": "PASS", "evidence_ref": "photo.jpg"},
            "PWR-01": {"value": "PASS", "evidence_ref": "boot.log"},
            "PWR-02": {"value": "PASS", "evidence_ref": "led.jpg"},
            "ETH-01": {"value": "100M", "evidence_ref": "negotiation.txt"},
            "ETH-02": {"value": "PASS", "evidence_ref": "counters.txt"},
            "WIFI-01": {"value": "PASS", "evidence_ref": "wifi.txt"},
            "WLAN-02": {"value": "PASS", "evidence_ref": "assoc.txt"}
        }
        report = self.engine.run_qc_session(dev, measurements, technician="Tech_Bob")
        eth_res = [r for r in report.results if r.test_id == "ETH-01"][0]
        self.assertEqual(eth_res.status, TestStatus.PASS)
        self.assertEqual(report.final_status, FinalQCStatus.PASS)


    def test_model_specific_ethernet_rate_outside_profile_fails(self):
        dev = DeviceIdentity(
            manufacturer="MikroTik", model="RB941-2nD", serial_number="SN-HAP-LITE"
        )
        report = self.engine.run_qc_session(
            dev,
            {"ETH-01": {"value": "1000M", "evidence_ref": "negotiation.txt"}},
            technician="QC-Test",
        )
        eth = next(item for item in report.results if item.test_id == "ETH-01")
        self.assertEqual(eth.status, TestStatus.FAIL)
        self.assertIn("not supported", eth.notes)

    def test_ambiguous_ethernet_rate_never_passes(self):
        dev = DeviceIdentity(
            manufacturer="MikroTik", model="RB941-2nD", serial_number="SN-HAP-LITE-AMBIG"
        )
        report = self.engine.run_qc_session(
            dev,
            {"ETH-01": {"value": "FAST", "status": "PASS", "evidence_ref": "negotiation.txt"}},
            technician="QC-Test",
        )
        eth = next(item for item in report.results if item.test_id == "ETH-01")
        self.assertEqual(eth.status, TestStatus.NEEDS_REVIEW)

    def test_report_generation(self):
        dev = DeviceIdentity("MikroTik", "RB750Gr3", "SN123456")
        measurements = {
            "PHYS-01": {"value": "PASS", "evidence_ref": "p1.jpg"},
            "PHYS-02": {"value": "PASS", "evidence_ref": "p2.jpg"},
            "PHYS-03": {"value": "PASS", "evidence_ref": "p3.jpg"},
            "PWR-01": {"value": "PASS", "evidence_ref": "b.log"},
            "PWR-02": {"value": "PASS", "evidence_ref": "l.jpg"},
            "ETH-01": {"value": "1000M", "evidence_ref": "e.txt"},
            "ETH-02": {"value": "PASS", "evidence_ref": "c.txt"}
        }
        report = self.engine.run_qc_session(dev, measurements, technician="Tech_Carol")
        gen = QCReportGenerator(report)

        # Test JSON report
        json_path = os.path.join(self.temp_dir, "report.json")
        gen.generate_json(json_path)
        self.assertTrue(os.path.exists(json_path))

        # Test CSV report
        csv_path = os.path.join(self.temp_dir, "report.csv")
        gen.generate_csv(csv_path)
        self.assertTrue(os.path.exists(csv_path))

        # Test PDF report (ReportLab is installed)
        pdf_path = os.path.join(self.temp_dir, "report.pdf")
        pdf_success = gen.generate_pdf(pdf_path)
        self.assertTrue(pdf_success)
        self.assertTrue(os.path.exists(pdf_path))

        # XLSX includes evidence traceability and stores formula-like text safely.
        from scripts.qc_engine.report_generator import OPENPYXL_AVAILABLE
        self.assertTrue(OPENPYXL_AVAILABLE)
        report.results[0].test_name = '=HYPERLINK("https://example.invalid","open")'
        gen.generate_csv(csv_path)
        with open(csv_path, "r", encoding="utf-8") as csv_file:
            self.assertIn("'=HYPERLINK", csv_file.read())
        xlsx_path = os.path.join(self.temp_dir, "report.xlsx")
        self.assertTrue(gen.generate_xlsx(xlsx_path))
        from openpyxl import load_workbook
        workbook = load_workbook(xlsx_path, data_only=False)
        result_sheet = workbook["Test Results"]
        self.assertEqual(result_sheet["B2"].data_type, "s")
        self.assertTrue(result_sheet["B2"].value.startswith("'="))
        self.assertIn("Evidence SHA256", [cell.value for cell in result_sheet[1]])
        summary_sheet = workbook["QC Summary"]
        self.assertEqual(summary_sheet["B6"].value, report.workflow_status)

    def test_qc_history_tracking(self):
        hist_file = os.path.join(self.temp_dir, "qc_hist.json")
        mgr = QCHistoryManager(hist_file, allowed_root=self.temp_dir)
        mgr.record_session({
            "session_id": "QC-TEST-001",
            "device": {"manufacturer": "MikroTik", "model": "RB750Gr3", "serial_number": "SN001"},
            "final_status": "PASS"
        })
        mgr.record_session({
            "session_id": "QC-TEST-002",
            "device": {"manufacturer": "MikroTik", "model": "RB750Gr3", "serial_number": "SN002"},
            "final_status": "FAIL"
        })
        stats = mgr.get_summary_statistics()
        self.assertEqual(stats["total_inspections"], 2)
        self.assertEqual(stats["status_counts"]["PASS"], 1)
        self.assertEqual(stats["status_counts"]["FAIL"], 1)

if __name__ == '__main__':
    unittest.main()
