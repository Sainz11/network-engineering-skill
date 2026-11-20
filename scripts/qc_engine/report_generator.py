import os
import json
import csv
import tempfile
from typing import Optional
from xml.sax.saxutils import escape as xml_escape

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Font, PatternFill
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False
from .models import QCReportData

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class QCReportGenerator:
    def __init__(self, data: QCReportData):
        self.data = data

    def to_dict(self) -> dict:
        return {
            "session_id": self.data.session_id,
            "qc_date": self.data.qc_date,
            "technician": self.data.technician,
            "test_environment": self.data.test_environment,
            "workflow_status": self.data.workflow_status,
            "device": {
                "manufacturer": self.data.device.manufacturer,
                "model": self.data.device.model,
                "serial_number": self.data.device.serial_number,
                "mac_address": self.data.device.mac_address,
                "hardware_revision": self.data.device.hardware_revision,
                "firmware_version": self.data.device.firmware_version,
                "device_category": self.data.device.device_category,
            },
            "final_status": self.data.final_status.value,
            "status_reason": self.data.status_reason,
            "findings": self.data.findings,
            "reviewer": self.data.reviewer,
            "approval_date": self.data.approval_date,
            "notes": self.data.notes,
            "results": [
                {
                    "test_id": r.test_id,
                    "test_name": r.test_name,
                    "category": r.category,
                    "status": r.status.value,
                    "mandatory": r.mandatory,
                    "measured_value": str(r.measured_value) if r.measured_value is not None else "",
                    "expected_threshold": r.expected_threshold or "",
                    "threshold_source": r.threshold_source or "",
                    "evidence_reference": r.evidence_reference or "",
                    "evidence_type": r.evidence_type or "",
                    "evidence_status": r.evidence_status or "",
                    "evidence_sha256": r.evidence_sha256 or "",
                    "instrument_id": r.instrument_id or "",
                    "evidence_attestation": r.evidence_attestation or "",
                    "notes": r.notes or ""
                }
                for r in self.data.results
            ]
        }

    def generate_json(self, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def generate_csv(self, output_path: str):
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            safe = self._safe_spreadsheet_value
            writer.writerow([safe("QC Session ID"), safe(self.data.session_id)])
            writer.writerow([safe("Date"), safe(self.data.qc_date)])
            writer.writerow([safe("Technician"), safe(self.data.technician)])
            writer.writerow([safe("Device"), safe(f"{self.data.device.manufacturer} {self.data.device.model}")])
            writer.writerow([safe("Serial Number"), safe(self.data.device.serial_number)])
            writer.writerow([safe("Firmware"), safe(self.data.device.firmware_version or "")])
            writer.writerow([safe("Final QC Status"), safe(self.data.final_status.value)])
            writer.writerow([safe("Status Reason"), safe(self.data.status_reason)])
            writer.writerow([])
            writer.writerow([safe(value) for value in ["Test ID", "Test Name", "Category", "Mandatory", "Status", "Measured", "Expected Threshold", "Threshold Source", "Evidence Ref", "Evidence Type", "Evidence Status", "Evidence SHA256", "Instrument ID", "Manual Attestation", "Notes"]])
            for r in self.data.results:
                writer.writerow([safe(value) for value in [
                    r.test_id,
                    r.test_name,
                    r.category,
                    "YES" if r.mandatory else "NO",
                    r.status.value,
                    str(r.measured_value) if r.measured_value is not None else "",
                    r.expected_threshold or "",
                    r.threshold_source or "",
                    r.evidence_reference or "",
                    r.evidence_type or "",
                    r.evidence_status or "",
                    r.evidence_sha256 or "",
                    r.instrument_id or "",
                    r.evidence_attestation or "",
                    r.notes or ""
                ]])

    @staticmethod
    def _safe_spreadsheet_value(value):
        """Prevent untrusted text from being interpreted as an Excel formula."""
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
            return "'" + value
        return value

    def generate_xlsx(self, output_path: str) -> bool:
        """Create an atomic XLSX report with evidence provenance and safe text cells."""
        if not OPENPYXL_AVAILABLE:
            return False
        output_path = os.path.abspath(output_path)
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)

        workbook = Workbook()
        summary = workbook.active
        summary.title = "QC Summary"
        summary_rows = [
            ("Session ID", self.data.session_id),
            ("QC Date", self.data.qc_date),
            ("Technician", self.data.technician),
            ("Test Environment", self.data.test_environment),
            ("Workflow Status", self.data.workflow_status),
            ("Final Status", self.data.final_status.value),
            ("Status Reason", self.data.status_reason),
            ("Manufacturer", self.data.device.manufacturer),
            ("Model", self.data.device.model),
            ("Serial Number", self.data.device.serial_number),
            ("Firmware", self.data.device.firmware_version or ""),
            ("Reviewer", self.data.reviewer or ""),
        ]
        summary.append(("Field", "Value"))
        for row in summary_rows:
            summary.append(tuple(self._safe_spreadsheet_value(value) for value in row))

        results = workbook.create_sheet("Test Results")
        headers = [
            "Test ID", "Test Name", "Category", "Mandatory", "Status", "Measured Value",
            "Expected Threshold", "Threshold Source", "Evidence Reference", "Evidence Type",
            "Evidence Status", "Evidence SHA256", "Instrument ID", "Manual Attestation", "Notes",
        ]
        results.append(headers)
        for result in self.data.results:
            values = [
                result.test_id, result.test_name, result.category, "YES" if result.mandatory else "NO",
                result.status.value, "" if result.measured_value is None else str(result.measured_value),
                result.expected_threshold or "", result.threshold_source or "", result.evidence_reference or "",
                result.evidence_type or "", result.evidence_status or "", result.evidence_sha256 or "",
                result.instrument_id or "", result.evidence_attestation or "", result.notes or "",
            ]
            results.append(tuple(self._safe_spreadsheet_value(value) for value in values))

        header_fill = PatternFill(fill_type="solid", fgColor="17365D")
        for sheet in (summary, results):
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
            for cell in sheet[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = header_fill
            for column_cells in sheet.columns:
                width = min(max(len(str(cell.value or "")) for cell in column_cells) + 2, 60)
                sheet.column_dimensions[column_cells[0].column_letter].width = max(12, width)

        fd, temp_path = tempfile.mkstemp(prefix=".qc-report-", suffix=".xlsx", dir=output_dir)
        os.close(fd)
        try:
            workbook.save(temp_path)
            with open(temp_path, "rb") as stream:
                os.fsync(stream.fileno())
            os.replace(temp_path, output_path)
        finally:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
        return True

    def generate_pdf(self, output_path: str) -> bool:
        if not REPORTLAB_AVAILABLE:
            return False
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        title_style = styles["Heading1"]
        h2_style = styles["Heading2"]
        body_style = styles["Normal"]

        story.append(Paragraph(f"Device Quality Control Inspection Report", title_style))
        story.append(Paragraph(
            f"<b>Session ID:</b> {xml_escape(str(self.data.session_id))} | "
            f"<b>Date:</b> {xml_escape(str(self.data.qc_date))} | "
            f"<b>Technician:</b> {xml_escape(str(self.data.technician))}", body_style
        ))
        story.append(Paragraph(f"<b>Workflow Status:</b> {xml_escape(str(self.data.workflow_status))}", body_style))
        story.append(Spacer(1, 10))

        # Status badge summary
        status_color = colors.green if self.data.final_status.value == "PASS" else (colors.orange if "PASS" in self.data.final_status.value else colors.red)
        story.append(Paragraph(f"<b>FINAL QC STATUS:</b> <font color='{status_color.hexval()}'>{self.data.final_status.value}</font>", h2_style))
        story.append(Paragraph(f"<b>Assessment:</b> {xml_escape(str(self.data.status_reason))}", body_style))
        story.append(Spacer(1, 12))

        # Device info table
        dev_data = [
            ["Manufacturer", self.data.device.manufacturer, "Model", self.data.device.model],
            ["Serial Number", self.data.device.serial_number, "Hardware Rev", self.data.device.hardware_revision or "N/A"],
            ["MAC Address", self.data.device.mac_address or "N/A", "Firmware", self.data.device.firmware_version or "N/A"],
            ["Category", self.data.device.device_category, "Environment", self.data.test_environment]
        ]
        t_dev = Table(dev_data, colWidths=[100, 170, 100, 170])
        t_dev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        story.append(t_dev)
        story.append(Spacer(1, 14))

        # Test Results Table
        table_rows = [["ID", "Category", "Test Name", "Mandatory", "Result", "Measured", "Criteria"]]
        for r in self.data.results:
            table_rows.append([
                r.test_id,
                r.category[:12],
                r.test_name[:24],
                "YES" if r.mandatory else "NO",
                r.status.value,
                str(r.measured_value)[:15] if r.measured_value is not None else "-",
                (r.expected_threshold or "")[:20]
            ])
        t_results = Table(table_rows, colWidths=[40, 75, 155, 55, 65, 75, 75])
        t_results.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.navy),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ]))
        story.append(t_results)

        if self.data.findings:
            story.append(Spacer(1, 14))
            story.append(Paragraph("<b>QC Findings & Discrepancies:</b>", h2_style))
            for finding in self.data.findings:
                story.append(Paragraph(xml_escape(f"• {finding}"), body_style))

        provenance = [result for result in self.data.results if any((
            result.evidence_reference, result.evidence_type, result.evidence_status,
            result.evidence_sha256, result.instrument_id, result.evidence_attestation,
        ))]
        if provenance:
            story.append(Spacer(1, 14))
            story.append(Paragraph("<b>Evidence & Instrument Traceability:</b>", h2_style))
            evidence_style = ParagraphStyle("EvidenceTrace", parent=body_style, fontSize=7, leading=9)
            for result in provenance:
                details = (
                    f"{result.test_id} | type={result.evidence_type or 'N/A'} | "
                    f"status={result.evidence_status or 'N/A'} | "
                    f"reference={result.evidence_reference or 'N/A'} | "
                    f"SHA256={result.evidence_sha256 or 'N/A'} | "
                    f"instrument={result.instrument_id or 'N/A'} | "
                    f"manual_attestation={result.evidence_attestation or 'N/A'}"
                )
                story.append(Paragraph(xml_escape(details), evidence_style))

        doc.build(story)
        return True
