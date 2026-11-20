import json
import os
from html import escape as html_escape
from xml.sax.saxutils import escape as xml_escape
from typing import Dict, Any, List
from .topology_engine import TopologyEngine

class TopologyVisualizer:
    """
    Generates interactive HTML/SVG and structured JSON network topology visualizations.
    Supports device grouping, vendor icons, health indicators, and link confidence styling.
    """
    def __init__(self, topology_data: Dict[str, Any]):
        self.data = topology_data

    def generate_svg(self, output_path: str):
        devices = self.data.get("devices", [])
        links = self.data.get("links", [])

        # Assign deterministic 2D coordinates for layout
        coords = {}
        cols = 3
        x_spacing = 260
        y_spacing = 180
        start_x = 100
        start_y = 80

        for i, dev in enumerate(devices):
            r = i // cols
            c = i % cols
            coords[dev["device_id"]] = (start_x + c * x_spacing, start_y + r * y_spacing)

        width = start_x + cols * x_spacing + 50
        height = start_y + ((len(devices) // cols) + 1) * y_spacing + 50

        svg_lines = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="100%">',
            '<defs>',
            '  <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">',
            '    <feDropShadow dx="2" dy="3" stdDeviation="3" flood-opacity="0.3"/>',
            '  </filter>',
            '</defs>',
            f'<rect width="{width}" height="{height}" fill="#0f172a"/>',
            '<g id="links">'
        ]

        # Draw Links
        for l in links:
            src = l["source"]
            tgt = l["target"]
            if src in coords and tgt in coords:
                x1, y1 = coords[src]
                x2, y2 = coords[tgt]
                # Style by confidence
                stroke_color = "#10b981" if l["confidence"] == "VERIFIED" else ("#f59e0b" if l["confidence"] == "INFERRED" else "#ef4444")
                dash_array = 'stroke-dasharray="5,5"' if l["confidence"] != "VERIFIED" else ""
                svg_lines.append(f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke_color}" stroke-width="2.5" {dash_array} opacity="0.8"/>')

        svg_lines.append('</g>')
        svg_lines.append('<g id="devices">')

        # Draw Devices
        for dev in devices:
            dev_id = dev["device_id"]
            if dev_id in coords:
                cx, cy = coords[dev_id]
                vendor = str(dev.get("vendor", "UNKNOWN"))
                v_color = "#3b82f6" if "mikrotik" in vendor.lower() else ("#0284c7" if "cisco" in vendor.lower() else "#dc2626")
                health = str(dev.get("health_status", "UNKNOWN")).upper()
                health_color = "#10b981" if health == "HEALTHY" else ("#ef4444" if health in {"CRITICAL", "DOWN", "UNHEALTHY"} else "#94a3b8")

                svg_lines.append(f'  <g transform="translate({cx-80}, {cy-35})" filter="url(#shadow)">')
                svg_lines.append(f'    <rect width="160" height="70" rx="8" fill="#1e293b" stroke="{v_color}" stroke-width="2"/>')
                svg_lines.append(f'    <circle cx="15" cy="18" r="5" fill="{health_color}"/>')
                svg_lines.append(f'    <text x="26" y="22" font-family="sans-serif" font-size="11" font-weight="bold" fill="#f8fafc">{xml_escape(str(dev_id)[:16])}</text>')
                svg_lines.append(f'    <text x="12" y="42" font-family="sans-serif" font-size="9" fill="#94a3b8">{xml_escape(str(vendor))} {xml_escape(str(dev.get("model", ""))[:12])}</text>')
                svg_lines.append(f'    <text x="12" y="58" font-family="sans-serif" font-size="9" fill="#64748b">{xml_escape(str(dev.get("management_ip", "")))}</text>')
                svg_lines.append('  </g>')

        svg_lines.append('</g>')
        svg_lines.append('</svg>')

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(svg_lines))

    @staticmethod
    def _text(value: Any) -> str:
        """Escape untrusted network-derived values for an HTML text node."""
        return html_escape("" if value is None else str(value), quote=True)

    def generate_html_viewer(self, output_path: str):
        """Generate a static viewer; network data is text only, never executable markup."""
        devices = self.data.get("devices", []) or []
        links = self.data.get("links", []) or []
        health_states = [str(d.get("health_status", "UNKNOWN")).upper() for d in devices]
        if health_states and all(state == "HEALTHY" for state in health_states):
            aggregate_health = "HEALTHY (reported)"
        elif any(state in {"CRITICAL", "DOWN", "UNHEALTHY"} for state in health_states):
            aggregate_health = "ISSUES REPORTED"
        elif health_states:
            aggregate_health = "MIXED / UNKNOWN"
        else:
            aggregate_health = "UNKNOWN"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Topology Visualizer</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; margin: 0; padding: 20px; }}
  h2 {{ color: #38bdf8; margin-top: 0; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 15px; margin-bottom: 20px; }}
  .summary-pill {{ background: #1e293b; padding: 8px 14px; border-radius: 6px; font-size: 13px; margin-right: 10px; border: 1px solid #334155; }}
  .badge-verified {{ color: #10b981; font-weight: bold; }}
  .badge-inferred {{ color: #f59e0b; font-weight: bold; }}
  .badge-unknown {{ color: #cbd5e1; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background: #111827; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 12px 14px; text-align: left; font-size: 13px; border-bottom: 1px solid #1f2937; }}
  th {{ background: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
  tr:hover {{ background: #1f2937; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h2>Network Topology &amp; Device Discovery Explorer</h2>
    <div>
      <span class="summary-pill">Total Devices: <b>{len(devices)}</b></span>
      <span class="summary-pill">Discovered Links: <b>{len(links)}</b></span>
      <span class="summary-pill">Reported Health: <b>{self._text(aggregate_health)}</b></span>
    </div>
  </div>
</div>
<h3>Discovered Device Inventory</h3>
<table><thead><tr>
<th>Device ID</th><th>Hostname</th><th>Management IP</th><th>Vendor / Model</th><th>Role</th><th>Health</th><th>Telemetry</th>
</tr></thead><tbody>
"""
        for device in devices:
            telemetry_data = device.get("health_metrics", {}) or {}
            if isinstance(telemetry_data, dict):
                telemetry = ", ".join(
                    f"{self._text(key)}: {self._text(value)}" for key, value in telemetry_data.items()
                )
            else:
                telemetry = self._text(telemetry_data)
            html_content += f"""
<tr>
<td><b>{self._text(device.get('device_id', 'UNKNOWN'))}</b></td>
<td>{self._text(device.get('hostname', 'UNKNOWN'))}</td>
<td><code>{self._text(device.get('management_ip', 'UNKNOWN'))}</code></td>
<td>{self._text(device.get('vendor', 'UNKNOWN'))} {self._text(device.get('model', 'UNKNOWN'))}</td>
<td>{self._text(device.get('role', 'UNKNOWN'))}</td>
<td>{self._text(device.get('health_status', 'UNKNOWN'))}</td>
<td><small>{telemetry}</small></td>
</tr>
"""

        html_content += """</tbody></table>
<h3 style="margin-top: 35px;">Topology Adjacency &amp; Evidence Matrix</h3>
<table><thead><tr>
<th>Link ID</th><th>Source Device [Port]</th><th>Target Device [Port]</th><th>Link Confidence</th><th>Evidence Sources</th><th>Status</th>
</tr></thead><tbody>
"""
        for link in links:
            confidence = str(link.get("confidence", "UNKNOWN")).upper()
            badge = "badge-verified" if confidence == "VERIFIED" else ("badge-inferred" if confidence == "INFERRED" else "badge-unknown")
            evidence = link.get("evidence_sources", []) or []
            if not isinstance(evidence, (list, tuple)):
                evidence = [evidence]
            evidence_text = ", ".join(self._text(value) for value in evidence)
            html_content += f"""
<tr>
<td><code>{self._text(link.get('link_id', 'UNKNOWN'))}</code></td>
<td><b>{self._text(link.get('source', 'UNKNOWN'))}</b> [{self._text(link.get('source_interface', 'UNKNOWN'))}]</td>
<td><b>{self._text(link.get('target', 'UNKNOWN'))}</b> [{self._text(link.get('target_interface', 'UNKNOWN'))}]</td>
<td><span class="{badge}">{self._text(confidence)}</span></td>
<td>{evidence_text}</td>
<td>{self._text(link.get('status', 'UNKNOWN'))}</td>
</tr>
"""

        html_content += "</tbody></table></body></html>"
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as output:
            output.write(html_content)
