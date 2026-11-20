from typing import Dict, Any, List, Optional
from ..discovery.models import DiscoveredDevice

class NetworkHealthAnalyzer:
    """
    Evaluates network device telemetry, interface drops, CPU/memory, optical levels,
    and wireless metrics against vendor-calibrated engineering thresholds.
    """
    @staticmethod
    def analyze_device_health(device: DiscoveredDevice) -> Dict[str, Any]:
        metrics = device.health_metrics
        anomalies = []
        severity = "HEALTHY"

        # 1. CPU Load
        cpu = metrics.get("cpu_load")
        if cpu is not None:
            if cpu > 85:
                severity = "CRITICAL"
                anomalies.append(f"High CPU utilization: {cpu}%")
            elif cpu > 70:
                severity = "WARNING" if severity != "CRITICAL" else severity
                anomalies.append(f"Elevated CPU utilization: {cpu}%")

        # 2. Free Memory
        mem = metrics.get("free_memory_mb")
        if mem is not None and mem < 32:
            severity = "CRITICAL"
            anomalies.append(f"Critical low memory: {mem} MB remaining")

        # 3. Optical Power (ONTs)
        rx_power = metrics.get("rx_power_dbm")
        if rx_power is not None:
            if rx_power < -27.0:
                severity = "CRITICAL"
                anomalies.append(f"Optical power attenuation fault: RX {rx_power} dBm (< -27.0 dBm)")
            elif rx_power > -8.0:
                severity = "WARNING"
                anomalies.append(f"Optical power receiver overload risk: RX {rx_power} dBm (> -8.0 dBm)")

        # 4. Wireless SNR / RSSI
        rssi = metrics.get("rssi_dbm")
        snr = metrics.get("snr_db")
        if rssi is not None and rssi < -78:
            severity = "WARNING" if severity != "CRITICAL" else severity
            anomalies.append(f"Weak wireless RF signal: RSSI {rssi} dBm")
        if snr is not None and snr < 18:
            severity = "WARNING" if severity != "CRITICAL" else severity
            anomalies.append(f"High RF noise / low SNR: {snr} dB")

        # 5. Interface Errors
        for intf in device.interfaces:
            errors = intf.get("errors", 0)
            if errors > 50:
                severity = "WARNING" if severity != "CRITICAL" else severity
                anomalies.append(f"Port errors detected on {intf.get('name')}: {errors} CRC/Frame errors")

        return {
            "device_id": device.device_id,
            "health_status": severity,
            "anomalies": anomalies,
            "analyzed_metrics": metrics
        }

    @staticmethod
    def generate_health_summary(devices: List[DiscoveredDevice]) -> Dict[str, Any]:
        healthy = 0
        warning = 0
        critical = 0
        details = []

        for d in devices:
            res = NetworkHealthAnalyzer.analyze_device_health(d)
            details.append(res)
            st = res["health_status"]
            if st == "HEALTHY":
                healthy += 1
            elif st == "WARNING":
                warning += 1
            elif st == "CRITICAL":
                critical += 1

        return {
            "total_devices": len(devices),
            "status_breakdown": {
                "HEALTHY": healthy,
                "WARNING": warning,
                "CRITICAL": critical
            },
            "overall_health": "HEALTHY" if critical == 0 and warning == 0 else ("DEGRADED" if critical == 0 else "CRITICAL"),
            "device_evaluations": details
        }
